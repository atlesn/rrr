/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

// Allow u_int which being used when including Perl.h
#undef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#include <sys/types.h>
#undef __BSD_VISIBLE

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/linked_list.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/message_addr.h"
#include "../lib/message_log.h"
#include "../lib/modules.h"
#include "../lib/poll_helper.h"
#include "../lib/threads.h"
#include "../lib/perl5/perl5.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../lib/rrr_strerror.h"
#include "../lib/socket/rrr_socket_msg.h"
#include "../lib/common.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/message_broker.h"
#include "../lib/cmodule_common.h"
#include "../lib/log.h"
#include "../lib/gnu.h"
#include "../lib/cmodule_native.h"

#include <EXTERN.h>
#include <perl.h>

#define PERL5_DEFAULT_SOURCE_INTERVAL_MS 1000
#define PERL5_CHILD_MAX_IN_FLIGHT 100
#define PERL5_CHILD_MAX_IN_BUFFER (PERL5_CHILD_MAX_IN_FLIGHT * 10)
#define PERL5_MMAP_SIZE (1024*1024*2)
#define PERL5_CONTROL_MSG_CONFIG_COMPLETE RRR_SOCKET_MSG_CTRL_F_USR_A

struct perl5_data {
	struct rrr_instance_thread_data *thread_data;

	struct cmd_argv_copy *cmdline;

	uint64_t spawn_interval_ms;

	char *perl5_file;
	char *source_sub;
	char *process_sub;
	char *config_sub;

	int do_drop_on_error;

	// For test suite, put build dirs in @INC
	int do_include_build_directories;
};

struct perl5_child_data {
	struct perl5_data *parent_data;
	struct rrr_perl5_ctx *ctx;
	struct rrr_cmodule_worker *worker;
};

static int xsub_send_message (
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr,
		void *private_data
) {
	struct perl5_child_data *child_data = private_data;
	int ret = 0;

	// Always frees message
	if ((ret = rrr_cmodule_worker_send_message_to_parent(
			child_data->worker,
			message,
			message_addr
	)) != 0) {
		RRR_MSG_0("Could not send address message on memory map channel in xsub_send_message_addr of perl5 instance %s.\n",
				INSTANCE_D_NAME(child_data->parent_data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static char *xsub_get_setting(const char *key, void *private_data) {
	struct perl5_child_data *perl5_child_data = private_data;
	struct rrr_instance_settings *settings = perl5_child_data->worker->settings;

	char *value = NULL;
	if (rrr_settings_get_string_noconvert_silent(&value, settings, key)) {
		RRR_MSG_0("Warning: Setting '%s', requested by perl5 program in instance %s, could not be retrieved\n",
				key, INSTANCE_D_NAME(perl5_child_data->parent_data->thread_data));
		return NULL;
	}

	return value;
}

static int xsub_set_setting(const char *key, const char *value, void *private_data) {
	struct perl5_child_data *perl5_child_data = private_data;
	struct rrr_instance_settings *settings = perl5_child_data->worker->settings;

	int ret = rrr_settings_replace_string(settings, key, value);
	if (ret != 0) {
		RRR_MSG_0("Could not update settings key '%s' as requested by perl5 program in instance %s\n",
				key, INSTANCE_D_NAME(perl5_child_data->parent_data->thread_data));
	}

	return ret;
}

static int preload_perl5 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = (struct rrr_instance_thread_data *) thread->private_data;

	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if ((ret = rrr_perl5_init3(cmdline->argc, cmdline->argv, NULL)) != 0) {
		RRR_MSG_0("Could not initialize perl5 in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

static int perl5_data_init(struct perl5_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	cmd_get_argv_copy(&data->cmdline, thread_data->init_data.cmd_data);

	return ret;
}

static int perl5_start(struct perl5_child_data *data) {
	int ret = 0;

	ret |= rrr_perl5_new_ctx (
			&data->ctx,
			data,
			xsub_send_message,
			xsub_get_setting,
			xsub_set_setting
	);

	if (ret != 0) {
		RRR_MSG_0("Could not create perl5 context in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	RRR_DBG_1 ("perl5 instance %s starting perl5 interpreter pointer %p\n",
			INSTANCE_D_NAME(data->parent_data->thread_data), data->ctx->interpreter);

	ret |= rrr_perl5_ctx_parse (
			data->ctx,
			data->parent_data->perl5_file,
			data->parent_data->do_include_build_directories
	);

	if (ret != 0) {
		RRR_MSG_0("Could not parse perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_ctx_run(data->ctx);

	if (ret != 0) {
		RRR_MSG_0("Could not run perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	out:
	// Everything is cleaned up my perl5_stop, also in case of errors
	return ret;
}

static void data_cleanup(void *arg) {
	struct perl5_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->perl5_file);
	RRR_FREE_IF_NOT_NULL(data->source_sub);
	RRR_FREE_IF_NOT_NULL(data->process_sub);
	RRR_FREE_IF_NOT_NULL(data->config_sub);

	cmd_destroy_argv_copy(data->cmdline);
}

static int parse_config(struct perl5_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->perl5_file, config, "perl5_file");

	if (ret != 0) {
		RRR_MSG_0("No perl5_file specified for perl5 instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_sub, config, "perl5_source_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->process_sub, config, "perl5_process_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->config_sub, config, "perl5_config_sub");

	if (data->source_sub == NULL && data->process_sub == NULL) {
		RRR_MSG_0("No source or processor sub defined for perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_setting_uint uint_tmp = 0;
	if ((ret = rrr_instance_config_read_unsigned_integer(&uint_tmp, config, "perl5_source_interval")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error in setting perl5_source_interval of perl5 instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else {
			uint_tmp = PERL5_DEFAULT_SOURCE_INTERVAL_MS;
		}
		ret = 0;
	}
	else {
		if (data->source_sub == NULL) {
			RRR_MSG_0("perl5_source_interval of perl5 instance %s was set but no source function was defined with perl5_source_sub\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->spawn_interval_ms = uint_tmp;

	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("perl5_drop_on_error", do_drop_on_error, 0);

	// For test suite, but build directories into @INC
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("perl5_do_include_build_directories", do_include_build_directories, 0);

	out:
	return ret;
}

static int perl5_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	int ret = 0;

	(void)(configuration_callback_arg);
	(void)(process_callback_arg);

	struct perl5_child_data child_data = {0};

	child_data.parent_data = private_arg;
	child_data.worker = worker;

	if (preload_perl5 (child_data.parent_data->thread_data->thread) != 0) {
		RRR_MSG_0("Could not preload perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data.parent_data->thread_data));
		ret = 1;
		goto out_final;
	}

	if (perl5_start(&child_data) != 0) {
		RRR_MSG_0("Could not compile and start perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data.parent_data->thread_data));
		ret = 1;
		goto out_sys_term;
	}

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			&child_data,
			process_callback,
			&child_data
	)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_init_wrapper_default\n");
		// Don't goto out, run cleanup functions
	}

//	out_destroy_ctx:
		rrr_perl5_destroy_ctx(child_data.ctx);
	out_sys_term:
		rrr_perl5_sys_term();
	out_final:
		return ret;
}

static int perl5_configuration_callback (RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	int ret = 0;

	(void)(worker);

	struct perl5_child_data *child_data = private_arg;
	struct perl5_data *data = child_data->parent_data;

	struct rrr_instance_settings *settings = data->thread_data->init_data.instance_config->settings;
	struct rrr_perl5_settings_hv *settings_hv = NULL;

	if (data->config_sub == NULL || *(data->config_sub) == '\0') {
		RRR_DBG_2("Perl5 no configure sub defined in configuration\n", data->config_sub);
		goto out;
	}

	RRR_DBG_2("Perl5 configuring, sub is %s\n", data->config_sub);

	if ((ret = rrr_perl5_settings_to_hv(&settings_hv, child_data->ctx, settings)) != 0) {
		RRR_MSG_0("Could not convert settings of perl5 instance %s to hash value\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	// The settings object from parent will get updated as the application accesses
	// entries or writes new ones. Memory will however only get written to in the
	// child fork, and all settings must be sent back to the parent over the mmap channel.
	if ((ret = rrr_perl5_call_blessed_hvref (
			child_data->ctx,
			data->config_sub,
			"rrr::rrr_helper::rrr_settings",
			settings_hv->hv
	)) != 0) {
		RRR_MSG_0("Error while sending settings to sub %s in perl5 instance %s\n",
				data->config_sub, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	rrr_perl5_destruct_settings_hv(child_data->ctx, settings_hv);
	return ret;
}

static int perl5_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	int ret = 0;

	(void)(worker);

	struct perl5_child_data *child_data = private_arg;
	struct perl5_data *data = child_data->parent_data;
	struct rrr_perl5_ctx *ctx = child_data->ctx;

	struct rrr_perl5_message_hv *hv_message = NULL;
	struct rrr_message_addr addr_msg_tmp = *message_addr;

	// We prefer to send NULL for empty address messages when spawning.
	if ((ret = rrr_perl5_message_to_new_hv(&hv_message, ctx, message, (is_spawn_ctx ? NULL : &addr_msg_tmp))) != 0) {
		RRR_MSG_0("Could not create rrr_perl5_message_hv struct in worker_process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (is_spawn_ctx) {
		RRR_DBG_2("Perl5 spawning, sub is %s\n", data->source_sub);
		ret = rrr_perl5_call_blessed_hvref(ctx, data->source_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);
	}
	else {
		RRR_DBG_2("Perl5 processing, sub is %s\n", data->process_sub);
		ret = rrr_perl5_call_blessed_hvref(ctx, data->process_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not call source/process function in worker_process_message of perl5 instance %s, spawn ctx is %i\n",
				INSTANCE_D_NAME(data->thread_data), is_spawn_ctx);
		ret = 1;
		goto out;
	}

	out:
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	return ret;
}

static void *thread_entry_perl5(struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll_ip;

	if (perl5_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	rrr_poll_collection_init(&poll_ip);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	rrr_poll_add_from_thread_senders(&poll_ip, thread_data);
	int no_polling = 1;
	if (rrr_poll_collection_count (&poll_ip) > 0) {
		if (!data->process_sub) {
			RRR_MSG_0("Perl5 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	pid_t fork_pid = 0;

	if (rrr_cmodule_start_worker_fork (
			&fork_pid,
			thread_data->cmodule,
			data->spawn_interval_ms * 1000,
			10 * 1000,
			INSTANCE_D_NAME(thread_data),
			(data->source_sub != NULL ? 1 : 0),
			(data->process_sub != NULL ? 1 : 0),
			data->do_drop_on_error,
			INSTANCE_D_SETTINGS(thread_data),
			perl5_init_wrapper_callback,
			data,
			perl5_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			perl5_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting perl5 worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);

	RRR_DBG_1 ("perl5 instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_common_loop (
			thread_data,
			stats,
			&poll_ip,
			fork_pid,
			no_polling
	);

	out_message:
	RRR_DBG_1 ("perl5 instance %s thread %p exiting\n", INSTANCE_D_NAME(thread_data), thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_exit(0);
}

static int test_config(struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_perl5,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "perl5";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->start_priority = RRR_THREAD_START_PRIORITY_FORK;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy perl5 module\n");
}

