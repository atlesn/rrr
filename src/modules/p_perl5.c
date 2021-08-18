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

#undef __USE_GNU
#include <stdio.h>

// Allow u_int which being used when including Perl.h
#undef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#include <sys/types.h>
#undef __BSD_VISIBLE

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/modules.h"
#include "../lib/poll_helper.h"
#include "../lib/threads.h"
#include "../lib/perl5/perl5.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../lib/rrr_strerror.h"
#include "../lib/common.h"
#include "../lib/message_broker.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/messages/msg.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/messages/msg_addr.h"
#include "../lib/messages/msg_log.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_ext.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/util/gnu.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/linked_list.h"
#include "../lib/array.h"

#include <EXTERN.h>
#include <perl.h>

#define PERL5_DEFAULT_SOURCE_INTERVAL_MS 1000
#define PERL5_CHILD_MAX_IN_FLIGHT 100
#define PERL5_CHILD_MAX_IN_BUFFER (PERL5_CHILD_MAX_IN_FLIGHT * 10)
#define PERL5_MMAP_SIZE (1024*1024*2)
#define PERL5_CONTROL_MSG_CONFIG_COMPLETE RRR_MSG_CTRL_F_USR_A

struct perl5_data {
	struct rrr_instance_runtime_data *thread_data;

	struct cmd_argv_copy *cmdline;

	char *perl5_file;

	// For test suite, put build dirs in @INC
	int do_include_build_directories;
};

struct perl5_child_data {
	struct perl5_data *parent_data;
	struct rrr_perl5_ctx *ctx;
	struct rrr_cmodule_worker *worker;
};

static int xsub_send_message (
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr,
		void *private_data
) {
	struct perl5_child_data *child_data = private_data;
	int ret = 0;

	if ((ret = rrr_cmodule_ext_send_message_to_parent (
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
	struct rrr_instance_settings *settings = rrr_cmodule_worker_get_settings(perl5_child_data->worker);

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
	struct rrr_instance_settings *settings = rrr_cmodule_worker_get_settings(perl5_child_data->worker);

	int ret = rrr_settings_replace_string(settings, key, value);
	if (ret != 0) {
		RRR_MSG_0("Could not update settings key '%s' as requested by perl5 program in instance %s\n",
				key, INSTANCE_D_NAME(perl5_child_data->parent_data->thread_data));
	}

	return ret;
}

static int preload_perl5 (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) thread->private_data;

	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if (cmdline->argc > INT_MAX) {
		RRR_MSG_0("argc overflow (%llu>%i) in perl5 instance %s\n",
			(unsigned long long) cmdline->argc, INT_MAX, INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_destroy_cmdline;
	}
	
	if ((ret = rrr_perl5_init3((int) cmdline->argc, cmdline->argv, NULL)) != 0) {
		RRR_MSG_0("Could not initialize perl5 in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

static int perl5_data_init(struct perl5_data *data, struct rrr_instance_runtime_data *thread_data) {
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
		goto out_cleanup_ctx;
	}

	ret |= rrr_perl5_ctx_run(data->ctx);

	if (ret != 0) {
		RRR_MSG_0("Could not run perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out_cleanup_ctx;
	}

	goto out;
	out_cleanup_ctx:
		rrr_perl5_destroy_ctx(data->ctx);
		data->ctx = NULL;
	out:
		return ret;
}

static void data_cleanup(void *arg) {
	struct perl5_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->perl5_file);
	cmd_destroy_argv_copy(data->cmdline);
}

static int parse_config(struct perl5_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->perl5_file, config, "perl5_file");

	if (ret != 0) {
		RRR_MSG_0("No perl5_file specified for perl5 instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	// For test suite, but build directories into @INC
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("perl5_do_include_build_directories", do_include_build_directories, 0);

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

	if (preload_perl5 (INSTANCE_D_THREAD(child_data.parent_data->thread_data)) != 0) {
		RRR_MSG_0("Could not preload perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data.parent_data->thread_data));
		ret = 1;
		goto out_final;
	}

	if (perl5_start(&child_data) != 0) {
		RRR_MSG_0("Could not compile and start perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data.parent_data->thread_data));
		ret = 1;
		// When there are errors, perl5_start will cleanup perl5 ctx
		goto out_sys_term;
	}

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			&child_data,
			process_callback,
			&child_data,
			custom_tick_callback,
			custom_tick_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from worker loop in perl5_init_wrapper_callback\n");
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
	const struct rrr_cmodule_config_data *cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);

	struct rrr_instance_settings *settings = data->thread_data->init_data.instance_config->settings;
	struct rrr_perl5_settings_hv *settings_hv = NULL;

	if (cmodule_config_data->config_function == NULL || *(cmodule_config_data->config_function) == '\0') {
		RRR_DBG_1("Perl5 instance %s no configure sub defined in configuration\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_DBG_1("Perl5 configuring, sub is %s\n", cmodule_config_data->config_function);

	if (rrr_perl5_settings_to_hv(&settings_hv, child_data->ctx, settings) != 0) {
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
			cmodule_config_data->config_function,
			"rrr::rrr_helper::rrr_settings",
			settings_hv->hv
	)) != 0) {
		RRR_MSG_0("Error while sending settings to sub %s in perl5 instance %s\n",
				cmodule_config_data->config_function, INSTANCE_D_NAME(data->thread_data));
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
	const struct rrr_cmodule_config_data *cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);

	struct rrr_perl5_message_hv *hv_message = NULL;
	struct rrr_msg_addr addr_msg_tmp = *message_addr;

	struct rrr_array array_tmp = {0};

	// We prefer to send NULL for empty address messages when spawning.
	if ((ret = rrr_perl5_message_to_new_hv (
			&hv_message,
			ctx,
			message,
			(is_spawn_ctx ? NULL : &addr_msg_tmp),
			&array_tmp
	)) != 0) {
		RRR_MSG_0("Could not create rrr_perl5_message_hv struct in worker_process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (is_spawn_ctx) {
		ret = rrr_perl5_call_blessed_hvref(ctx, cmodule_config_data->source_function, "rrr::rrr_helper::rrr_message", hv_message->hv);
	}
	else {
		ret = rrr_perl5_call_blessed_hvref(ctx, cmodule_config_data->process_function, "rrr::rrr_helper::rrr_message", hv_message->hv);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not call source/process function in worker_process_message of perl5 instance %s, spawn ctx is %i\n",
				INSTANCE_D_NAME(data->thread_data), is_spawn_ctx);
		ret = 1;
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	return ret;
}

struct perl5_fork_callback_data {
	struct rrr_instance_runtime_data *thread_data;
};

static int perl5_fork (void *arg) {
	struct perl5_fork_callback_data *callback_data = arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;
	struct perl5_data *data = thread_data->private_data;

	int ret = 0;

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}
	if (rrr_cmodule_helper_parse_config(thread_data, "perl5", "sub") != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_worker_forks_start (
			thread_data,
			perl5_init_wrapper_callback,
			data,
			perl5_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			perl5_process_callback,
			NULL  // <-- in the init wrapper, this callback is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting perl5 worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_perl5(struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;

	if (perl5_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	pthread_cleanup_push(data_cleanup, data);

	struct perl5_fork_callback_data fork_callback_data = {
		thread_data
	};

	if (rrr_thread_start_condition_helper_fork(thread, perl5_fork, &fork_callback_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("perl5 instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data
	);

	out_message:
	RRR_DBG_1 ("perl5 instance %s thread %p exiting\n",
			INSTANCE_D_NAME(thread_data), thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_perl5,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "perl5";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->event_functions = rrr_cmodule_helper_event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy perl5 module\n");
}

