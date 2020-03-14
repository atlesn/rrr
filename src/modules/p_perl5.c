/*

Read Route Record

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "../lib/ip.h"
#include "../lib/buffer.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/modules.h"
#include "../lib/poll_helper.h"
#include "../lib/threads.h"
#include "../lib/perl5.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../global.h"

#include <EXTERN.h>
#include <perl.h>

struct perl5_data {
	struct rrr_instance_thread_data *thread_data;

	struct rrr_fifo_buffer storage;

	struct rrr_perl5_ctx *ctx;

	struct cmd_argv_copy *cmdline;

	char *perl5_file;
	char *source_sub;
	char *process_sub;
	char *config_sub;
};

int poll_delete(RRR_MODULE_POLL_SIGNATURE) {
	struct perl5_data *perl5_data = data->private_data;

	if (rrr_fifo_read_clear_forward(&perl5_data->storage, NULL, callback, poll_data, wait_milliseconds) == RRR_FIFO_GLOBAL_ERR) {
		return 1;
	}

	return 0;
}

static int xsub_send_message(struct rrr_message *message, void *private_data) {
	struct perl5_data *perl5_data = private_data;
	int ret = 0;

	rrr_fifo_buffer_write(&perl5_data->storage, (char*) message, sizeof(*message));

	return ret;
}

static char *xsub_get_setting(const char *key, void *private_data) {
	struct perl5_data *perl5_data = private_data;
	struct rrr_instance_settings *settings = perl5_data->thread_data->init_data.instance_config->settings;

	char *value = NULL;
	if (rrr_settings_get_string_noconvert_silent(&value, settings, key)) {
		RRR_MSG_ERR("Warning: Setting '%s', requested by perl5 program in instance %s, could not be retrieved\n",
				key, INSTANCE_D_NAME(perl5_data->thread_data));
		return NULL;
	}

	return value;
}

static int xsub_set_setting(const char *key, const char *value, void *private_data) {
	struct perl5_data *perl5_data = private_data;
	struct rrr_instance_settings *settings = perl5_data->thread_data->init_data.instance_config->settings;

	int ret = rrr_settings_replace_string(settings, key, value);
	if (ret != 0) {
		RRR_MSG_ERR("Could not update settings key '%s' as requested by perl5 program in instance %s\n",
				key, INSTANCE_D_NAME(perl5_data->thread_data));
	}

	return ret;
}

int preload_perl5 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = (struct rrr_instance_thread_data *) thread->private_data;

	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if ((ret = rrr_perl5_init3(cmdline->argc, cmdline->argv, NULL)) != 0) {
		RRR_MSG_ERR("Could not initialize perl5 in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

int data_init(struct perl5_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	ret |= rrr_fifo_buffer_init(&data->storage);

	cmd_get_argv_copy(&data->cmdline, thread_data->init_data.cmd_data);

	return ret;
}

int perl5_start(struct rrr_instance_thread_data *thread_data) {
	struct perl5_data *data = thread_data->private_data;

	int ret = 0;

	ret |= rrr_perl5_new_ctx (
			&data->ctx,
			data,
			xsub_send_message,
			xsub_get_setting,
			xsub_set_setting
	);

	if (ret != 0) {
		RRR_MSG_ERR("Could not create perl5 context in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_ctx_parse(data->ctx, data->perl5_file);

	if (ret != 0) {
		RRR_MSG_ERR("Could not parse perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_ctx_run(data->ctx);

	if (ret != 0) {
		RRR_MSG_ERR("Could not run perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	// Everything is cleaned up my perl5_stop, also in case of errors
	return ret;
}

void perl5_stop(void *arg) {
	struct perl5_data *data = arg;

	rrr_perl5_destroy_ctx(data->ctx);
}

void data_cleanup(void *arg) {
	struct perl5_data *data = arg;
	rrr_fifo_buffer_invalidate(&data->storage);
	RRR_FREE_IF_NOT_NULL(data->perl5_file);
	RRR_FREE_IF_NOT_NULL(data->source_sub);
	RRR_FREE_IF_NOT_NULL(data->process_sub);
	RRR_FREE_IF_NOT_NULL(data->config_sub);
	cmd_destroy_argv_copy(data->cmdline);
}

void poststop_perl5(const struct rrr_thread *thread) {
	(void)(thread);
	rrr_perl5_sys_term();
}

int parse_config(struct perl5_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->perl5_file, config, "perl5_file");

	if (ret != 0) {
		RRR_MSG_ERR("No perl5_file specified for perl5 instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_sub, config, "perl5_source_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->process_sub, config, "perl5_process_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->config_sub, config, "perl5_config_sub");

	if (data->source_sub == NULL && data->process_sub == NULL) {
		RRR_MSG_ERR("No source or processor sub defined for perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int spawn_messages(struct perl5_data *perl5_data) {
	int ret = 0;
	struct rrr_message *message = NULL;

	struct rrr_perl5_ctx *ctx = perl5_data->ctx;

	struct rrr_perl5_message_hv *hv_message = rrr_perl5_allocate_message_hv(ctx);

	uint64_t time_start = rrr_time_get_64();
	for (int i = 0; i < 50; i++) {
		uint64_t now_time = rrr_time_get_64();

		if (rrr_message_new_empty (
				&message,
				MSG_TYPE_MSG,
				0,
				MSG_CLASS_POINT,
				now_time,
				now_time,
				0,
				0,
				0
		) != 0) {
			RRR_MSG_ERR("Could not initialize message in perl5 spawn_messages of instance %s\n",
					INSTANCE_D_NAME(perl5_data->thread_data));
			ret = 1;
			goto out;
		}

		rrr_perl5_message_to_hv(hv_message, ctx, message);
		rrr_perl5_call_blessed_hvref(ctx, perl5_data->source_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);
		rrr_perl5_hv_to_message(&message, ctx, hv_message);

		rrr_fifo_buffer_write(&perl5_data->storage, (char*) message, sizeof(*message));

		message = NULL;

		uint64_t time_end = rrr_time_get_64();
		if (time_end - time_start > 10000) { // 10 ms
			// If the source function is slow or sleeps, break the loop
			break;
		}
	}

	out:
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int process_message(struct perl5_data *perl5_data, struct rrr_message *message) {
	int ret = 0;

	struct rrr_perl5_ctx *ctx = perl5_data->ctx;

	struct rrr_perl5_message_hv *hv_message;

	ret |= rrr_perl5_message_to_new_hv(&hv_message, ctx, message);
	if (ret != 0) {
		RRR_MSG_ERR("Could not create rrr_perl5_message_hv struct in process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(perl5_data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_call_blessed_hvref(ctx, perl5_data->process_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);
	if (ret != 0) {
		RRR_MSG_ERR("Could not call process function in process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(perl5_data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_hv_to_message(&message, ctx, hv_message);
	if (ret != 0) {
		RRR_MSG_ERR("Could not convertrrr_perl5_message_hv struct to message in process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(perl5_data->thread_data));
		goto out;
	}

	rrr_fifo_buffer_write(&perl5_data->storage, (char*) message, sizeof(*message));

	out:
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	return ret;
}

int poll_callback(struct rrr_fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = caller_data->private_data;
	struct perl5_data *perl5_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;

	RRR_DBG_3 ("perl5 instance %s Result from buffer: measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->data_numeric, size);

	return process_message(perl5_data, message);
}

int send_config(struct perl5_data *data) {
	int ret = 0;

	struct rrr_instance_settings *settings = data->thread_data->init_data.instance_config->settings;
	struct rrr_perl5_settings_hv *settings_hv = NULL;

	if (data->config_sub == NULL || *(data->config_sub) == '\0') {
		goto out;
	}

	if ((ret = rrr_perl5_settings_to_hv(&settings_hv, data->ctx, settings)) != 0) {
		RRR_MSG_ERR("Could not convert settings of perl5 instance %s to hash value\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_perl5_call_blessed_hvref(
			data->ctx,
			data->config_sub,
			"rrr::rrr_helper::rrr_settings",
			settings_hv->hv
	)) != 0) {
		RRR_MSG_ERR("Error while sending settings to sub %s in perl5 instance %s\n",
				data->config_sub, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	rrr_perl5_destruct_settings_hv(data->ctx, settings_hv);
	return ret;
}

static void *thread_entry_perl5(struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initialize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(perl5_stop, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (perl5_start(thread_data) != 0) {
		pthread_exit(0);
	}

	if (send_config(data) != 0) {
		RRR_MSG_ERR("Could not send config to perl5 program in instance %s\n",
				INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		RRR_MSG_ERR("perl5 instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	int no_polling = 1;
	if (poll_collection_count (&poll) > 0) {
		if (!data->process_sub) {
			RRR_MSG_ERR("Perl5 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	int no_spawning = (data->source_sub == NULL || *(data->source_sub) == '\0' ? 1 : 0);

	RRR_DBG_1 ("perl5 started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_update_watchdog_time(thread_data->thread);

		if (no_polling == 0) {
			if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
				break;
			}
		}
		else {
			usleep (50000);
		}

		if (no_spawning == 0) {
			if (spawn_messages(data) != 0) {
				break;
			}
		}
	}

	out_message:
	RRR_DBG_1 ("Thread perl5 %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config(struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		preload_perl5,
		thread_entry_perl5,
		poststop_perl5,
		NULL,
		NULL,
		poll_delete,
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
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy perl5 module\n");
}

