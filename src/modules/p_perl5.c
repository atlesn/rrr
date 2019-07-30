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

#include <EXTERN.h>
#include <perl.h>

struct perl5_data {
	struct fifo_buffer storage;
	struct instance_thread_data *thread_data;
	PerlInterpreter *interpreter;
};

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct perl5_data *perl5_data = data->private_data;

	if (fifo_read_clear_forward(&perl5_data->storage, NULL, callback, poll_data, wait_milliseconds) == FIFO_GLOBAL_ERR) {
		return 1;
	}

	return 0;
}

int poll_callback(struct fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = caller_data->private_data;
	struct perl5_data *perl5_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	VL_DEBUG_MSG_3 ("perl5 instance %s Result from buffer: %s measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->data, message->data_numeric, size);

	fifo_buffer_write(&perl5_data->storage, data, size);

	return 0;
}

int preload_perl5 (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = (struct instance_thread_data *) thread->private_data;

	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if ((ret = rrr_perl5_init3(cmdline->argc, cmdline->argv, NULL)) != 0) {
		VL_MSG_ERR("Could not initialize perl5 in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

int data_init(struct perl5_data *data, struct instance_thread_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	ret |= fifo_buffer_init(&data->storage);

	return ret;
}

int perl5_start(struct instance_thread_data *thread_data) {
	struct perl5_data *data = thread_data->private_data;

	PerlInterpreter *interpreter = NULL;
	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if ((interpreter = rrr_perl5_construct(cmdline->argc, cmdline->argv, NULL)) == NULL) {
		VL_MSG_ERR("Could not construct perl5 interpreter in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	data->interpreter = interpreter;

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

void perl5_stop(void *arg) {
	struct perl5_data *data = arg;

	if (data->interpreter != NULL) {
		rrr_perl5_destruct(data->interpreter);
		data->interpreter = NULL;
	}
}

void poststop_perl5 (const struct vl_thread *thread) {
	(void)(thread);
	rrr_perl5_sys_term();
}

void data_cleanup(void *arg) {
	struct perl5_data *data = arg;
	fifo_buffer_invalidate(&data->storage);
}

static void *thread_entry_perl5 (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initialize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(perl5_stop, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (perl5_start(thread_data) != 0) {
		pthread_exit(0);
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("perl5 instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("perl5 started thread %p\n", thread_data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread perl5 %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	VL_DEBUG_MSG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct module_operations module_operations = {
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

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy perl5 module\n");
}

