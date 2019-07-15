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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/poll_helper.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_CONTROLLER_MAX_SENDERS VL_MODULE_MAX_SENDERS

struct controller_data {
	struct fifo_buffer to_ipclient;
	struct fifo_buffer to_blockdev;
	struct instance_thread_data *data;
};

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct controller_data *controller_data = data->private_data;
	struct instance_thread_data *source = poll_data->source;

	if (strcmp (source->init_data.module->module_name, "ipclient") == 0) {
		fifo_read_clear_forward(&controller_data->to_ipclient, NULL, callback, poll_data, wait_milliseconds);
	}
	else if (strcmp (source->init_data.module->module_name, "blockdev") == 0) {
		fifo_read_clear_forward(&controller_data->to_blockdev, NULL, callback, poll_data, wait_milliseconds);
	}
	else {
		VL_MSG_ERR ("controller %s: No output buffer defined for instance %s using module %s\n",
				controller_data->data->init_data.module->instance_name,
				source->init_data.module->instance_name,
				source->init_data.module->module_name
		);
		return 1;
	}

	return 0;
}

int poll_callback(struct fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct controller_data *controller_data = caller_data->private_data;
	struct instance_thread_data *source = caller_data->source;
	struct vl_message *message = (struct vl_message *) data;

	VL_DEBUG_MSG_3 ("controller: Result from buffer: %s measurement %" PRIu64 " size %lu\n",
			message->data, message->data_numeric, size);

	if (strcmp (source->init_data.module->module_name, "blockdev") == 0) {
		fifo_buffer_write(&controller_data->to_ipclient, data, size);
	}
	else if (strcmp (source->init_data.module->module_name, "ipclient") == 0) {
		if (message->type == MSG_TYPE_TAG) {
			fifo_buffer_write(&controller_data->to_blockdev, data, size);
		}
		else {
			// Discard everything else as trash
			VL_MSG_ERR ("controller: Warning: Discarding message from ipclient timestamp %" PRIu64 "\n", message->timestamp_from);
			free(message);
		}
	}
	else if (
		(strcmp (source->init_data.module->module_name, "udpreader") == 0) ||
		(strcmp (source->init_data.module->module_name, "averager") == 0) ||
		(strcmp (source->init_data.module->module_name, "voltmonitor") == 0) ||
		(strcmp (source->init_data.module->module_name, "dummy") == 0)
	) {
		void *data_2 = message_duplicate(message); // Remember to copy message!
		fifo_buffer_write(&controller_data->to_ipclient, data, size);
		fifo_buffer_write(&controller_data->to_blockdev, data_2, size);
	}
	else {
		VL_MSG_ERR ("controller %s: Don't know where to route messages from '%s' using module '%s'\n",
				controller_data->data->init_data.module->instance_name,
				source->init_data.module->instance_name,
				source->init_data.module->module_name
		);
		free(data);
	}

	return 0;
}

void data_cleanup(void *arg) {
	struct controller_data *data = arg;
	fifo_buffer_invalidate(&data->to_blockdev);
	fifo_buffer_invalidate(&data->to_ipclient);
}

int data_init(struct controller_data *data, struct instance_thread_data *thread_data) {
	int ret = 0;
	ret |= fifo_buffer_init(&data->to_blockdev);
	ret |= fifo_buffer_init(&data->to_ipclient);
	data->data = thread_data;
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static void *thread_entry_controller(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct controller_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	thread_data->thread = start_data->thread;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initalize data in controller instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("controller thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("Controller instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("controller started thread %p\n", thread_data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread controller %p exiting\n", thread_data->thread);

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
		NULL,
		thread_entry_controller,
		NULL,
		NULL,
		NULL,
		poll_delete,
		NULL,
		test_config,
		NULL
};

static const char *module_name = "controller";

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
	VL_DEBUG_MSG_1 ("Destroy controller module\n");
}

