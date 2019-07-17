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

#include "../lib/ip.h"
#include "../lib/poll_helper.h"
#include "../lib/buffer.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_buffer_MAX_SENDERS VL_MODULE_MAX_SENDERS

struct buffer_data {
	struct fifo_buffer storage;
	struct instance_thread_data *data;
};

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct buffer_data *buffer_data = data->private_data;

	if (fifo_read_clear_forward(&buffer_data->storage, NULL, callback, poll_data, wait_milliseconds) == FIFO_GLOBAL_ERR) {
		return 1;
	}

	return 0;
}

int poll_callback(struct fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = caller_data->private_data;
	struct buffer_data *buffer_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	VL_DEBUG_MSG_3 ("buffer: Result from buffer: %s measurement %" PRIu64 " size %lu\n",
			message->data, message->data_numeric, size);

	fifo_buffer_write(&buffer_data->storage, data, size);

	return 0;
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct buffer_data *data = thread_data->private_data;
	VL_DEBUG_MSG_2("buffer: writing data from inject function\n");
	fifo_buffer_write(&data->storage, (char*)message, sizeof(*message));
	return 0;
}

void data_cleanup(void *arg) {
	struct buffer_data *data = arg;
	fifo_buffer_invalidate(&data->storage);
}

int data_init(struct buffer_data *data, struct instance_thread_data *thread_data) {
	int ret = 0;
	data->data = thread_data;
	ret |= fifo_buffer_init(&data->storage);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static void *thread_entry_buffer(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct buffer_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	thread_data->thread = start_data->thread;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initalize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("buffer thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("buffer instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("buffer started thread %p\n", thread_data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread buffer %p exiting\n", thread_data->thread);

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
		thread_entry_buffer,
		NULL,
		NULL,
		NULL,
		poll_delete,
		NULL,
		test_config,
		inject,
		NULL
};

static const char *module_name = "buffer";

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
	VL_DEBUG_MSG_1 ("Destroy buffer module\n");
}

