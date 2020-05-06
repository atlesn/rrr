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
#include "../lib/ip_buffer_entry.h"
#include "../lib/poll_helper.h"
#include "../lib/buffer.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../global.h"

struct buffer_data {
	struct rrr_fifo_buffer storage;
	struct rrr_instance_thread_data *data;
};

int poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
//	printf ("buffer got entry %p\n", entry);

	struct rrr_message *message = entry->message;

	RRR_DBG_3("buffer instance %s received message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	int ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			entry
	);

	if (ret != 0) {
		RRR_MSG_ERR("Error while adding message to buffer in buffer instance %s\n",
				INSTANCE_D_NAME(thread_data));
	}

	rrr_ip_buffer_entry_unlock_(entry);
	return ret;
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	RRR_DBG_2("buffer instance %s: writing data from inject function\n", INSTANCE_D_NAME(thread_data));

	// This will also unlock
	if (rrr_message_broker_clone_and_write_entry (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			message
	) != 0) {
		RRR_MSG_ERR("Error while injecting packet in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		return 1;
	}

	return 0;
}

void data_cleanup(void *arg) {
	struct buffer_data *data = arg;
	rrr_fifo_buffer_clear(&data->storage);
}

int data_init(struct buffer_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;
	data->data = thread_data;
	ret |= rrr_fifo_buffer_init(&data->storage);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static void *thread_entry_buffer (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct buffer_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("buffer thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders (&poll, thread_data);

	RRR_DBG_1 ("buffer started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete (thread_data, &poll, poll_callback, 50) != 0) {
			break;
		}
	}

	RRR_DBG_1 ("Thread buffer %p exiting\n", thread_data->thread);

	//pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_buffer,
		NULL,
		test_config,
		inject,
		NULL
};

static const char *module_name = "buffer";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy buffer module\n");
}

