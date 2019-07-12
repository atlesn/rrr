/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#define DUPLICATOR_MAX_SENDERS VL_MODULE_MAX_SENDERS

struct duplicator_reader {
	const struct instance_thread_data *identifier;
	struct fifo_buffer buffer;
};

struct duplicator_data {
	pthread_mutex_t readers_lock;
	struct duplicator_reader readers[DUPLICATOR_MAX_SENDERS];
	struct instance_thread_data *data;
	int readers_count;
};

struct duplicator_reader *find_reader (struct duplicator_data *data, const struct instance_thread_data *identifier) {
	struct duplicator_reader *result = NULL;

	pthread_mutex_lock(&data->readers_lock);

	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &data->readers[i];
		if (test->identifier == identifier) {
			result = test;
			break;
		}
	}

	pthread_mutex_unlock(&data->readers_lock);

	return result;
}

struct duplicator_reader *register_reader (struct duplicator_data *data, const struct instance_thread_data *identifier) {
	struct duplicator_reader *result = NULL;

	pthread_mutex_lock(&data->readers_lock);

	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &data->readers[i];
		if (test->identifier == NULL) {
			if (fifo_buffer_init(&test->buffer) != 0) {
				VL_MSG_ERR("Could not initialize fifo buffer for sender %s in duplicator\n", INSTANCE_D_NAME(identifier));
				break;
			}
			test->identifier = identifier;
			data->readers_count++;
			result = test;
			break;
		}
	}

	pthread_mutex_unlock(&data->readers_lock);

	if (result == NULL) {
		VL_MSG_ERR("Maximum number of readers reached: %i\n", DUPLICATOR_MAX_SENDERS);
	}

	return result;
}

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct duplicator_data *duplicator_data = data->private_data;
	struct instance_thread_data *instance_reader = poll_data->source;
	struct duplicator_reader *reader = find_reader(duplicator_data, instance_reader);

	if (reader == NULL) {
		reader = register_reader(duplicator_data, instance_reader);
		if (reader == NULL) {
			VL_MSG_ERR("Could not register reader %p in duplicator instance %s\n", instance_reader, INSTANCE_D_NAME(data));
			return 1;
		}
		else {
			VL_DEBUG_MSG_2("Duplicator instance %s registered reader %s\n", INSTANCE_D_NAME(data), INSTANCE_D_NAME(instance_reader));
		}
	}

	if (fifo_read_clear_forward(&reader->buffer, NULL, callback, poll_data, wait_milliseconds) == FIFO_GLOBAL_ERR) {
		return 1;
	}

	return 0;
}

int poll_callback(struct fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = caller_data->private_data;
	struct duplicator_data *duplicator_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	int ret = 0;

	VL_DEBUG_MSG_3 ("duplicator %s: Result from duplicator: %s measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->data, message->data_numeric, size);

	pthread_mutex_lock(&duplicator_data->readers_lock);

	int count = 0;
	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &duplicator_data->readers[i];
		if (test->identifier != NULL) {
			char *new_data = malloc(size);
			if (new_data == NULL) {
				VL_MSG_ERR("Could not allocate memory for message in duplicator instance %s\n", INSTANCE_D_NAME(thread_data));
				ret = 1;
				break;
			}
			memcpy(new_data, data, size);
			fifo_buffer_write(&test->buffer, new_data, size);
			count++;
		}
	}

	free(data);

	pthread_mutex_unlock(&duplicator_data->readers_lock);

	VL_DEBUG_MSG_3 ("duplicator %s: Message duplicated %i times\n", INSTANCE_D_NAME(thread_data), count);

	return ret;
}

void data_cleanup(void *arg) {
	struct duplicator_data *data = arg;
	pthread_mutex_lock(&data->readers_lock);
	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
			struct duplicator_reader *test = &data->readers[i];
			if (test != NULL) {
				fifo_buffer_invalidate(&test->buffer);
			}
		}
	}
	data->readers_count = 0;
	pthread_mutex_unlock(&data->readers_lock);
}

int data_init(struct duplicator_data *data, struct instance_thread_data *thread_data) {
	int ret = 0;
	memset(data, '\0', sizeof(*data));
	data->data = thread_data;
	ret |= pthread_mutex_init(&data->readers_lock, NULL);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static void *thread_entry_duplicator(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct duplicator_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	thread_data->thread = start_data->thread;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initalize data in duplicator instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("duplicator thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("duplicator instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("duplicator instance %s started thread, waiting a bit for readers to register\n",
			INSTANCE_D_NAME(thread_data));

	usleep (500000); // 500ms

	VL_DEBUG_MSG_1 ("duplicator instance %s detected %i readers for now\n",
			INSTANCE_D_NAME(thread_data), data->readers_count);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread duplicator %p exiting\n", thread_data->thread);

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
		thread_entry_duplicator,
		NULL,
		NULL,
		poll_delete,
		NULL,
		test_config,
		NULL
};

static const char *module_name = "duplicator";

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
	VL_DEBUG_MSG_1 ("Destroy duplicator module\n");
}

