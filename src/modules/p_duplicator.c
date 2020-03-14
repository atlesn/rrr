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

#define DUPLICATOR_MAX_SENDERS RRR_MODULE_MAX_SENDERS

struct duplicator_reader {
	const struct rrr_instance_thread_data *identifier;
	struct rrr_fifo_buffer buffer;
	uint64_t read_position;
};

struct duplicator_data {
	pthread_mutex_t readers_lock;
	struct duplicator_reader readers[DUPLICATOR_MAX_SENDERS];
	struct rrr_instance_thread_data *data;
	struct rrr_fifo_buffer input_buffer;
	int readers_count;
	int registering_active;
	int readers_active;
};

inline void readers_read_lock(struct duplicator_data *data) {
	int ok = 0;

	while (!ok) {
		pthread_mutex_lock(&data->readers_lock);
		if (!data->registering_active) {
			data->readers_active++;
			ok = 1;
		}
		pthread_mutex_unlock(&data->readers_lock);
	}
}

inline void readers_read_unlock(struct duplicator_data *data) {
	pthread_mutex_lock(&data->readers_lock);
	data->readers_active--;
	pthread_mutex_unlock(&data->readers_lock);
}

inline void readers_register_lock(struct duplicator_data *data) {
	int ok = 0;
	while (ok != 2) {
		if (ok == 0) {
			pthread_mutex_lock(&data->readers_lock);
			if (data->registering_active == 0) {
				ok = 1;
				data->registering_active = 1;
			}
			pthread_mutex_unlock(&data->readers_lock);
		}
		if (ok == 1) {
			pthread_mutex_lock(&data->readers_lock);
			if (data->readers_active == 0) {
				ok = 2;
			}
			pthread_mutex_unlock(&data->readers_lock);
		}
	}
}

inline void readers_register_unlock(struct duplicator_data *data) {
	pthread_mutex_lock(&data->readers_lock);
	data->registering_active = 0;
	pthread_mutex_unlock(&data->readers_lock);
}

struct duplicator_reader *find_reader (struct duplicator_data *data, const struct rrr_instance_thread_data *identifier) {
	struct duplicator_reader *result = NULL;

	readers_read_lock(data);

	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &data->readers[i];
		if (test->identifier == identifier) {
			result = test;
			break;
		}
	}

	readers_read_unlock(data);

	return result;
}

struct duplicator_reader *register_reader (struct duplicator_data *data, const struct rrr_instance_thread_data *identifier) {
	struct duplicator_reader *result = NULL;

	readers_register_lock(data);

	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &data->readers[i];
		if (test->identifier == NULL) {
			if (rrr_fifo_buffer_init(&test->buffer) != 0) {
				RRR_MSG_ERR("Could not initialize fifo buffer for sender %s in duplicator\n", INSTANCE_D_NAME(identifier));
				break;
			}
			test->identifier = identifier;
			data->readers_count++;
			result = test;
			break;
		}
	}

	readers_register_unlock(data);

	if (result == NULL) {
		RRR_MSG_ERR("Maximum number of readers reached: %i\n", DUPLICATOR_MAX_SENDERS);
	}

	return result;
}

struct read_minimum_data {
	int (*callback)(struct rrr_fifo_callback_args *callback_data, char *data, unsigned long int size);
	struct rrr_fifo_callback_args *poll_data;
	uint64_t result_timestamp;
};

/* Callback must free or take care of memory even in case of an error */
int read_minimum_callback (struct rrr_fifo_callback_args *args, char *data, unsigned long int size) {
	int ret = 0;

	(void)(size);

	struct read_minimum_data *minimum_callback_data = args->private_data;
	struct rrr_fifo_callback_args *fifo_callback_data_orig = minimum_callback_data->poll_data;

	struct rrr_message *message_new = rrr_message_duplicate((struct rrr_message *) data);
	if (message_new == NULL) {
		RRR_MSG_ERR("Could not allocate data in duplicator read_minimum_callback\n");
		return 1;
	}

	uint64_t timestamp = message_new->timestamp_from;

	int res = minimum_callback_data->callback(fifo_callback_data_orig, (char*) message_new, MSG_TOTAL_SIZE(message_new));

	if (res == 0) {
		if (timestamp > minimum_callback_data->result_timestamp) {
			minimum_callback_data->result_timestamp = timestamp;
		}
	}
	else {
		ret = 1;
	}

	return ret;
}

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct duplicator_data *duplicator_data = data->private_data;
	struct rrr_instance_thread_data *instance_reader = poll_data->source;
	struct duplicator_reader *reader = find_reader(duplicator_data, instance_reader);

	if (reader == NULL) {
		reader = register_reader(duplicator_data, instance_reader);
		if (reader == NULL) {
			RRR_MSG_ERR("Could not register reader %p in duplicator instance %s\n", instance_reader, INSTANCE_D_NAME(data));
			return 1;
		}
		else {
			RRR_DBG_2("Duplicator instance %s registered reader %s\n", INSTANCE_D_NAME(data), INSTANCE_D_NAME(instance_reader));
		}
	}

	struct read_minimum_data minimum_callback_data = {callback, poll_data, 0};
	struct rrr_fifo_callback_args fifo_callback_data = {NULL, &minimum_callback_data, 0};

	int res = rrr_fifo_read_minimum (
			&duplicator_data->input_buffer,
			NULL,
			read_minimum_callback,
			&fifo_callback_data,
			reader->read_position,
			wait_milliseconds
	);

	if (minimum_callback_data.result_timestamp > 0) {
		RRR_DBG_3("Duplicator %s New read position for reader %s: %lu\n",
				INSTANCE_D_NAME(duplicator_data->data),
				INSTANCE_D_NAME(reader->identifier),
				minimum_callback_data.result_timestamp
		);

		readers_read_lock(duplicator_data);
		reader->read_position = minimum_callback_data.result_timestamp;
		readers_read_unlock(duplicator_data);
	}

	if (res == RRR_FIFO_GLOBAL_ERR) {
		return 1;
	}

	return 0;
}

int poll_callback(struct rrr_fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = caller_data->private_data;
	struct duplicator_data *duplicator_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;

	int ret = 0;

	RRR_DBG_3 ("duplicator %s: Result from duplicator: measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->data_numeric, size);
	/*
	readers_read_lock(duplicator_data);

	uint64_t time_begin = time_get_64();

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

			uint64_t time_middle = time_get_64();

			VL_DEBUG_MSG_3 ("duplicator %s write measurement to buffer %p: %" PRIu64 " to %s time since begin is %" PRIu64 "\n",
					INSTANCE_D_NAME(thread_data), &test->buffer, message->data_numeric,
					INSTANCE_D_NAME(test->identifier), time_middle - time_begin);
			fifo_buffer_write(&test->buffer, new_data, size);
			count++;
		}
	}

	uint64_t time_end = time_get_64();

	VL_DEBUG_MSG_3 ("duplicator %s loop time: %" PRIu64 "\n", INSTANCE_D_NAME(thread_data), time_end - time_begin);

	readers_read_unlock(duplicator_data);

	free(data);

	VL_DEBUG_MSG_3 ("duplicator %s: Message duplicated %i times\n", INSTANCE_D_NAME(thread_data), count);
*/

	rrr_update_watchdog_time(thread_data->thread);
	rrr_fifo_buffer_write_ordered(&duplicator_data->input_buffer, message->timestamp_from, data, size);

	return ret;
}

int maintain_input_buffer(struct duplicator_data *data) {
	int ret = 0;

	uint64_t lowest_timestamp = 0xffffffffffffffff;

	readers_read_lock(data);
	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		struct duplicator_reader *test = &data->readers[i];
		if (test->identifier != NULL) {
			if (lowest_timestamp > test->read_position) {
				lowest_timestamp = test->read_position;
			}
		}
	}
	readers_read_unlock(data);

	if (rrr_fifo_clear_order_lt(&data->input_buffer, lowest_timestamp) == RRR_FIFO_GLOBAL_ERR) {
		RRR_MSG_ERR("Duplicator got error from fifo_clear_order_lt\n");
		ret = 1;
	}

	return ret;
}

void data_cleanup(void *arg) {
	struct duplicator_data *data = arg;
	rrr_fifo_buffer_invalidate(&data->input_buffer);
	pthread_mutex_lock(&data->readers_lock);
	for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
		for (int i = 0; i < DUPLICATOR_MAX_SENDERS; i++) {
			struct duplicator_reader *test = &data->readers[i];
			if (test != NULL) {
				rrr_fifo_buffer_invalidate(&test->buffer);
			}
		}
	}
	data->readers_count = 0;
	pthread_mutex_unlock(&data->readers_lock);
}

int data_init(struct duplicator_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;
	memset(data, '\0', sizeof(*data));
	data->data = thread_data;
	ret |= pthread_mutex_init(&data->readers_lock, NULL);
	ret |= rrr_fifo_buffer_init(&data->input_buffer);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static void *thread_entry_duplicator (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct duplicator_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in duplicator instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("duplicator thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		RRR_MSG_ERR("duplicator instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	RRR_DBG_1 ("duplicator instance %s started thread, waiting a bit for readers to register\n",
			INSTANCE_D_NAME(thread_data));

	usleep (500000); // 500ms

	RRR_DBG_1 ("duplicator instance %s detected %i readers for now\n",
			INSTANCE_D_NAME(thread_data), data->readers_count);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_update_watchdog_time(thread_data->thread);

		int input_buffer_size = rrr_fifo_buffer_get_entry_count(&data->input_buffer);

		if (input_buffer_size > 5000) {
			usleep(1000);
		}
		else {
			if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
				break;
			}
		}

		if (maintain_input_buffer(data) != 0) {
			RRR_MSG_ERR("Duplicator instance %s got error from maintain function\n", INSTANCE_D_NAME(thread_data));
			break;
		}
	}

	out_message:
	RRR_DBG_1 ("Thread duplicator %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
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
		thread_entry_duplicator,
		NULL,
		NULL,
		NULL,
		poll_delete,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "duplicator";

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
	RRR_DBG_1 ("Destroy duplicator module\n");
}

