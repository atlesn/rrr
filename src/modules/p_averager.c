/*

Voltage Logger

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

#include "../modules.h"
#include "../lib/measurement.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"

struct averager_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
};

// Should not be smaller than module max
#define VL_AVERAGER_MAX_SENDERS VL_MODULE_MAX_SENDERS

// In seconds, keep x seconds of readings in the buffer
#define VL_AVERAGER_TIMESPAN 15

// Create an average/max/min-reading every x seconds
#define VL_AVERAGER_INTERVAL 10

void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct vl_reading *reading = (struct vl_reading *) data;

	struct averager_data *averager_data = thread_data->private_data;
	struct fifo_buffer *input_buffer = &averager_data->input_buffer;

	fifo_buffer_write_ordered(input_buffer, reading->message.timestamp_from, data, size);

	printf ("Result from buffer: %s size %lu\n", reading->message.data, size);
}

struct averager_data *data_init(struct module_thread_data *module_thread_data) {
	// Use special memory region provided in module_thread_data which we don't have to free
	struct averager_data *data = (struct averager_data *) module_thread_data->private_memory;
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->input_buffer);
	fifo_buffer_init(&data->output_buffer);
	return data;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct averager_data *data = (struct averager_data *) arg;
	fifo_buffer_invalidate(&data->input_buffer);
	fifo_buffer_invalidate(&data->output_buffer);
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}



static void *thread_entry_averager(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;

	struct averager_data *data = data_init(thread_data);

	printf ("Averager  thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	thread_data->private_data = data;

	if (senders_count > VL_AVERAGER_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for averager module, max is %i\n", VL_AVERAGER_MAX_SENDERS);
		pthread_exit(0);
	}

	int (*poll[VL_AVERAGER_MAX_SENDERS])(struct module_thread_data *data, void (*callback)(void *caller_data, char *data, unsigned long int size), struct module_thread_data *caller_data);

	for (int i = 0; i < senders_count; i++) {
		printf ("Averager: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;
	}

	printf ("Averager started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for averager processor module\n");
		pthread_exit(0);
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	for (int i = 0; i < senders_count; i++) {
		while (thread_get_state(thread_data->senders[i]->thread) != VL_THREAD_STATE_RUNNING && thread_check_encourage_stop(thread_data->thread) != 1) {
			update_watchdog_time(thread_data->thread);
			printf ("Averager: Waiting for source thread to become ready\n");
			usleep (5000);
		}
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		printf ("Averager polling data\n");
		for (int i = 0; i < senders_count; i++) {
			int res = poll[i](thread_data->senders[i], poll_callback, thread_data);
			if (!(res >= 0)) {
				printf ("Averager module received error from poll function\n");
				err = 1;
				break;
			}
		}

		if (err != 0) {
			break;
		}
		usleep (1249000); // 1249 ms
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_STOPPING);
	printf ("Thread averager %p exiting\n", thread_data->thread);

	out:

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_averager,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "averager";

__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(struct module_dynamic_data *data) {
	printf ("Destroy averager module\n");
}

