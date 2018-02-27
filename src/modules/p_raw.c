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
#include <inttypes.h>

#include "../modules.h"
#include "../lib/measurement.h"
#include "../lib/threads.h"
#include "p_raw.h"

// Should not be smaller than module max
#define VL_RAW_MAX_SENDERS VL_MODULE_MAX_SENDERS

void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct vl_reading *reading = (struct vl_reading *) data;
	printf ("Result from buffer: %s measurement %u size %lu\n", reading->message.data, reading->reading_millis, size);
	free(data);
}


static void *thread_entry_raw(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;

	printf ("Raw thread data is %p\n", thread_data);

	if (senders_count > VL_RAW_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for raw module, max is %i\n", VL_RAW_MAX_SENDERS);
		pthread_exit(0);
	}

	int (*poll[VL_RAW_MAX_SENDERS])(struct module_thread_data *data, void (*callback)(void *caller_data, char *data, unsigned long int size), struct module_thread_data *caller_data);

	for (int i = 0; i < senders_count; i++) {
		printf ("Raw: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;
	}

	printf ("Raw started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for raw processor module\n");
		pthread_exit(0);
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	for (int i = 0; i < senders_count; i++) {
		while (thread_get_state(thread_data->senders[i]->thread) != VL_THREAD_STATE_RUNNING && thread_check_encourage_stop(thread_data->thread) != 1) {
			update_watchdog_time(thread_data->thread);
			printf ("Raw: Waiting for source thread to become ready\n");
			usleep (5000);
		}
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		printf ("Raw polling data\n");
		for (int i = 0; i < senders_count; i++) {
			int res = poll[i](thread_data->senders[i], poll_callback, thread_data);
			if (!(res >= 0)) {
				printf ("Raw module received error from poll function\n");
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
	printf ("Thread raw %p exiting\n", thread_data->thread);

	out:
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_raw,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "raw";

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
	printf ("Destroy raw module\n");
}

