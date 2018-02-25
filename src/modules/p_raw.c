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
#include "../measurement.h"
#include "../lib/threads.h"
#include "p_raw.h"


void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct reading *reading = (struct reading *) data;
	printf ("Result from buffer: %s size %lu\n", reading->msg, size);
	free(data);
}


static void *thread_entry(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	struct module_thread_data *sender_data = thread_data->sender;
	int (*poll)(struct module_thread_data *data, void (*callback)(void *caller_data, char *data, unsigned long int size), struct module_thread_data *caller_data) = NULL;
	poll = sender_data->module->operations.poll;


	printf ("Raw started thread %p\n", thread_data);
	if (sender_data == NULL) {
		fprintf (stderr, "Error: Sender was not set for raw processor module\n");
		pthread_exit(0);
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	while (thread_get_state(sender_data->thread) != VL_THREAD_STATE_RUNNING && thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);
		printf ("Raw: Waiting for source thread to become ready\n");
		usleep (5000);
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		printf ("Raw polling data\n");
		int res = poll(sender_data, poll_callback, thread_data);
		if (!(res >= 0)) {
			printf ("Raw module received error from poll function\n");
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
		thread_entry,
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

