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

#include "../lib/instances.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_RAW_MAX_SENDERS VL_MODULE_MAX_SENDERS

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct vl_message *reading = (struct vl_message *) data;
	VL_DEBUG_MSG_2 ("Raw: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);
	free(data);
	return 0;
}

static void *thread_entry_raw(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->init_data.senders_count;

	VL_DEBUG_MSG_1 ("Raw thread data is %p\n", thread_data);

	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_RAW_MAX_SENDERS) {
		VL_MSG_ERR ("Too many senders for raw module, max is %i\n", VL_RAW_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_RAW_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *poll_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);


	for (int i = 0; i < senders_count; i++) {
		VL_DEBUG_MSG_1 ("Raw: found sender %p\n", thread_data->init_data.senders[i]);
		poll[i] = thread_data->init_data.senders[i]->dynamic_data->operations.poll_delete;

		if (poll[i] == NULL) {
			poll[i] = thread_data->init_data.senders[i]->dynamic_data->operations.poll_delete_ip;
			if (poll[i] == NULL) {
				VL_MSG_ERR ("Raw cannot use sender %s using module %s, lacking poll_delete or poll_delete_ip function for instance %s.\n",
						thread_data->init_data.senders[i]->dynamic_data->instance_name,
						thread_data->init_data.senders[i]->dynamic_data->module_name,
						thread_data->init_data.module->module_name
					);
				goto out_message;
			}
		}
	}

	VL_DEBUG_MSG_1 ("Raw started thread %p\n", thread_data);
	if (senders_count == 0) {
		VL_MSG_ERR ("Error: Sender was not set for raw processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->init_data.senders[i]->thread_data, poll_callback, &poll_data);
			if (!(res >= 0)) {
				VL_MSG_ERR ("Raw module received error from poll function\n");
				err = 1;
				break;
			}
		}

		if (err != 0) {
			break;
		}
		usleep (100000); // 100 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread raw %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_raw,
		NULL,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "raw";

__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload() {
	VL_DEBUG_MSG_1 ("Destroy raw module\n");
}

