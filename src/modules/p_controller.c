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

#include "../lib/buffer.h"
#include "../modules.h"
#include "../lib/messages.h"
#include "../lib/threads.h"

// Should not be smaller than module max
#define VL_CONTROLLER_MAX_SENDERS VL_MODULE_MAX_SENDERS

struct controller_data {
	struct fifo_buffer to_ipclient;
	struct fifo_buffer to_blockdev;
};

int poll_delete (
	struct module_thread_data *data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *poll_data
) {
	struct controller_data *controller_data = data->private_data;
	struct module_thread_data *source = poll_data->source;

	if (strcmp (source->module->name, "ipclient") == 0) {
		fifo_read_clear_forward(&controller_data->to_ipclient, NULL, callback, poll_data);
	}
	else if (strcmp (source->module->name, "blockdev") == 0) {
		fifo_read_clear_forward(&controller_data->to_blockdev, NULL, callback, poll_data);
	}
	else {
		fprintf (stderr, "controller: No output buffer defined for module %s\n", source->module->name);
		return 1;
	}

	return 0;
}

int poll_callback(struct fifo_callback_args *caller_data, char *data, unsigned long int size) {
	struct controller_data *controller_data = caller_data->private_data;
	struct module_thread_data *source = caller_data->source;
	struct vl_message *message = (struct vl_message *) data;

	printf ("controller: Result from buffer: %s measurement %" PRIu64 " size %lu\n", message->data, message->data_numeric, size);

	if (strcmp (source->module->name, "blockdev") == 0) {
		fifo_buffer_write(&controller_data->to_ipclient, data, size);
	}
	else if (strcmp (source->module->name, "ipclient") == 0) {
		if (message->type == MSG_TYPE_TAG) {
			fifo_buffer_write(&controller_data->to_blockdev, data, size);
		}
		else {
			// Discard everything else as trash
			fprintf (stderr, "controller: Warning: Discarding message from ipclient timestamp %" PRIu64 "\n", message->timestamp_from);
			free(message);
		}
	}
	else if (
		(strcmp (source->module->name, "averager") == 0) ||
		(strcmp (source->module->name, "voltmonitor") == 0) ||
		(strcmp (source->module->name, "dummy") == 0)
	) {
		void *data_2 = message_duplicate(message); // Remember to copy message!
		fifo_buffer_write(&controller_data->to_ipclient, data, size);
		fifo_buffer_write(&controller_data->to_blockdev, data_2, size);
	}
	else {
		fprintf (stderr, "controller: Don't know where to route messages from %s\n", source->module->name);
		free(data);
	}

	return 0;
}

void data_init(struct controller_data *data) {
	fifo_buffer_init(&data->to_blockdev);
	fifo_buffer_init(&data->to_ipclient);
}

void data_cleanup(void *arg) {
	struct controller_data *data = arg;
	fifo_buffer_invalidate(&data->to_blockdev);
	fifo_buffer_invalidate(&data->to_ipclient);
}

static void *thread_entry_controller(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;

	struct controller_data *data = (struct controller_data *) thread_data->private_memory;
	thread_data->private_data = data;

	printf ("controller thread data is %p\n", thread_data);

	data_init(data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_CONTROLLER_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for controller module, max is %i\n", VL_CONTROLLER_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_CONTROLLER_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *caller_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);

	for (int i = 0; i < senders_count; i++) {
		printf ("controller: found sender %s\n", thread_data->senders[i]->thread->name);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;

		if (poll[i] == NULL) {
			fprintf (stderr, "controller cannot use sender %s, lacking poll delete function.\n", thread_data->senders[i]->thread->name);
			goto out_message;
		}
	}

	printf ("controller started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for controller processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data->senders[i], data};

			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				fprintf (stderr, "controller module received error from poll function\n");
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
	printf ("Thread controller %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_controller,
		NULL,
		NULL,
		poll_delete,
		NULL
};

static const char *module_name = "controller";

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
	printf ("Destroy controller module\n");
}

