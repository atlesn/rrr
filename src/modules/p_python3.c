/*

Voltage Logger

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
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <errno.h>

#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/python3.h"
#include "../global.h"

#define RRR_PYTHON3_MAX_SENDERS 16

struct python3_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	char *python3_file;
};

void data_init(struct python3_data *data) {
	memset (data, '\0', sizeof(*data));
	fifo_buffer_init (&data->input_buffer);
	fifo_buffer_init (&data->output_buffer);
}

void data_cleanup(void *arg) {
	struct python3_data *data = arg;
	fifo_buffer_invalidate (&data->input_buffer);
	fifo_buffer_invalidate (&data->output_buffer);
	RRR_FREE_IF_NOT_NULL(data->python3_file);
}

int python3_parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	char *python3_file = NULL;

	ret = rrr_instance_config_get_string_noconvert_silent (&python3_file, config, "python3_file");

	if (ret == 0) {
		data->python3_file = python3_file;
	}
	else {
		VL_MSG_ERR("No python3_file specified for python module\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

// Poll request from other modules
int python3_poll_delete (
	struct module_thread_data *thread_data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *caller_data
) {
	struct python3_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->output_buffer, NULL, callback, caller_data);
}

int poll_callback_local (struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct python3_data *python3_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	VL_DEBUG_MSG_3 ("python3: Result from buffer (local): %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&python3_data->input_buffer, (char*) reading, sizeof(*reading));

	return 0;
}

static void *thread_entry_python3 (struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	int senders_count = thread_data->init_data.senders_count;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;

	VL_DEBUG_MSG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	data_init(data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (python3_parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (senders_count > RRR_PYTHON3_MAX_SENDERS) {
		VL_MSG_ERR ("Too many senders for python3 module, max is %i\n", RRR_PYTHON3_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[RRR_PYTHON3_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *poll_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);

	for (int i = 0; i < senders_count; i++) {
		VL_DEBUG_MSG_1 ("python3: found sender %p\n", thread_data->init_data.senders[i]);

		poll[i] = thread_data->init_data.senders[i]->dynamic_data->operations.poll_delete;

		if (poll[i] == NULL) {
			VL_MSG_ERR ("python3 cannot use sender '%s', module '%s' is lacking poll_delete function.\n",
					thread_data->init_data.senders[i]->dynamic_data->instance_name,
					thread_data->init_data.senders[i]->dynamic_data->module_name
			);
			goto out_message;
		}
	}

	VL_DEBUG_MSG_1 ("python3 started thread %p\n", thread_data);
	if (senders_count == 0) {
		VL_MSG_ERR ("Error: Sender was not set for python3 processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res;

			res = poll[i](thread_data->init_data.senders[i]->thread_data, poll_callback_local, &poll_data);

			if (!(res >= 0)) {
				VL_MSG_ERR ("python3 module received error from poll function\n");
				err = 1;
				break;
			}
		}

//		process_entries(thread_data);

		if (err != 0) {
			break;
		}
		usleep (20000); // 20 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread python3 %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_python3,
		NULL,
		NULL,
		NULL,
		python3_poll_delete
};

static const char *module_name = "python3";

__attribute__((constructor)) void load() {
	Py_Initialize();
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload() {
	VL_DEBUG_MSG_1 ("Destroy python3 module\n");
	Py_Finalize();
}

