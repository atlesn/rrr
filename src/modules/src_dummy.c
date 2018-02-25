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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>

#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../modules.h"
#include "../measurement.h"
#include "src_dummy.h"

struct dummy_data {
	struct fifo_buffer buffer;
};

static int poll (
		struct module_thread_data *data,
		void (*callback)(void *caller_data, char *data, unsigned long int size),
		struct module_thread_data *caller_data
) {
	struct dummy_data *dummy_data = data->private_data;
	int res = fifo_read_clear_forward(&dummy_data->buffer, NULL, callback, caller_data);
	printf ("Poll result was: %i\n", res);
	if (res == 0) {
		return VL_POLL_EMPTY_RESULT_OK;
	}
	else if (res >= 1) {
		return VL_POLL_RESULT_OK;
	}
	else {
		return VL_POLL_RESULT_ERR;
	}
}

struct dummy_data *data_init(struct module_thread_data *module_thread_data) {
	// Use special memory region provided in module_thread_data which we don't have to free
	struct dummy_data *data = (struct dummy_data *) module_thread_data->private_memory;
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->buffer);
	return data;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct dummy_data *data = (struct dummy_data *) arg;
	fifo_buffer_invalidate(&data->buffer);
	fifo_buffer_destroy(&data->buffer);
}

void dummy_set_stopping(void *arg) {
	struct vl_thread *thread = arg;
	// This must be done to stop readers from accessing us
	thread_set_state(thread, VL_THREAD_STATE_STOPPING);
}

static void *thread_entry(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	struct dummy_data *data = data_init(thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(dummy_set_stopping, start_data->thread);
	thread_data->private_data = data;

	static const char *dummy_msg = "Dummy measurement of time";

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		uint64_t time = time_get_64();

		struct reading *reading = reading_new(time, NULL, 0);
		memcpy(reading->msg, dummy_msg, strlen(dummy_msg)+1);
		reading->msg_size = strlen(dummy_msg) + 1;
		fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading));

		usleep (250000); // 250 ms

	}

	printf ("Dummy received encourage stop\n");

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry,
		poll,
		NULL
};

static const char *module_name = "dummy";


__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
		data->name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(struct module_dynamic_data *data) {
}


