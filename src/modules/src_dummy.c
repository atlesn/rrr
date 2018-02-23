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
	struct fifo_buffer *buffer;
};

static int poll(struct module_thread_data *module_data, void (*callback)(void*)) {
	struct dummy_data *data = (struct dummy_data *) module_data->private_data;
	return fifo_read_clear_forward(data->buffer, NULL, callback);
}

struct dummy_data *data_init() {
	struct dummy_data *data = malloc(sizeof(*data));
	data->buffer = fifo_buffer_init();
	return data;
}

void data_cleanup(void *arg) {
	struct dummy_data *data = (struct dummy_data *) arg;
	fifo_buffer_invalidate(data->buffer);
	fifo_buffer_destroy(data->buffer);
	free(data);
}

static void *thread_entry(void *arg) {
	struct module_thread_data *thread_data = arg;
	struct dummy_data *data = data_init();

	pthread_cleanup_push(data_cleanup, data);
	thread_data->private_data = data;

	static const char *dummy_msg = "Dummy measurement of time";

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		uint64_t time = time_get_64();

		struct reading *reading = reading_new(time, NULL, 0);
		memcpy(reading->msg, dummy_msg, strlen(dummy_msg)+1);
		reading->msg_size = strlen(dummy_msg) + 1;
		fifo_buffer_write(data->buffer, reading);

		usleep (500000); // 500 ms

	}

	pthread_cleanup_pop(1);
	pthread_exit(0);

	return NULL;
}

static struct module_operations module_operations = {
		thread_entry,
		poll,
		NULL
};

static const char *module_name = "dummy";


__attribute__((constructor)) void load(struct module_dynamic_data *data) {
		data->name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

__attribute__((constructor)) void unload(struct module_dynamic_data *data) {
}


