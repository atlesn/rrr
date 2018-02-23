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

static void module_destroy(struct module_dynamic_data *data) {
	free(data);
}

struct dummy_data {
	struct fifo_buffer *buffer;
};

static int poll(struct module_dynamic_data *arg, void (*callback)(void*)) {
	struct module_dynamic_data *module_data = (struct module_dynamic_data *) arg;
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
	struct module_dynamic_data *module_data = (struct module_dynamic_data *) arg;
	struct dummy_data *data = data_init();

	pthread_cleanup_push(data_cleanup, data);
	module_data->private_data = data;

	static const char *dummy_msg = "Dummy measurement of time";

	while (1) {
		uint64_t time = time_get_64();

		struct reading *reading = reading_new(time, NULL, 0);
		memcpy(reading->msg, dummy_msg, strlen(dummy_msg)+1);
		reading->msg_size = strlen(dummy_msg) + 1;
		usleep (500000); // 500 ms

		fifo_buffer_write(data->buffer, reading);
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static struct module_operations module_operations = {
		module_destroy,
		thread_entry,
		poll,
		NULL,
		NULL
};

static const char *module_name = "dummy";

struct module_dynamic_data *module_get_data() {
		struct module_dynamic_data *data = malloc(sizeof(*data));
		data->name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
		return data;
};

__attribute__((constructor)) void load(void) {
}
