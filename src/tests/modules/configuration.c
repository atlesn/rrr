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

#include <stdlib.h>
#include <unistd.h>

#include "type_array.h"
#include "../test.h"
#include "../../lib/instances.h"
#include "../../lib/modules.h"

/* This is picked up by main after the tests are complete and all threads have stopped */
static int configuration_test_result = 1;

int get_configuration_test_result(void) {
	return configuration_test_result;
}

void set_configuration_test_result(int result) {
	configuration_test_result = result;
}

struct configuration_test_data {
	int dummy;
};


void data_init(struct configuration_test_data *data) {
	data->dummy = 1;
}

void data_cleanup(void *_data) {
	struct configuration_test_data *data = _data;
	data->dummy = 0;
}

static void *thread_entry_configuration_test (struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct configuration_test_data *data = thread_data->private_data = thread_data->private_memory;

	thread_data->thread = start_data->thread;

	data_init(data);

	VL_DEBUG_MSG_1 ("configuration test thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

/*	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);
		usleep (20000); // 20 ms
	}*/

	update_watchdog_time(thread_data->thread);

	int ret;

	/* Test array type and data endian conversion */
	ret = test_type_array(thread_data->init_data.module->all_instances,
			"instance_udpreader","instance_buffer");
	TEST_MSG("Result from array test: %i\n", ret);

	update_watchdog_time(thread_data->thread);

	set_configuration_test_result(ret);

	/* We exit without looping which also makes the other loaded modules exit */

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_configuration_test,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};
static const char *module_name = "configuration_test";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_SOURCE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->special_module_operations = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy configuration test module\n");
}
