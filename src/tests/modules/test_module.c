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
#include "../../lib/messages.h"

/* This is picked up by main after the tests are complete and all threads have stopped */
static int test_module_result = 1;

int get_test_module_result(void) {
	return test_module_result;
}

void set_test_module_result(int result) {
	test_module_result = result;
}

struct test_module_data {
	int dummy;
};


void data_init(struct test_module_data *data) {
	data->dummy = 1;
}

void data_cleanup(void *_data) {
	struct test_module_data *data = _data;
	data->dummy = 0;
}

static void *thread_entry_test_module (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;
	int ret = 0;
	struct vl_message *array_message = NULL;
	struct vl_message *array_message_python3 = NULL;

	data_init(data);

	VL_DEBUG_MSG_1 ("configuration test thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(array_message,array_message_python3);
	VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(array_message,array_message);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

/*	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);
		usleep (20000); // 20 ms
	}*/

	update_watchdog_time(thread_data->thread);

	/* Test array type and data endian conversion */
	ret = test_type_array (
			&array_message,
			&array_message_python3,
			thread_data->init_data.module->all_instances,
			"instance_udpreader",
			"instance_socket",
			"instance_buffer_from_perl5",
			"instance_buffer_from_python3"
	);
	TEST_MSG("Result from array test: %i %p\n", ret, array_message);

	update_watchdog_time(thread_data->thread);

	if (ret != 0) {
		goto configtest_done;
	}

	/* Test which sets up the MySQL database and then listens on a
	 * buffer for ACK message */
	ret = test_type_array_mysql_and_network(thread_data->init_data.module->all_instances,
			"instance_dummy_input",
			"instance_buffer_msg",
			"instance_mysql",
			array_message
	);
	TEST_MSG("Result from MySQL test: %i\n", ret);


	configtest_done:
	set_test_module_result(ret);

	/* We exit without looping which also makes the other loaded modules exit */

	VL_DEBUG_MSG_1 ("Thread configuration test instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_test_module,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};
static const char *module_name = "test_module";

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
