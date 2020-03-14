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

static void *thread_entry_test_module (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;
	int ret = 0;
	struct rrr_message *array_message_perl5 = NULL;
	struct rrr_message *array_message_python3 = NULL;
	struct rrr_message *array_message_mqtt_raw = NULL;

	data_init(data);

	RRR_DBG_1 ("configuration test thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(array_message,array_message_mqtt_raw);
	RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(array_message,array_message_python3);
	RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(array_message,array_message_perl5);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

/*	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);
		usleep (20000); // 20 ms
	}*/

	rrr_update_watchdog_time(thread_data->thread);

	/* Test array type and data endian conversion */
	ret = test_type_array (
			&array_message_perl5,
			&array_message_python3,
			&array_message_mqtt_raw,
			thread_data->init_data.module->all_instances,
			"instance_udpreader",
			"instance_socket",
			"instance_buffer_from_perl5",
			"instance_buffer_from_python3",
			"instance_buffer_from_mqtt_raw"
	);
	TEST_MSG("Result from array test: %i %p, %p and %p\n", ret, array_message_perl5, array_message_python3, array_message_mqtt_raw);

	rrr_update_watchdog_time(thread_data->thread);

	if (ret != 0) {
		goto configtest_done;
	}

	/* Test which sets up the MySQL database */
	ret = test_type_array_mysql_and_network(thread_data->init_data.module->all_instances,
			"instance_dummy_input",
			"instance_buffer_msg",
			"instance_mysql",
			array_message_perl5
	);
	TEST_MSG("Result from MySQL test: %i\n", ret);


	configtest_done:
	set_test_module_result(ret);

	/* We exit without looping which also makes the other loaded modules exit */

	RRR_DBG_1 ("Thread configuration test instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
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

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_SOURCE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->special_module_operations = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy configuration test module\n");
}
