/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "../../lib/log.h"

#include "type_array.h"
#include "../test.h"
#include "../../lib/instances.h"
#include "../../lib/modules.h"
#include "../../lib/messages/msg_msg.h"
#include "../../lib/instance_config.h"
#include "../../lib/util/posix.h"
#include "../../lib/util/macro_utils.h"

/* This is picked up by main after the tests are complete and all threads have stopped */
static int test_module_result = 1;

int get_test_module_result(void) {
	return test_module_result;
}

void set_test_module_result(int result) {
	test_module_result = result;
}

struct test_module_data {
	rrr_setting_uint exit_delay_ms;
	int dummy;

	char *test_method;
	char *test_output_instance;

	struct rrr_test_function_data test_function_data;
};


void data_init(struct test_module_data *data) {
	memset(data, '\0', sizeof(*data));
	data->dummy = 1;
}

void data_cleanup(void *_data) {
	struct test_module_data *data = _data;
	data->dummy = 0;
	RRR_FREE_IF_NOT_NULL(data->test_method);
	RRR_FREE_IF_NOT_NULL(data->test_output_instance);
}

int parse_config (struct test_module_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("test_method", test_method);
	if (data->test_method == NULL) {
		RRR_MSG_0("test_method not set for test module instance %s\n", config->name);
		ret = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("test_output_instance", test_output_instance);
	if (data->test_output_instance == NULL) {
		RRR_MSG_0("test_method not set for test module instance %s\n", config->name);
		ret = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("test_exit_delay_ms", exit_delay_ms, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("test_array_str_to_h_conversion", test_function_data.do_array_str_to_h_conversion, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("test_array_blob_field_divide", test_function_data.do_blob_field_divide, 0);

	out:
	if (ret != 0) {
		RRR_FREE_IF_NOT_NULL(data->test_method);
		RRR_FREE_IF_NOT_NULL(data->test_output_instance);
	}
	return ret;
}

static void *thread_entry_test_module (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;

	int ret = 0;
	data_init(data);

	RRR_DBG_1 ("configuration test thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	pthread_cleanup_push(data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// Uncomment to make test module halt before it runs
/*	while (rrr_thread_signal_encourage_stop_check(thread_data->thread) != 1) {
		rrr_thread_watchdog_time_update(thread_data->thread);
		rrr_posix_usleep (20000); // 20 ms
	}*/

	rrr_thread_watchdog_time_update(thread);

	if (strcmp(data->test_method, "test_dummy") == 0) {
		rrr_posix_usleep(1000000); // 1s
		ret = 0;
	}
	else if (strcmp(data->test_method, "test_array") == 0) {
		ret = test_array (
				&data->test_function_data,
				thread_data->init_data.module->all_instances,
				thread_data,
				data->test_output_instance
		);
		TEST_MSG("Result from array test: %i\n", ret);
	}
	else if (strcmp(data->test_method, "test_averager") == 0) {
		ret = test_averager (
				&data->test_function_data,
				thread_data->init_data.module->all_instances,
				thread_data,
				data->test_output_instance
		);
		TEST_MSG("Result from averager test: %i\n", ret);
	}
	else if (strcmp(data->test_method, "test_anything") == 0) {
		ret = test_anything (
				&data->test_function_data,
				thread_data->init_data.module->all_instances,
				thread_data,
				data->test_output_instance
		);
		TEST_MSG("Result from anything test: %i\n", ret);
	}
	else if (strcmp(data->test_method, "test_mysql") == 0) {
#ifdef RRR_ENABLE_DB_TESTING
		ret = test_type_array_mysql (
				&data->test_function_data,
				thread_data->init_data.module->all_instances,
				thread_data,
				data->test_output_instance
		);
		TEST_MSG("Result from MySQL test: %i\n", ret);
#else
		TEST_MSG("MySQL test not enabled in configuration with --enable-database-testing\n");
#endif
	}
	else {
		RRR_MSG_0("Unknown test type '%s' in test module\n", data->test_method);
		ret = 1;
		goto out_message;
	}

	set_test_module_result(ret);

	if (data->exit_delay_ms > 0) {
		TEST_MSG("Exit delay configured, %" PRIrrrbl " ms\n", data->exit_delay_ms);
		rrr_posix_usleep(data->exit_delay_ms * 1000);
	}

	/* We exit without looping which also makes the other loaded modules exit */

	out_message:
	RRR_DBG_1 ("Thread configuration test instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_test_module,
		NULL,
		NULL,
		NULL
};
static const char *module_name = "test_module";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
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
