/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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
#include "../../lib/allocator.h"

#include "type_array.h"
#include "../test.h"
#include "../../lib/event/event_collection_struct.h"
#include "../../lib/event/event_collection.h"
#include "../../lib/instances.h"
#include "../../lib/threads.h"
#include "../../lib/modules.h"
#include "../../lib/messages/msg_msg.h"
#include "../../lib/instance_config.h"
#include "../../lib/util/posix.h"
#include "../../lib/util/macro_utils.h"
#include "../../lib/map.h"

static volatile int test_module_result = 1;

int test_module_result_get (void) {
	return test_module_result;
}

static void __test_module_result_set (int result) {
	test_module_result = result;
}

struct test_module_data {
	rrr_setting_uint exit_delay_ms;

	uint64_t start_time;

	char *test_method;
	struct rrr_map array_check_values;

	struct rrr_test_function_data test_function_data;

	struct rrr_event_collection events;

	struct rrr_test_data test_data;
};


void data_init(struct test_module_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));
}

void data_cleanup(void *_data) {
	struct test_module_data *data = _data;
	rrr_event_collection_clear(&data->events);
	RRR_FREE_IF_NOT_NULL(data->test_method);
}

int parse_config (struct test_module_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("test_method", test_method);
	if (data->test_method == NULL) {
		RRR_MSG_0("test_method not set for test module instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("test_exit_delay_ms", exit_delay_ms, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("test_array_str_to_h_conversion", test_function_data.do_array_str_to_h_conversion, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("test_array_blob_field_divide", test_function_data.do_blob_field_divide, 0);

	if (strcmp(data->test_method, "test_anything") == 0) {
		if ((ret = rrr_instance_config_parse_comma_separated_to_map (
				&data->array_check_values,
				config,
				"test_anything_check_values"
		)) != 0) {
			if (ret == RRR_SETTING_NOT_FOUND) {
				ret = 0;
			}
			else {
				RRR_MSG_0("Failed to parse parameter test_anything_check_values\n");
				goto out;
			}
		}
	}


	out:
	return ret;
}

int test_dummy_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;

	if (rrr_time_get_64() - data->start_time > 1 * 1000 * 1000 /* 1 second */) {
		__test_module_result_set(2);
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

int test_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;

	int ret = 0;

	data_init(data, thread_data);

	RRR_DBG_1 ("configuration test thread data is %p, size of private data: %llu\n",
		thread_data, (long long unsigned) sizeof(*data));

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_error;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// Uncomment to make test module halt before it runs
/*	while (rrr_thread_signal_encourage_stop_check(thread_data->thread) == 0) {
		rrr_thread_watchdog_time_update(thread_data->thread);
		rrr_posix_usleep (20000); // 20 ms
	}*/

	rrr_thread_watchdog_time_update(thread);

	struct rrr_test_data test_data = {
		.array_check_values = &data->array_check_values,
		.config = &data->test_function_data,
		.result = &test_module_result,
		.events = &data->events,
		.thread_data = thread_data
	};

	memcpy(&data->test_data, &test_data, sizeof(test_data));

	data->start_time = rrr_time_get_64();

	if (strcmp(data->test_method, "test_dummy") == 0) {
		if ((ret = rrr_event_function_periodic_set (
				INSTANCE_D_EVENTS_H(thread_data),
				50 * 1000, // 50 ms
				test_dummy_periodic
		)) != 0) {
			goto out;
		}
	}
	else if (strcmp(data->test_method, "test_array") == 0) {
		if ((ret = test_array (
				&data->test_data
		)) != 0) {
			goto out;
		}
	}
	else if (strcmp(data->test_method, "test_averager") == 0) {
		if ((ret = test_averager (
				&data->test_data
		)) != 0) {
			goto out;
		}
	}
	else if (strcmp(data->test_method, "test_anything") == 0) {
		if ((ret = test_anything (
				&data->test_data
		)) != 0) {
			goto out;
		}
	}
	else if (strcmp(data->test_method, "test_mysql") == 0) {
#ifdef RRR_ENABLE_DB_TESTING
		if ((ret = test_type_array_mysql (
				&data->test_data
		)) != 0) {
			goto out;
		}
#else
		TEST_MSG("MySQL test not enabled in configuration with --enable-database-testing\n");

		if ((ret = rrr_event_function_periodic_set (
				INSTANCE_D_EVENTS_H(thread_data),
				50 * 1000, // 50 ms
				test_dummy_periodic
		)) != 0) {
			goto out;
		}
#endif
	}
	else {
		RRR_MSG_0("Unknown test type '%s' in test module\n", data->test_method);
		ret = 1;
		goto out_error;
	}

	goto out;
	out_error:
		data_cleanup(data);
	out:
		RRR_DBG_1 ("Thread configuration test instance %s initialization complete\n",
			INSTANCE_D_MODULE_NAME(thread_data));
		return ret;
}

void test_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct test_module_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	if (data->test_data.cleanup != NULL) {
		data->test_data.cleanup(data->test_data.cleanup_arg);
	}

	if (test_module_result_get() == 2) {
		__test_module_result_set(0);
	}
	else {
		__test_module_result_set(1);
	}

	if (data->exit_delay_ms > 0) {
		TEST_MSG("Exit delay configured, %" PRIrrrbl " ms\n", data->exit_delay_ms);
		rrr_posix_usleep(rrr_size_from_biglength_bug_const(data->exit_delay_ms * 1000));
	}

	data_cleanup(data);

	rrr_event_receiver_reset(INSTANCE_D_EVENTS_H(thread_data));

	*deinit_complete = 1;

	RRR_DBG_1 ("Thread configuration test instance %s exiting\n",
		INSTANCE_D_MODULE_NAME(thread_data));
}

static const char *module_name = "test_module";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_DEADEND;
	data->init = test_init;
	data->deinit = test_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy configuration test module\n");
}
