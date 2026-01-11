/*

Read Route Record

Copyright (C) 2026 Atle Solbakken atle@goliathdns.no

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

#include "../lib/gpio/rrr_gpio.h"

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/event/event.h"
#include "../lib/array.h"

#define GPIO_TAG_LINE "gpio_line"
#define GPIO_TAG_SET "gpio_set"

struct gpio_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_poll_helper_counters counters;
	char *chip;
	struct rrr_gpio_ctx *ctx;
};

int gpio_data_init(struct gpio_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

void gpio_data_cleanup(void *arg) {
	struct gpio_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->chip);
	rrr_gpio_ctx_destroy(&data->ctx);
}

static int gpio_process_cmd (
		struct gpio_data *data,
		const struct rrr_array *array
) {
	unsigned long long line = 0;
	char *value_str = NULL;
	int value;

	int ret = 0;

	if ((ret = rrr_array_get_value_ull_by_tag (&line, array, GPIO_TAG_LINE)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " GPIO_TAG_LINE " in message to gpio instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	if ((ret = rrr_array_get_value_str_by_tag (&value_str, array, GPIO_TAG_SET)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " GPIO_TAG_SET " in message to gpio instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	if (strcmp(value_str, "on") == 0) {
		value = 1;
	}
	else if (strcmp(value_str, "off") == 0) {
		value = 0;
	}
	else {
		RRR_MSG_0("Warning: Unknown value '%s' for " GPIO_TAG_SET " in message to gpio instance %s\n",
			value_str, INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	RRR_DBG_3("gpio instance %s received command to set value of line '%llu' to '%s'\n",
			INSTANCE_D_NAME(data->thread_data),
			line,
			value_str
	);

	if ((ret = rrr_gpio_set_line(&data->ctx, data->chip, rrr_uint_from_biglength_bug_const(line), value)) != 0) {
		RRR_MSG_0("Failed to set line %luu on device %s to %s in gpio instance %s\n",
			line, data->chip, value_str, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(value_str);
	return ret;
}

static int gpio_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct gpio_data *data = thread_data->private_data;

	const struct rrr_msg_msg *message = entry->message;
	struct rrr_array array_tmp = {0};

	int ret = 0;

	if (!MSG_IS_ARRAY(message)) {
		RRR_MSG_0("Warning: gpio instance %s received a message which was not an array message. Dropping it.\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	uint16_t array_version;
	if ((ret = rrr_array_message_append_to_array (
			&array_version,
			&array_tmp,
			message
	)) != 0) {
		RRR_MSG_0("Failed to get array from message in gpio instance %s.\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_DBG_2("gpio instance %s received a message with timestamp %llu\n",
		INSTANCE_D_NAME(data->thread_data),
		(long long unsigned int) message->timestamp
	);

	if ((ret = gpio_process_cmd (data, &array_tmp)) != 0) {
		goto out;
	}

	out:
	RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(data);
	rrr_msg_holder_unlock(entry);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int gpio_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct gpio_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data);

	return rrr_poll_do_poll_delete (amount, thread_data, gpio_poll_callback);
}

static int gpio_parse_config (struct gpio_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("gpio_chip", chip);

	if (data->chip == NULL || *data->chip == '\0') {
		RRR_MSG_0("Could not find required data_chip setting for gpio instance %s\n", INSTANCE_C_DBG_NAME(config));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int gpio_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct gpio_data *data = thread_data->private_data;

	(void)(data);

	int ret = 0;

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		ret = RRR_EVENT_EXIT;
		goto out;
	}
	rrr_thread_watchdog_time_update(thread);

	out:
	return ret;
}

static void *thread_entry_gpio (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct gpio_data *data = thread_data->private_data = thread_data->private_memory;
	RRR_DBG_1 ("gpio thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (gpio_data_init(data, thread_data) != 0) {
		goto out_message;
	}

	pthread_cleanup_push(gpio_data_cleanup, data);

	if (gpio_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("gpio instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			gpio_periodic,
			thread
	);

	out_cleanup:
	pthread_cleanup_pop(1);
	out_message:
	RRR_DBG_1 ("Thread gpio %p exiting\n", thread);

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_gpio,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	gpio_event_broker_data_available
};

static const char *module_name = "gpio";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_DEADEND;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy gpio module\n");
}
