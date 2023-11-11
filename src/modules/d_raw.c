/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/array.h"

struct raw_data {
	int print_data;
	long double total_message_age_us;
	struct rrr_poll_helper_counters counters;
	uint64_t start_time;
};

int raw_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct raw_data *raw_data = thread_data->private_data;
	struct rrr_array array_tmp = {0};
	char *topic_tmp = NULL;

	int ret = 0;

	struct rrr_msg_msg *reading = entry->message;

	long double message_age = (long double) (rrr_time_get_64() - reading->timestamp);

	RRR_DBG_3 ("Raw %s: Result from buffer: length %u timestamp %" PRIu64 " age %Lg ms\n",
			INSTANCE_D_NAME(thread_data), MSG_TOTAL_SIZE(reading), reading->timestamp, message_age / 1000.0);

	if (raw_data->print_data != 0) {
		// Use high debuglevel to force suppression of messages in journal module

		if (rrr_msg_msg_topic_get(&topic_tmp, reading) != 0 ) {
			RRR_MSG_0("Error while getting topic from message in raw_poll_callback\n");
			ret = 1;
			goto out;
		}

		RRR_DBG_2("Raw %s: Received message of size %llu with timestamp %" PRIu64 " topic '%s' age %Lg ms\n",
				INSTANCE_D_NAME(thread_data), (long long unsigned) MSG_TOTAL_SIZE(reading), reading->timestamp, topic_tmp, message_age / 1000.0);

		if (MSG_IS_ARRAY(reading)) {
			uint16_t array_version_dummy;
			if (rrr_array_message_append_to_array(&array_version_dummy, &array_tmp, reading) != 0) {
				RRR_MSG_0("Could not get array from message in raw_poll_callback of raw instance %s\n",
						INSTANCE_D_NAME(thread_data));
				ret = 1;
				goto out;
			}
			if (rrr_array_dump(&array_tmp) != 0) {
				RRR_MSG_0("Error while dumping array in raw_poll_callback of raw instance %s\n",
						INSTANCE_D_NAME(thread_data));
				ret = 1;
				goto out;
			}
		}
	}

	raw_data->total_message_age_us += message_age;

	RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(raw_data);

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_array_clear(&array_tmp);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int raw_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raw_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data);

	return rrr_poll_do_poll_delete (amount, thread_data, raw_poll_callback);
}

static int raw_event_periodic (void *arg) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raw_data *raw_data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_PERIODIC(message_count, raw_data);

	double per_sec_average = ((double) raw_data->counters.total_message_count) / ((double) (rrr_time_get_64() - raw_data->start_time) / 1000000);

	RRR_DBG_1("Raw instance %s messages per second %" PRIu64 " average %.2f total %" PRIu64 " average age %Lg ms\n",
			INSTANCE_D_NAME(thread_data),
			message_count,
			per_sec_average,
			raw_data->counters.total_message_count,
			(raw_data->total_message_age_us/(long double) raw_data->counters.total_message_count/1000.0)
	);

	rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 0, "received", message_count);

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

void data_init(struct raw_data *data) {
	memset (data, '\0', sizeof(*data));
	data->start_time = rrr_time_get_64();
}

int parse_config (struct raw_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;
	int yesno = 0;

	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "raw_print_data")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0; // Default to no
			ret = 0;
		}
		else {
			RRR_MSG_0("Error while parsing raw_print_data setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->print_data = yesno;

	out:
	return ret;
}

static void *thread_entry_raw (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raw_data *raw_data = thread_data->private_data = thread_data->private_memory;

	data_init(raw_data);

	RRR_DBG_1 ("Raw thread data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(raw_data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Error while parsing configuration for raw instance %s\n",
				INSTANCE_D_NAME(thread_data));
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("Raw started thread %p\n", thread_data);

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			raw_event_periodic,
			thread
	);

	RRR_DBG_1 ("Thread raw %p instance %s exiting\n",
			thread, INSTANCE_D_NAME(thread_data));

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_raw,
		NULL
};

static struct rrr_instance_event_functions event_functions = {
	raw_event_broker_data_available
};

static const char *module_name = "raw";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy raw module\n");
}

