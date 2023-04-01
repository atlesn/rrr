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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/array.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/event/event_collection.h"
#include "../lib/event/event_collection_struct.h"

#define DUMMY_DEFAULT_SLEEP_INTERVAL_US 50 * 1000

struct dummy_data {
	struct rrr_instance_runtime_data *thread_data;

	int no_generation;
	int no_sleeping;
	int no_ratelimit;
	rrr_setting_uint max_generated;
	rrr_setting_uint random_payload_max_size;
	rrr_setting_uint sleep_interval_us;

	char *topic;
	uint16_t topic_len; // Optimization, don't calculate length for every message

	char *array_tag;
	struct rrr_array array_template;

	struct rrr_event_collection events;
	rrr_event_handle event_write_entry;

	unsigned int generated_count;
	unsigned int generated_count_to_stats;
	rrr_setting_uint generated_count_total;

	uint64_t next_periodic_time;
};

static int dummy_inject (RRR_MODULE_INJECT_SIGNATURE) {
	RRR_DBG_2("dummy instance %s: writing data from inject function\n",
			INSTANCE_D_NAME(thread_data));

	int ret = 0;

	if (rrr_message_broker_clone_and_write_entry (
			INSTANCE_D_BROKER_ARGS(thread_data),
			message,
			NULL
	) != 0) {
		RRR_MSG_0("Could not inject message in dummy instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	rrr_msg_holder_unlock(message);
	return ret;
}

static int dummy_data_init(struct dummy_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;
	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(data->thread_data));

	return 0;
}

static void dummy_data_cleanup(void *arg) {
	struct dummy_data *data = (struct dummy_data *) arg;
	RRR_FREE_IF_NOT_NULL(data->topic);
	RRR_FREE_IF_NOT_NULL(data->array_tag);
	rrr_array_clear(&data->array_template);
	rrr_event_collection_clear(&data->events);
}

static int dummy_parse_config (struct dummy_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("dummy_no_generation", no_generation, 1);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("dummy_no_sleeping", no_sleeping, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("dummy_no_ratelimit", no_ratelimit, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("dummy_max_generated", max_generated, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("dummy_random_payload_max_size", random_payload_max_size, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("dummy_sleep_interval_us", sleep_interval_us, DUMMY_DEFAULT_SLEEP_INTERVAL_US);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("dummy_array_tag", array_tag);

	if ((rrr_biglength) data->random_payload_max_size > UINT32_MAX) { // Note : UINT32 (unsigned)
		RRR_MSG_0("Parameter 'dummy_random_payload_max_size' exceeds maximum of %" PRIu32 "in dummy instance %s\n",
			(uint32_t) UINT32_MAX,
			config->name
		);
		ret = 1;
		goto out;
	}

	if ((rrr_biglength) data->sleep_interval_us > INT_MAX) {
		RRR_MSG_0("Parameter 'dummy_sleep_interval_us' exceeds maximum of %i in dummy instance %s\n",
			INT_MAX,
			config->name
		);
		ret = 1;
		goto out;
	}

	if (data->sleep_interval_us == 0) {
		RRR_MSG_0("Parameter dummy_sleep_interval_us was out of range in dummy instance %s, must be > 0\n",
				config->name);
		ret = 1;
		goto out;
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("dummy_no_sleeping") && RRR_INSTANCE_CONFIG_EXISTS("dummy_sleep_interval_us")) {
		RRR_MSG_0("Parameters dummy_sleep_interval_us and dummy_no_sleeping was both set in dummy instance %s, this is an invalid confiuguration.\n",
				config->name);
		ret = 1;
		goto out;
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("dummy_random_payload_size_max") && RRR_INSTANCE_CONFIG_EXISTS("dummy_array_tag")) {
		RRR_MSG_0("Parameters dummy_random_payload_size_max and dummy_array_tag was both set in dummy instance %s, this is an invalid confiuguration.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("dummy_topic", topic, topic_len);

	out:
	return ret;
}

struct dummy_write_message_callback_data {
	struct dummy_data *data;
	int count;
};

static int dummy_write_message_callback (struct rrr_msg_holder *entry, void *arg) {
	struct dummy_write_message_callback_data *callback_data = arg;
	struct dummy_data *data = callback_data->data;

	int ret = 0;

	struct rrr_msg_msg *reading = NULL;

	uint64_t time = rrr_time_get_64();

	if (RRR_LL_COUNT(&data->array_template) > 0) {
		if ((ret = rrr_array_new_message_from_array(
			&reading,
			&data->array_template,
			rrr_time_get_64(),
			data->topic,
			(rrr_u16) data->topic_len
		)) != 0) {
			goto out;
		}
	}
	else {
		rrr_biglength payload_size = 0;
		if (data->random_payload_max_size > 0) {
			if ((payload_size = ((rrr_biglength) rrr_rand()) % data->random_payload_max_size) > UINT32_MAX) {
				RRR_BUG("BUG: Payload size exceeds maximum in dummy_write_message_callback, config parses should check for this\n");
			}
		}

		if ((ret = rrr_msg_msg_new_empty (
				&reading,
				MSG_TYPE_MSG,
				MSG_CLASS_DATA,
				time,
				(rrr_u16) data->topic_len,
				(rrr_u32) payload_size
		)) != 0) {
			goto out;
		}

		if (data->topic != NULL && *(data->topic) != '\0') {
			memcpy(MSG_TOPIC_PTR(reading), data->topic, data->topic_len);
		}
	}

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	data->generated_count++;
	data->generated_count_total++;
	data->generated_count_to_stats++;

	out:
	rrr_msg_holder_unlock(entry);
	return (ret != 0 ? ret : (--(callback_data->count) > 0 ? RRR_MESSAGE_BROKER_AGAIN : 0));
}

static int dummy_periodic (
		struct dummy_data *data
) {
	RRR_DBG_1("dummy instance %s messages per second %i total %" PRIrrrbl " of %" PRIrrrbl "\n",
			INSTANCE_D_NAME(data->thread_data), data->generated_count, data->generated_count_total, data->max_generated);
	data->generated_count = 0;

	rrr_stats_instance_update_rate (INSTANCE_D_STATS(data->thread_data), 0, "generated", data->generated_count_to_stats);
	data->generated_count_to_stats = 0;

	data->next_periodic_time = rrr_time_get_64() + 1 * 1000 * 1000;
	
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data));
}

struct dummy_check_cancel_callback_data {
	struct dummy_data *data;
	int check_cancel_count;
};

static int dummy_check_cancel (void *arg) {
	struct dummy_check_cancel_callback_data *callback_data = arg;
	struct dummy_data *data = callback_data->data;

	if (callback_data->check_cancel_count++ != 0) {
		sched_yield();
	}

	if (rrr_time_get_64() > data->next_periodic_time) {
		return dummy_periodic(data);
	}

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data));
}

static int dummy_check_complete (
		struct dummy_data *data
) {
	return (data->max_generated != 0 && data->generated_count_total >= data->max_generated);
}

static int dummy_write_entry (
		struct dummy_data *data,
		int count
) {
	int ret = 0;

	if (data->max_generated != 0 && count > (int) (data->max_generated - data->generated_count_total)) {
		count = (int) (data->max_generated - data->generated_count_total);
	}

	struct dummy_write_message_callback_data callback_data = {
		data,
		count
	};

	struct dummy_check_cancel_callback_data cancel_callback_data = {
		data,
		0
	};

	if ((ret = rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data))) != 0) {
		goto out;
	}

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			dummy_write_message_callback,
			&callback_data,
			dummy_check_cancel,
			&cancel_callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void dummy_event_write_entry (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct dummy_data *data = thread_data->private_data;

	(void)(fd);
	(void)(flags);

	if (dummy_write_entry (data, 1) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}

	if (dummy_check_complete(data)) {
		EVENT_REMOVE(data->event_write_entry);
	}
}

static int dummy_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct dummy_data *data = thread_data->private_data;

	return dummy_periodic(data);
}

static void *thread_entry_dummy (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct dummy_data *data = thread_data->private_data = thread_data->private_memory;

	if (dummy_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in dummy instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("Dummy thread data is %p\n", thread_data);

	pthread_cleanup_push(dummy_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (dummy_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// If we are not sleeping we need to enable automatic rate limiting on our output buffer
	if (data->no_sleeping == 1) {
		if (data->no_ratelimit) {
			RRR_DBG_1("dummy instance %s both sleeping and ratelimit disabled\n", INSTANCE_D_NAME(thread_data));
		}
		else {
			RRR_DBG_1("dummy instance %s enabling ratelimit on output buffer as sleeping is disabled\n", INSTANCE_D_NAME(thread_data));
			rrr_message_broker_set_ratelimit(INSTANCE_D_BROKER_ARGS(thread_data), 1);
		}
	}

	if (data->array_tag != NULL && *(data->array_tag) != '\0') {
		if (rrr_array_push_value_vain_with_tag(&data->array_template, data->array_tag) != 0) {
			RRR_MSG_0("Failed to push vain value to template array in dummy instance %s\n",
				INSTANCE_D_NAME(thread_data));
			goto out_cleanup;
		}
	}

	if (data->no_generation) {
		goto dispatch;
	}

	if (!data->no_sleeping && data->sleep_interval_us >= DUMMY_DEFAULT_SLEEP_INTERVAL_US) {
		// Event operation
		if (rrr_event_collection_push_periodic (
				&data->event_write_entry,
				&data->events,
				dummy_event_write_entry,
				thread,
				data->sleep_interval_us
		) != 0) {
			RRR_MSG_0("Failed to create write event in dummy instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_cleanup;
		}

		EVENT_ADD(data->event_write_entry);
		EVENT_ACTIVATE(data->event_write_entry);

		goto dispatch;
	}

	// Busy-loop operation
	const int count = (data->no_sleeping ? 50 : 1);
	int count_extra = 0;
	while (1) {
		const uint64_t time_now = rrr_time_get_64();

		// Check cancel callback will run the periodic function

		if (dummy_write_entry(data, count + count_extra) != 0) {
			break;
		}

		if (!data->no_sleeping) {
			rrr_posix_usleep(data->sleep_interval_us);
			count_extra = (int) ((rrr_time_get_64() - time_now) / data->sleep_interval_us);
		}

		if (dummy_check_complete(data)) {
			// Run the next periodic function at the correct time before going to dispatch
			rrr_posix_usleep(data->next_periodic_time - rrr_time_get_64());
			if (dummy_periodic(data) != 0) {
				break;
			}
			goto dispatch;
		}
	}

	goto out_cleanup;
	dispatch:
		rrr_event_dispatch (
				INSTANCE_D_EVENTS(thread_data),
				1 * 1000 * 1000,
				dummy_event_periodic,
				thread
		);

	out_cleanup:
		RRR_DBG_1 ("Thready dummy instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
		pthread_cleanup_pop(1);
		pthread_exit(0);
}

static int dummy_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;

	(void)(thread);
	(void)(amount);

	RRR_BUG("BUG: dummy_event_broker_data_available called in dummy module\n");

	return 0;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_dummy,
	dummy_inject,
	NULL
};

struct rrr_instance_event_functions event_functions = {
	dummy_event_broker_data_available
};

static const char *module_name = "dummy";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_SOURCE;
	data->operations = module_operations;
	data->private_data = NULL;
	data->event_functions = event_functions;
}

void unload(void) {
}


