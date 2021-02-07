/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"

struct dummy_data {
	int no_generation;
	int no_sleeping;
	rrr_setting_uint max_generated;
	rrr_setting_uint random_payload_max_size;

	char *topic;
	size_t topic_len; // Optimization, don't calculate length for every message
};

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	RRR_DBG_2("dummy instance %s: writing data from inject function\n",
			INSTANCE_D_NAME(thread_data));

	int ret = 0;

	// This will unlock the entry
	if (rrr_message_broker_clone_and_write_entry (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			message
	) != 0) {
		RRR_MSG_0("Could not inject message in dummy instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int data_init(struct dummy_data *data) {
	memset(data, '\0', sizeof(*data));
	return 0;
}

void data_cleanup(void *arg) {
	struct dummy_data *data = (struct dummy_data *) arg;
	RRR_FREE_IF_NOT_NULL(data->topic);
}

int parse_config (struct dummy_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("dummy_no_generation", no_generation, 1);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("dummy_no_sleeping", no_sleeping, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("dummy_max_generated", max_generated, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("dummy_random_payload_max_size", random_payload_max_size, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("dummy_topic", topic);

	if (data->topic != NULL) {
		data->topic_len = strlen(data->topic);
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static int dummy_write_message_callback (struct rrr_msg_holder *entry, void *arg) {
	struct dummy_data *data = arg;

	int ret = 0;

	struct rrr_msg_msg *reading = NULL;

	uint64_t time = rrr_time_get_64();

	size_t payload_size = 0;
	if (data->random_payload_max_size > 0) {
		payload_size = ((size_t) rrr_rand()) % data->random_payload_max_size;
	}

	if (rrr_msg_msg_new_empty (
			&reading,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			time,
			data->topic_len,
			payload_size
	) != 0) {
		ret = 1;
		goto out;
	}

	if (data->topic != NULL && *(data->topic) != '\0') {
		memcpy(MSG_TOPIC_PTR(reading), data->topic, data->topic_len);
	}

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static void *thread_entry_dummy (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct dummy_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data) != 0) {
		RRR_MSG_0("Could not initialize data in dummy instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("Dummy thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// If we are not sleeping we need to enable automatic rate limiting on our output buffer
	if (data->no_sleeping == 1) {
		RRR_DBG_1("dummy instance %s enabling rate limit on output buffer\n", INSTANCE_D_NAME(thread_data));
		rrr_message_broker_set_ratelimit(INSTANCE_D_BROKER(thread_data), INSTANCE_D_HANDLE(thread_data), 1);
	}

	uint64_t time_start = rrr_time_get_64();
	int generated_count = 0;
	int generated_count_to_stats = 0;
	rrr_setting_uint generated_count_total = 0;
	while (!rrr_thread_signal_encourage_stop_check(thread)) {
		rrr_thread_watchdog_time_update(thread);

		if (data->no_generation == 0 && (data->max_generated == 0 || generated_count_total < data->max_generated)) {
			if (rrr_message_broker_write_entry (
					INSTANCE_D_BROKER(thread_data),
					INSTANCE_D_HANDLE(thread_data),
					NULL,
					0,
					0,
					dummy_write_message_callback,
					data,
					INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
			)) {
				RRR_MSG_0("Could not create new message in dummy instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}

			generated_count++;
			generated_count_total++;
			generated_count_to_stats++;
		}

		uint64_t time_now = rrr_time_get_64();

		if (time_now - time_start > 1000000) {
			RRR_DBG_1("dummy instance %s messages per second %i total %" PRIrrrbl " of %" PRIrrrbl "\n",
					INSTANCE_D_NAME(thread_data), generated_count, generated_count_total, data->max_generated);
			generated_count = 0;
			time_start = time_now;

			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 0, "generated", generated_count_to_stats);
			generated_count_to_stats = 0;
		}

		if (data->no_sleeping == 0 || (data->max_generated > 0 && generated_count_total >= data->max_generated)) {
			rrr_posix_usleep (50000); // 50 ms
		}
	}

	out_cleanup:
	RRR_DBG_1 ("Thready dummy instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_dummy,
	NULL,
	inject,
	NULL
};

static const char *module_name = "dummy";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}


