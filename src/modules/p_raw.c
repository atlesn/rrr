/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/threads.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/array.h"

struct raw_data {
	int message_count;
	int print_data;
};

int raw_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct raw_data *raw_data = thread_data->private_data;
	struct rrr_array array_tmp = {0};
	char *topic_tmp = NULL;

	int ret = 0;

	struct rrr_msg_msg *reading = entry->message;

	RRR_DBG_3 ("Raw %s: Result from buffer: length %u timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), MSG_TOTAL_SIZE(reading), reading->timestamp);

	if (raw_data->print_data != 0) {
		// Use high debuglevel to force suppression of messages in journal module

		if (rrr_msg_msg_topic_get(&topic_tmp, reading) != 0 ) {
			RRR_MSG_0("Error while getting topic from message in raw_poll_callback\n");
			ret = 1;
			goto out;
		}

		RRR_DBG_2("Raw %s: Received data of size %lu with timestamp %" PRIu64 " topic '%s'\n",
				INSTANCE_D_NAME(thread_data), MSG_DATA_LENGTH(reading), reading->timestamp, topic_tmp);

		if (MSG_IS_ARRAY(reading)) {
			if (rrr_array_message_append_to_collection(&array_tmp, reading) != 0) {
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

	raw_data->message_count++;

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_array_clear(&array_tmp);
	rrr_msg_holder_unlock(entry);
	return ret;
}

void data_init(struct raw_data *data) {
	memset (data, '\0', sizeof(*data));
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

	/* On error, memory is freed by data_cleanup */

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

	uint64_t total_counter = 0;
	uint64_t timer_start = rrr_time_get_64();
	int ticks = 0;
	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		rrr_thread_watchdog_time_update(thread);

		int prev_message_count = raw_data->message_count;
		if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, raw_poll_callback, 0) != 0) {
			RRR_MSG_0("Error while polling in raw instance %s\n",
				INSTANCE_D_NAME(thread_data));
			break;
		}

		if (prev_message_count == raw_data->message_count) {
			rrr_posix_usleep(50000); // 50 ms
		}

		uint64_t timer_now = rrr_time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			total_counter += raw_data->message_count;

			RRR_DBG_1("Raw instance %s messages per second %i total %" PRIu64 "\n",
					INSTANCE_D_NAME(thread_data), raw_data->message_count, total_counter);

			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 0, "received", raw_data->message_count);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 1, "ticks", ticks);

			raw_data->message_count = 0;
			ticks = 0;
		}

		ticks++;
	}

	RRR_DBG_1 ("Thread raw %p instance %s exiting state is %i\n",
			thread, INSTANCE_D_NAME(thread_data), rrr_thread_state_get(thread));

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_raw,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "raw";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy raw module\n");
}

