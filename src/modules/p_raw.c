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

#include "../lib/ip.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/stats_instance.h"
#include "../lib/array.h"
#include "../global.h"

struct raw_data {
	int message_count;
	int print_data;
};

int poll_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->private_data;
	struct raw_data *raw_data = thread_data->private_data;
	struct rrr_message *reading = NULL;
	struct rrr_array array_tmp = {0};

	int ret = 0;

	if (poll_data->flags & RRR_POLL_POLL_DELETE_IP) {
		struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;
		reading = entry->message;
		entry->message = NULL;
		rrr_ip_buffer_entry_destroy(entry);
	}
	else {
		reading = (struct rrr_message *) data;
	}

	RRR_DBG_3 ("Raw %s: Result from buffer: poll flags %u length %u timestamp from %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), poll_data->flags, MSG_TOTAL_SIZE(reading), reading->timestamp_from, reading->data_numeric, size);

	if (raw_data->print_data != 0) {
		ssize_t print_length = MSG_DATA_LENGTH(reading);
		if (print_length > 100) {
			print_length = 100;
		}
		char buf[print_length + 1];
		memcpy(buf, MSG_DATA_PTR(reading), print_length);
		buf[print_length] = '\0';

		RRR_MSG("Raw %s: Received data with timestamp %" PRIu64 ": %s\n",
				INSTANCE_D_NAME(thread_data), reading->timestamp_from, buf);

		if (MSG_IS_ARRAY(reading)) {
			if (rrr_array_message_to_collection(&array_tmp, reading) != 0) {
				RRR_MSG_ERR("Could not get array from message in poll_callback of raw instance %s\n",
						INSTANCE_D_NAME(thread_data));
				ret = 1;
				goto out;
			}
			if (rrr_array_dump(&array_tmp) != 0) {
				RRR_MSG_ERR("Error while dumping array in poll_callback of raw instance %s\n",
						INSTANCE_D_NAME(thread_data));
				ret = 1;
				goto out;
			}
		}
	}

	raw_data->message_count++;

	out:
	rrr_array_clear(&array_tmp);
	free(reading);
	return ret;
}

void data_init(struct raw_data *data) {
	memset (data, '\0', sizeof(*data));
}

int parse_config (struct raw_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	int yesno = 0;

	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "raw_print_data")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0; // Default to no
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Error while parsing raw_print_data setting of instance %s\n", config->name);
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
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct raw_data *raw_data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	data_init(raw_data);

	RRR_DBG_1 ("Raw thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(raw_data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Error while parsing configuration for raw instance %s\n",
				INSTANCE_D_NAME(thread_data));
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(
			&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_POLL_DELETE_IP
	) != 0) {
		RRR_MSG_ERR("Raw requires poll_delete or poll_delete_ip from senders\n");
		goto out_message;
	}

	RRR_DBG_1 ("Raw started thread %p\n", thread_data);

	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	uint64_t total_counter = 0;
	uint64_t timer_start = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_combined_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		uint64_t timer_now = rrr_time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			total_counter += raw_data->message_count;

			RRR_DBG_1("Raw instance %s messages per second %i total %" PRIu64 "\n",
					INSTANCE_D_NAME(thread_data), raw_data->message_count, total_counter);

			rrr_stats_instance_update_rate (stats, 0, "received", raw_data->message_count);

			raw_data->message_count = 0;
		}
	}

	out_message:
	RRR_DBG_1 ("Thread raw %p instance %s exiting 1 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread raw %p instance %s exiting 2 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_raw,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "raw";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy raw module\n");
}

