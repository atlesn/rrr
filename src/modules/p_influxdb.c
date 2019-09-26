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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../global.h"

struct influxdb_data {
	int message_count;
	int print_data;
};

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	VL_DEBUG_MSG_2 ("InfluxDB %s: Result from buffer: poll flags %u length %u timestamp from %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), poll_data->flags, MSG_TOTAL_SIZE(reading), reading->timestamp_from, reading->data_numeric, size);

	if (influxdb_data->print_data != 0) {
		ssize_t print_length = MSG_DATA_LENGTH(reading);
		if (print_length > 100) {
			print_length = 100;
		}
		char buf[print_length + 1];
		memcpy(buf, MSG_DATA_PTR(reading), print_length);
		buf[print_length] = '\0';

		VL_MSG("InfluxDB %s: Received data with timestamp %" PRIu64 ": %s\n",
				INSTANCE_D_NAME(thread_data), reading->timestamp_from, buf);
	}

	influxdb_data->message_count++;

	free(data);
	return 0;
}

void data_init(struct influxdb_data *data) {
	memset (data, '\0', sizeof(*data));
}

int parse_config (struct influxdb_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	int yesno = 0;

	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "influxdb_print_data")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0; // Default to no
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing influxdb_print_data setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->print_data = yesno;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void *thread_entry_influxdb (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	data_init(influxdb_data);

	VL_DEBUG_MSG_1 ("InfluxDB thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(influxdb_data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Error while parsing configuration for influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(
			&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_POLL_DELETE_IP
	) != 0) {
		VL_MSG_ERR("InfluxDB requires poll_delete or poll_delete_ip from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("InfluxDB started thread %p\n", thread_data);

	uint64_t timer_start = time_get_64();
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_combined_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		uint64_t timer_now = time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			VL_DEBUG_MSG_1("InfluxDB instance %s messages per second: %i\n",
					INSTANCE_D_NAME(thread_data), influxdb_data->message_count);

			influxdb_data->message_count = 0;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread influxdb %p instance %s exiting 1 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	VL_DEBUG_MSG_1 ("Thread influxdb %p instance %s exiting 2 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	VL_DEBUG_MSG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_influxdb,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "influxdb";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy influxdb module\n");
}

