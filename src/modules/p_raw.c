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

#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../global.h"

struct raw_data {
	int message_count;
};

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->private_data;
	struct raw_data *raw_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	VL_DEBUG_MSG_2 ("Raw %s: Result from buffer: poll flags %u %s measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), poll_data->flags, reading->data, reading->data_numeric, size);

	raw_data->message_count++;

	free(data);
	return 0;
}

void data_init(struct raw_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void *thread_entry_raw(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct raw_data *raw_data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	data_init(raw_data);

	thread_data->thread = start_data->thread;

	VL_DEBUG_MSG_1 ("Raw thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(
			&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_POLL_DELETE_IP
	) != 0) {
		VL_MSG_ERR("Raw requires poll_delete or poll_delete_ip from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("Raw started thread %p\n", thread_data);

	uint64_t timer_start = time_get_64();
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_combined_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		uint64_t timer_now = time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			VL_DEBUG_MSG_1("Raw instance %s messages per second: %i\n",
					INSTANCE_D_NAME(thread_data), raw_data->message_count);

			raw_data->message_count = 0;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread raw %p instance %s exiting 1 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	VL_DEBUG_MSG_1 ("Thread raw %p instance %s exiting 2 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	VL_DEBUG_MSG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_raw,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		test_config,
		NULL
};

static const char *module_name = "raw";

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
	VL_DEBUG_MSG_1 ("Destroy raw module\n");
}

