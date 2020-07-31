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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"

#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/buffer.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"

struct duplicator_data {
	struct rrr_instance_thread_data *thread_data;
};

void data_cleanup(void *arg) {
	struct duplicator_data *data = arg;
	(void)(data);
}

int data_init(struct duplicator_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;

	data->thread_data = thread_data;

	return ret;
}

static int duplicator_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_thread_data *thread_data = arg;
	struct duplicator_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_message *message = entry->message;

	RRR_DBG_3("duplicator instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	int ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			entry
	);

	rrr_message_holder_unlock(entry);
	return ret;
}

static void *thread_entry_duplicator (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct duplicator_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in duplicator instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("duplicator thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders (thread_data->poll, thread_data);

	RRR_DBG_1 ("duplicator instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	// NOTE : The duplicating is handled by the message broker. See our preload() function.

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		if (rrr_poll_do_poll_delete (thread_data, thread_data->poll, duplicator_poll_callback, 50) != 0) {
			RRR_MSG_ERR("Error while polling in duplicator instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}
	}

	RRR_DBG_1 ("Thread duplicator %p exiting\n", thread_data->thread);

//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static int duplicator_preload (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;

	int ret = 0;

	int slots = rrr_instance_count_receivers_of_self(thread_data);

	RRR_DBG_1("Duplicator instance %s detected %i readers\n",
			INSTANCE_D_NAME(thread_data), slots);

	if (slots == 0) {
		RRR_MSG_0("Warning: 0 readers found for duplicator instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}

	if ((ret = rrr_message_broker_setup_split_output_buffer (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			slots
	)) != 0) {
		RRR_MSG_0("Could not setup split buffer in duplicator instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}

static struct rrr_module_operations module_operations = {
		duplicator_preload,
		thread_entry_duplicator,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "duplicator";

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
	RRR_DBG_1 ("Destroy duplicator module\n");
}

