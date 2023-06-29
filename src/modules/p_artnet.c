/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "../lib/artnet/rrr_artnet.h"

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"

struct artnet_data {
	struct rrr_instance_runtime_data *thread_data;
	rrr_setting_uint message_ttl_seconds;
	struct rrr_poll_helper_counters counters;
	struct rrr_artnet_node *node;
};

static int artnet_data_init(struct artnet_data *data, struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	if ((ret = rrr_artnet_node_new(&data->node)) != 0) {
		RRR_MSG_0("Failed to create artnet node in artnet instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out;
	}

	data->thread_data = thread_data;

	out:
	return ret;
}

static void artnet_data_cleanup(void *arg) {
	struct artnet_data *data = arg;

	if (data->node != NULL) {
		rrr_artnet_node_destroy(data->node);
	}
}

static int artnet_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct artnet_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	RRR_DBG_3("artnet instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	);

	RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(data);

	rrr_msg_holder_unlock(entry);
	return ret;
}

static int artnet_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data);

	return rrr_poll_do_poll_delete (amount, thread_data, artnet_poll_callback);
}

static int artnet_parse_config (struct artnet_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	out:
	return ret;
}

static void *thread_entry_artnet (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data = thread_data->private_memory;
	RRR_DBG_1 ("artnet thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (artnet_data_init(data, thread_data) != 0) {
		goto out_message;
	}

	pthread_cleanup_push(artnet_data_cleanup, data);

	if (artnet_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("artnet instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_cleanup:
	pthread_cleanup_pop(1);
	out_message:
	RRR_DBG_1 ("Thread artnet %p exiting\n", thread);

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_artnet,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	artnet_event_broker_data_available
};

static const char *module_name = "artnet";

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
	RRR_DBG_1 ("Destroy artnet module\n");
}

