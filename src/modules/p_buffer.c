/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"

struct buffer_data {
	struct rrr_instance_runtime_data *thread_data;
	rrr_setting_uint message_ttl_seconds;
	uint64_t message_ttl_us;
	struct rrr_poll_helper_counters counters;
};

static void buffer_data_init(struct buffer_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static int buffer_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct buffer_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	if (data->message_ttl_us > 0 && !rrr_msg_msg_ttl_ok(message, data->message_ttl_us)) {
		RRR_MSG_0("Warning: Received message in buffer instance %s with expired TTL, limit is set to %" PRIrrrbl " seconds. Dropping message.\n",
				INSTANCE_D_NAME(thread_data), data->message_ttl_seconds);
		goto drop;
	}

	RRR_DBG_3("buffer instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	);

	RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(data);

	drop:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int buffer_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct buffer_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data);

	return rrr_poll_do_poll_delete (amount, thread_data, buffer_poll_callback, 0);
}

static int buffer_parse_config (struct buffer_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("buffer_ttl_seconds", message_ttl_seconds, 0);

	if (data->message_ttl_seconds > UINT32_MAX) {
		RRR_MSG_0("buffer_ttl_seconds too large in instance %s, maximum is %u\n", config->name, UINT32_MAX);
		ret = 1;
		goto out;
	}

	data->message_ttl_us = ((uint64_t) data->message_ttl_seconds) * ((uint64_t) 1000000);

	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("buffer_do_duplicate",
		RRR_MSG_0("Warning: Parameter 'buffer_do_duplicate' which is set for instance %s is deprecated. Use 'duplicate' instead, which also works on any mdoule.\n",
			config->name);
	);

	out:
	return ret;
}

static void *thread_entry_buffer (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct buffer_data *data = thread_data->private_data = thread_data->private_memory;
	RRR_DBG_1 ("buffer thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	buffer_data_init(data, thread_data);

	if (buffer_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("buffer instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	RRR_DBG_1 ("Thread buffer %p exiting\n", thread);

	pthread_exit(0);
}

static int buffer_inject (RRR_MODULE_INJECT_SIGNATURE) {
	RRR_DBG_2("buffer instance %s: writing data from inject function\n", INSTANCE_D_NAME(thread_data));

	// This will also unlock
	if (rrr_message_broker_clone_and_write_entry (
			INSTANCE_D_BROKER_ARGS(thread_data),
			message
	) != 0) {
		RRR_MSG_0("Error while injecting packet in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		return 1;
	}

	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_buffer,
		NULL,
		buffer_inject,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	buffer_event_broker_data_available
};

static const char *module_name = "buffer";

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
	RRR_DBG_1 ("Destroy buffer module\n");
}

