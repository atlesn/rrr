/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include "../lib/instance_config.hpp"
#include "../lib/event/event_collection.hpp"

#include <string>

extern "C" {

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
#include "../lib/instance_friends.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/event/event.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/msgdb/msgdb_client.hpp"

#define RRR_OCR_DEFAULT_INPUT_TAG "ocr_input_data"

struct ocr_data {
	struct rrr_instance_runtime_data *thread_data;

	rrr::event::collection events;
	rrr::msgdb::client msgdb_conn;

	std::string msgdb_socket;
	std::string input_data_tag;

	ocr_data(struct rrr_instance_runtime_data *thread_data) :
		thread_data(thread_data),
		events(INSTANCE_D_EVENTS(thread_data)),
		msgdb_conn(),
		msgdb_socket(""),
		input_data_tag("")
	{}
};

static void ocr_data_cleanup(void *arg) {
	struct ocr_data *data = reinterpret_cast<struct ocr_data *>(arg);
	delete data;
}

static int ocr_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(arg);
	struct ocr_data *data = reinterpret_cast<struct ocr_data *>(thread_data->private_data);

	int ret = 0;

	goto out;

	// We check stuff with the watchdog in case we are slow to process messages
/*
	if (rrr_thread_signal_encourage_stop_check(INSTANCE_D_THREAD(data->thread_data))) {
		ret = RRR_FIFO_PROTECTED_SEARCH_STOP;
		goto out;
	}
	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	// Do not produce errors for message process failures, just drop them


	const struct rrr_instance_friend_collection *forward_to = NULL;
	if (ocr_process(&forward_to, data, entry) != 0) {
		RRR_MSG_0("Warning: Failed to process message in ocr instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}*/

/*	if (forward_to != NULL && (ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data), 
			entry,
			forward_to,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Failed to write entry in ocr_poll_callback of instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}*/

	out:
		rrr_msg_holder_unlock(entry);
		return ret;
}

static int ocr_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = reinterpret_cast<struct rrr_thread *>(arg);
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(thread->private_data);

	return rrr_poll_do_poll_delete (amount, thread_data, ocr_poll_callback);
}

static int ocr_event_periodic (void *arg) {
	struct rrr_thread *thread = reinterpret_cast<struct rrr_thread *>(arg);
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

static int ocr_parse_config (struct ocr_data *data, struct rrr_instance_config_data *config) {
	using namespace rrr::instance_config::parse;

	try {
		utf8_optional(data->input_data_tag, config, "ocr_input_data_tag", "");
		utf8_optional(data->msgdb_socket, config, "ocr_msgdb_socket", "");
	}
	catch (parse_error e) {
		RRR_MSG_0("Configuration parsing failed for ocr instance %s: %s\n", config->name, e.what());
		return 1;
	}

	return 0;
}

static void *thread_entry_ocr (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(thread->private_data);
	struct ocr_data *data = new ocr_data(thread_data);
	thread_data->private_data = data;

	RRR_DBG_1 ("ocr thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(ocr_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (ocr_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("ocr instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 s
			ocr_event_periodic,
			thread
	);

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread ocr %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_ocr,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "ocr";

__attribute__((constructor)) void load(void) {
}

static struct rrr_instance_event_functions event_functions = {
	ocr_event_broker_data_available
};

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ocr module\n");
}

} /* extern "C" */
