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
#include "../lib/poll_helper.hpp"
#include "../lib/event/event_collection.hpp"
#include "../lib/msgdb/msgdb_client.hpp"
#include "../lib/arrayxx.hpp"
#include "../lib/type.hpp"

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
#include "../lib/instances.h"
#include "../lib/instance_friends.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/message_holder/message_holder_util.h"

#define RRR_OCR_DEFAULT_INPUT_TAG "ocr_input_data"

__attribute__((constructor)) void load(void);
void init(struct rrr_instance_module_data *data);
void unload(void);

} /* extern "C" */

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

static void ocr_poll_callback (struct rrr_msg_holder *entry, struct rrr_instance_runtime_data *thread_data) {
	struct ocr_data *data = reinterpret_cast<struct ocr_data *>(thread_data->private_data);
	const struct rrr_msg_msg *msg = reinterpret_cast<struct rrr_msg_msg *>(entry->message);

	int ret = 0;

	RRR_MSG_1("Poll callback\n");

	try {
		const rrr::array::array array(msg);
		const rrr::type::data_const image = array.get_value_raw_by_tag(data->input_data_tag);
		printf("%" PRIrrrl "\n", image.l);
	}
	catch (rrr::exp::soft e) {
		RRR_MSG_0("Dropping message after soft error in ocr instance %s: %s\n", INSTANCE_D_NAME(thread_data), e.what());
	}

	rrr_msg_holder_unlock(entry);
}

static int ocr_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = reinterpret_cast<struct rrr_thread *>(arg);
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(thread->private_data);

	rrr::poll_helper::amount a(*amount);
	RRR_EXP_TO_RET(poll_delete(a, thread_data, ocr_poll_callback));

	*amount = a.a;

	return 0;
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
