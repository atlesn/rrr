/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "../lib/log.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"

#include "../lib/pg.h"

struct pg_data {
	struct rrr_instance_runtime_data *thread_data;
};

static void data_cleanup (void *arg) {
	struct pg_data *data = arg;
	(void)(data);
}

static int data_init (
		struct pg_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	memset (data, 0, sizeof (*data));
	data->thread_data = thread_data;

	return ret;
}

static int pg_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct pg_data *data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	(void)(message);

	RRR_BUG("pg_poll_callback called but not implemented");

	rrr_msg_holder_unlock(entry);

	return 0;
}

static int pg_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct pg_data *data = thread_data->private_data;

	int ret = rrr_poll_do_poll_delete (amount, thread_data, pg_poll_callback);

	RRR_BUG("Run events here");

	return ret;
}

static void pg_pause_check (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct rrr_instance_runtime_data *thread_data = callback_arg;
	struct pg_data *data = thread_data->private_data;

	(void)(is_paused);

	RRR_BUG("pg_pause_check called but not implemented");
}

static int parse_config (
		struct pg_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	RRR_BUG("parse_config not implemented");

	return ret;
}

static void *thread_entry_pg (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct pg_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in pg instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("pg thread data is %p, size of private data: %llu\n", thread_data, (long long unsigned) sizeof(*data));

	pthread_cleanup_push(data_cleanup, data);

	RRR_BUG("thread_entry_pg not implemented");

	if (parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(INSTANCE_D_CONFIG(thread_data));

	RRR_DBG_1("pg started thread %p\n", thread);

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			pg_pause_check,
			thread_data
	);

	RRR_BUG("Push periodic poll event here");

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 second
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	RRR_DBG_1("Thread pg %p exiting\n", thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_pg,
		NULL
};

static const char *module_name = "pg";

struct rrr_instance_event_functions event_functions = {
	pg_event_broker_data_available
};

__attribute__((constructor)) void load(void) {
	// Nothing to do
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy pg module\n");
	// Nothing to do
}
