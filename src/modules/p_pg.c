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
#include "../lib/allocator.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/posix.h"

#include "../lib/pg.h"

#define PG_DEFAULT_HOST "localhost"
#define PG_DEFAULT_PORT 5432
#define PG_DEFAULT_DB "rrr"
#define PG_DEFAULT_USER ""
#define PG_DEFAULT_PASSWORD ""

struct pg_data {
	struct rrr_instance_runtime_data *thread_data;

	char *host;
	uint16_t port;
	char port_str[16];
	char *db;
	char *user;
	char *pass;

	struct rrr_pg_conn *conn;
};

static void pg_data_cleanup (void *arg) {
	struct pg_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->host);
	RRR_FREE_IF_NOT_NULL(data->db);
	RRR_FREE_IF_NOT_NULL(data->user);
	RRR_FREE_IF_NOT_NULL(data->pass);

	if (data->conn != NULL) {
		rrr_pg_destroy(data->conn);
	}
}

static int data_init (
		struct pg_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	memset (data, '\0', sizeof (*data));

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

	// Memory cleaned up by pg_data_cleanup in all cases

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("pg_host", host, PG_DEFAULT_HOST);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT("pg_port", port, PG_DEFAULT_PORT);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("pg_db", db, PG_DEFAULT_DB);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("pg_user", user, PG_DEFAULT_USER);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("pg_password", pass, PG_DEFAULT_PASSWORD);

	out:
	return ret;
}

int pg_connect_as_needed_and_check (struct pg_data *data) {
	int ret = 0;

	if (data->conn) {
		if (rrr_pg_check(data->conn) == 0) {
			goto out;
		}

		RRR_DBG_1("pg instance %s connection is broken\n",
			INSTANCE_D_NAME(data->thread_data));

		rrr_pg_destroy(data->conn);
		data->conn = NULL;
	}

	RRR_DBG_1("pg instance %s connecting to %s:%s\n",
		INSTANCE_D_NAME(data->thread_data), data->host, data->port_str);

	if (rrr_pg_new (&data->conn, data->host, data->port_str, data->db, data->user, data->pass) != 0) {
		RRR_MSG_0("Failed to create database connection to %s:%s in pg instance %s\n",
			data->host, data->port_str, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	RRR_DBG_1("pg instance %s connected to %s:%s\n",
		INSTANCE_D_NAME(data->thread_data), data->host, data->port_str);

	out:
	return ret;
}

int pg_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct pg_data *data = thread_data->private_data;

	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread) != 0) {
		return RRR_EVENT_EXIT;
	}

	// Ignore errors, retry periodically
	pg_connect_as_needed_and_check (data);

	return 0;
}

static void *thread_entry_pg (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct pg_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in pg instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("pg thread data is %p, size of private data: %llu\n", thread_data, (long long unsigned) sizeof(*data));

	pthread_cleanup_push(pg_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(INSTANCE_D_CONFIG(thread_data));

	RRR_DBG_1("pg started thread %p\n", thread);

	// Ignore errors, retry periodically
	pg_connect_as_needed_and_check (data);

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			pg_pause_check,
			thread_data
	);

	// RRR_BUG("Push periodic poll event here");

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 second
			pg_event_periodic,
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
