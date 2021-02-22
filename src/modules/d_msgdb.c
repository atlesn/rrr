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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "../lib/log.h"

#include "../lib/msgdb/msgdb_server.h"
#include "../lib/instance_config.h"
#include "../lib/rrr_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/gnu.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"

#define RRR_MSGDB_DEFAULT_DIRECTORY  "/var/lib/rrr/msgdb"
#define RRR_MSGDB_DEFAULT_SOCKET     "msgdb.sock"

struct msgdb_data {
	struct rrr_instance_runtime_data *thread_data;
	char *directory;
	char *socket;
};

static void msgdb_data_cleanup(void *arg) {
	struct msgdb_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->directory);
	RRR_FREE_IF_NOT_NULL(data->socket);
}

static int msgdb_data_init (
		struct msgdb_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	data->thread_data = thread_data;

	return ret;
}

static int msgdb_parse_config (struct msgdb_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("msgdb_directory", directory, RRR_MSGDB_DEFAULT_DIRECTORY);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("msgdb_socket", socket);

	if (data->directory == NULL) {
		if ((ret = rrr_asprintf(&data->directory, "%s/%s", rrr_config_global.run_directory, RRR_MSGDB_DEFAULT_SOCKET)) <= 0) {
			RRR_MSG_0("rrr_asprintf() failed in msgdb_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

struct msgdb_fork_tick_callback_data {
	struct msgdb_data *data;
	struct rrr_msgdb_server *msgdb;
	uint64_t prev_recv_count;
};

static int msgdb_fork_tick_callback (RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS) {
	struct msgdb_fork_tick_callback_data *callback_data = private_arg;

	struct rrr_msgdb_server *msgdb = callback_data->msgdb;
	struct msgdb_data *data = callback_data->data;

	(void)(worker);
	(void)(msgdb);
	(void)(data);

	int ret = 0;

	*something_happened = 0;

	// Do nothing

	return ret;
}

static int msgdb_fork_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct rrr_instance_runtime_data *thread_data = private_arg;
	struct msgdb_data *data = thread_data->private_data;

	(void)(custom_tick_callback_arg);

	int ret = 0;

	struct rrr_msgdb_server *msgdb = NULL;

	if (rrr_msgdb_server_new(&msgdb, data->directory, data->socket) != 0) {
		RRR_MSG_0("Could not start message db server in msgdb instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((rrr_msgdb_server_event_setup(msgdb, rrr_cmodule_worker_get_event_queue(worker))) != 0) {
		RRR_MSG_0("Could not setup message db events in msgdb instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
		goto out;
	}

	struct msgdb_fork_tick_callback_data tick_callback_data = {
		data,
		msgdb,
		0
	};

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg,
			custom_tick_callback,
			&tick_callback_data
	)) != 0) {
		RRR_MSG_0("Error from worker loop in msgdb_fork_tick_callback\n");
		goto out;
	}

	out:
	if (msgdb != NULL) {
		rrr_msgdb_server_destroy(msgdb);
	}
	return ret;
}

static int msgdb_fork (void *arg) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct msgdb_data *data = thread_data->private_data;

	int ret = 0;

	if ((ret = msgdb_parse_config(data, thread_data->init_data.instance_config)) != 0) {
		RRR_MSG_0("Configuration parse failed for msgdb instance '%s'\n", INSTANCE_D_NAME(thread_data));
		goto out;
	}

	// Don't parse cmodule config, not used.

        if (rrr_cmodule_helper_worker_custom_fork_start (
                        thread_data,
			250, // 250ms
			msgdb_fork_init_wrapper_callback,
			thread_data,
			msgdb_fork_tick_callback,
			NULL
	) != 0) {
		RRR_MSG_0("Error while starting cmodule worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;

}

static void *thread_entry_msgdb (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct msgdb_data *data = thread_data->private_data = thread_data->private_memory;

	int init_ret = 0;
	if ((init_ret = msgdb_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initialize data in msgdb instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_DBG_1 ("msgdb thread data is %p\n", thread_data);

	pthread_cleanup_push(msgdb_data_cleanup, data);

	if (rrr_thread_start_condition_helper_fork(thread, msgdb_fork, thread_data) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("msgdb started thread %p\n", thread_data);

	rrr_cmodule_helper_loop (
			thread_data,
			1 * 1000 * 1000 // 1 s
	);

	out_message:
		RRR_DBG_1 ("Thread msgdb %p exiting\n", thread);
		pthread_cleanup_pop(1);
		pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_msgdb,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "msgdb";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_NETWORK;
	data->operations = module_operations;
}

void unload(void) {
	RRR_DBG_1 ("Destroy msgdb module\n");
}

