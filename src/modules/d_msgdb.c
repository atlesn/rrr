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
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"

#define RRR_MSGDB_DEFAULT_DIRECTORY  "/var/lib/rrr/msgdb"
#define RRR_MSGDB_DEFAULT_SOCKET     "/var/run/rrr/msgdb.sock"

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

// TODO : Provide more configuration arguments
static int msgdb_parse_config (struct msgdb_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("msgdb_directory", directory, RRR_MSGDB_DEFAULT_DIRECTORY);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("msgdb_socket", socket, RRR_MSGDB_DEFAULT_SOCKET);

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

	rrr_thread_start_condition_helper_nofork(thread);

	if (msgdb_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for msgdb instance '%s'\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("msgdb started thread %p\n", thread_data);

	struct rrr_msgdb_server *msgdb = NULL;

	if (rrr_msgdb_server_new(&msgdb, data->directory, data->socket) != 0) {
		RRR_MSG_0("Could not start message db server in msgdb instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	pthread_cleanup_push(rrr_msgdb_server_destroy_void, msgdb);

	// DO NOT use signed, let it overflow
	unsigned long int consecutive_nothing_happened = 0;

	uint64_t prev_recv_count = 0;
	uint64_t prev_second_recv_count = 0;
	uint64_t prev_stats_time = rrr_time_get_64();
	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		uint64_t time_now = rrr_time_get_64();
		rrr_thread_watchdog_time_update(thread);

		if (rrr_msgdb_server_tick(msgdb) != 0) {
			RRR_MSG_0("Error from message db server while ticking in msgdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
			break;
		}

		const uint64_t recv_count = rrr_msgdb_server_recv_count_get(msgdb);

		if (recv_count != prev_recv_count) {
			consecutive_nothing_happened++;
		}
		else {
			consecutive_nothing_happened = 0;
		}

		prev_recv_count = recv_count;

		if (consecutive_nothing_happened > 5000) {
			rrr_posix_usleep(50000); // 50 ms
		}
		if (consecutive_nothing_happened > 50) {
			rrr_posix_usleep(2000); // 2ms
		}

		if (time_now > (prev_stats_time + 1 * 1000 * 1000)) {
			RRR_DBG_1("msgdb instance %s messages per second %i total %" PRIu64 "\n",
					INSTANCE_D_NAME(thread_data), recv_count - prev_second_recv_count, recv_count);

			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 1, "recv_rate", recv_count - prev_second_recv_count);

			prev_second_recv_count = recv_count;
			prev_stats_time = rrr_time_get_64();
		}
	}

	pthread_cleanup_pop(1);

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
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy msgdb module\n");
}

