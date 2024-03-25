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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

//#include "../lib/ip/ip.h"
#include "../lib/map.h"
#include "../lib/threads.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/rrr_strerror.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/instance_config.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/raft/rrr_raft.h"

#define RAFT_DEFAULT_PORT 9001
#define RAFT_PATH_BASE "/tmp/rrr-raft"

struct raft_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_map servers;
	struct rrr_raft_channel *channel;
};

static void raft_data_init(struct raft_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void raft_data_cleanup(struct raft_data *data) {
	rrr_map_clear(&data->servers);
	if (data->channel != NULL)
		rrr_raft_cleanup(data->channel);
}

static int raft_poll_callback (RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct raft_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	RRR_DBG_3("raft instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	assert(0 && "Poll CB not implemented\n");
	
/*
	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	)) == RRR_THREAD_STOP) {
		// The stop signal might not propagate all the way
		// throug the poll stack. Save it here and check
		// in the data available event.
		data->encourage_stop_received = 1;
	}*/

	rrr_msg_holder_unlock(entry);
	return ret;
}

static int raft_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	*amount = 0;

	return 0;

	(void)(data);

	return rrr_poll_do_poll_delete (amount, thread_data, raft_poll_callback);
}

static int raft_parse_config (struct raft_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	if ((ret = rrr_instance_config_parse_comma_separated_associative_to_map (
			&data->servers,
			config,
			"raft_nodes",
			"->"
	)) != 0) {
		RRR_MSG_0("Failed to parse parameter raft_nodes of raft instance %s\n",
			config->name);
		goto out;
	}

	out:
	return ret;
}

static void raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(data);

	printf("Pong\n");
}

static void raft_ack_callback (RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(req_index);
	(void)(ok);
	(void)(data);

	assert(0 && "ACK callback not implemented");
}

static void raft_opt_callback (RRR_RAFT_CLIENT_OPT_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(req_index);
	(void)(is_leader);
	(void)(servers);
	(void)(data);

	assert(0 && "OPT callback not implemented");
}

static void raft_msg_callback (RRR_RAFT_CLIENT_MSG_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(req_index);
	(void)(msg);
	(void)(data);

	assert(0 && "MSG callback not implemented");
}

static int raft_fork (void *arg) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	int ret = 0;

	int socketpair[2] = {0}, i;
	unsigned long long id;
	char *end, path[64];
	struct rrr_raft_server *servers = NULL;

	if ((ret = raft_parse_config(data, INSTANCE_D_CONFIG(thread_data))) != 0) {
		goto out_err;
	}

	if ((servers = rrr_allocate_zero(sizeof(*servers) * (RRR_LL_COUNT(&data->servers) + 1))) == NULL) {
		RRR_MSG_0("Failed to allocate servers structure in %s\n", __func__);
		ret = 1;
		goto out_err;
	}

	if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, INSTANCE_D_NAME(thread_data), socketpair)) != 0) {
		RRR_MSG_0("Failed to create sockets in %s: %s\n",
			rrr_strerror(errno));
		goto out_err;
	}

	i = 0;
	RRR_MAP_ITERATE_BEGIN(&data->servers);
		id = strtoull(node_value, &end, 10);
		if (end == NULL || id < 1 || id > INT32_MAX || *end != '\0') {
			RRR_MSG_0("Invalid value '%s' for ID of server '%s' in configuration of raft instance %s. Ensure that ID is set after '->' separator.\n",
				node_value, node_tag, INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_err;
		}
		if (strlen(node_tag) > sizeof(servers[0].address) - 1) {
			RRR_MSG_0("Server name '%s' too long in configuration of raft instance %s, may not exceed %lu characters.\n",
				node_tag, sizeof(servers[0].address) - 1);
			ret = 1;
			goto out_err;
		}

		servers[i].id = rrr_int_from_biglength_bug_const(id);
		strcpy(servers[i].address, node_tag);

		i++;	
	RRR_MAP_ITERATE_END();

	sprintf(path, "%s/%" PRIi64 "", RAFT_PATH_BASE, servers[0].id);

	if ((ret = rrr_raft_fork (
			&data->channel,
			INSTANCE_D_FORK(thread_data),
			INSTANCE_D_EVENTS(thread_data),
			INSTANCE_D_NAME(thread_data),
			socketpair,
			servers,
			0, /* Self index, assume it to be first in servers list */
			path,
			raft_pong_callback,
			raft_ack_callback,
			raft_opt_callback,
			raft_msg_callback,
			data
	)) != 0) {
		RRR_MSG_0("Failed to create raft for in raft instance %s\n",
			INSTANCE_D_NAME(thread_data));
		goto out_err;
	}

	goto out;
	out_err:
		raft_data_cleanup(data);
	out:
		RRR_FREE_IF_NOT_NULL(servers);
		if (socketpair[0] > 0)
			rrr_socket_close(socketpair[0]);
		if (socketpair[1] > 0)
			rrr_socket_close(socketpair[1]);
		return ret;
}

static int raft_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	raft_data_init(data, thread_data);

	if (rrr_thread_start_condition_helper_fork(thread, raft_fork, thread) != 0) {
		RRR_MSG_0("Forking failed in raft instance %s\n", INSTANCE_D_NAME(thread_data));
		return 1;
	}

	RRR_DBG_1 ("raft thread data is %p\n", thread_data);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("raft instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000, // 1 second
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void
	);

	RRR_DBG_1 ("Thread raft %p exiting\n", thread);
	return 0;
}

static void raft_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	raft_data_cleanup(data);

	rrr_event_receiver_reset(INSTANCE_D_EVENTS_H(thread_data));

	*deinit_complete = 1;
}

struct rrr_instance_event_functions event_functions = {
	raft_event_broker_data_available
};

static const char *module_name = "raft";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = event_functions;
	data->init = raft_init;
	data->deinit = raft_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy raft module\n");
}

