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
#include "../lib/array.h"
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

enum raft_req_type {
	RAFT_REQ_PUT,
	RAFT_REQ_LEADERSHIP_TRANSFER
};

#define RAFT_REQ_TYPE_TO_STR(type)                                                   \
    ((type) == RAFT_REQ_PUT ? "PUT" :                                                \
    ((type) == RAFT_REQ_LEADERSHIP_TRANSFER ? "LEADERSHIP TRANSFER" : "UNKNOWN"))

struct raft_request {
	uint32_t req_index;
	struct rrr_msg_msg *msg_orig;
	enum raft_req_type req_type;
};

struct raft_request_collection {
	struct raft_request *requests;
	size_t capacity;
};

static int raft_request_init (
		struct raft_request *request,
		uint32_t req_index,
		enum raft_req_type req_type,
		const struct rrr_msg_msg *msg_orig
) {
	int ret = 0;

	request->req_index = req_index;
	request->req_type = req_type;

	if (msg_orig != NULL && (request->msg_orig = rrr_msg_msg_duplicate(msg_orig)) == NULL) {
		RRR_MSG_0("Failed to duplicate message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void raft_request_clear (
		struct raft_request *request
) {
	RRR_FREE_IF_NOT_NULL(request->msg_orig);
	*request = (struct raft_request) {0};
}

static struct raft_request raft_request_collection_consume (
		struct raft_request_collection *collection,
		uint32_t req_index
) {
	struct raft_request result;

	for (size_t i = 0; i < collection->capacity; i++) {
		if (collection->requests[i].req_index == req_index) {
			result = collection->requests[i];
			collection->requests[i] = (struct raft_request) {0};
			printf("== consume req %u type %s\n", req_index, RAFT_REQ_TYPE_TO_STR(result.req_type));
			return result;
		}
	}

	RRR_BUG("BUG: Request %u not found in %s\n", req_index, __func__);
}

static int raft_request_collection_push (
		struct raft_request_collection *collection,
		uint32_t req_index,
		enum raft_req_type req_type,
		const struct rrr_msg_msg *msg_orig
) {
	int ret = 0;

	printf("== push   req %u type %s cap %lu\n",
		req_index, RAFT_REQ_TYPE_TO_STR(req_type), collection->capacity);

	struct raft_request *target = NULL, *requests_new;
	size_t capacity_new;

	for (size_t i = 0; i < collection->capacity; i++) {
		if (collection->requests[i].req_index == 0) {
			target = &collection->requests[i];
			break;
		}
	}

	if (target)
		goto target_found;

	capacity_new = collection->capacity + 64;
	if ((requests_new = rrr_reallocate(collection->requests, capacity_new * sizeof(*requests_new))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}
	memset(requests_new + collection->capacity, '\0', sizeof(*requests_new) * (capacity_new - collection->capacity));

	target = requests_new + collection->capacity;
	collection->requests = requests_new;
	collection->capacity = capacity_new;

	target_found:
		if ((ret = raft_request_init(target, req_index, req_type, msg_orig)) != 0) {
			goto out;
		}
	out:
		return ret;
}

static void raft_request_collection_clear (
		struct raft_request_collection *collection
) {
	for (size_t i = 0; i < collection->capacity; i++) {
		raft_request_clear(&collection->requests[i]);
	}
	RRR_FREE_IF_NOT_NULL(collection->requests);
	*collection = (struct raft_request_collection) {0};
}

struct raft_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_map servers;
	rrr_setting_uint preferred_leader;

	struct rrr_raft_channel *channel;
	struct raft_request_collection requests;
	int is_leader;
	int leader_id;
	char leader_address[128];
};

static void raft_data_init(struct raft_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void raft_data_cleanup(struct raft_data *data) {
	rrr_map_clear(&data->servers);
	if (data->channel != NULL)
		rrr_raft_cleanup(data->channel);
	raft_request_collection_clear(&data->requests);
}

static int raft_poll_callback (RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct raft_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	uint32_t req_index;

	if (!data->is_leader) {
		RRR_MSG_0("Warning: Received message in raft instance %s which is not leader of the cluster.\n",
			INSTANCE_D_NAME(thread_data));
	}

	RRR_DBG_3("raft instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	if ((ret = rrr_raft_client_request_put_native (
			&req_index,
			data->channel,
			message
	)) != 0) {
		RRR_MSG_0("Warning: Failed to put message in raft instance %s\n",
			INSTANCE_D_NAME(thread_data));
		goto out;
	}

	// Message must be copied while the data is protected by entry lock
	if ((ret = raft_request_collection_push (
			&data->requests,
			req_index,
			RAFT_REQ_PUT,
			message
	)) != 0) {
		goto out;
	}

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int raft_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

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

	// TODO : Parse status message parameter
	
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("raft_preferred_leader", preferred_leader, 0);
	if (data->preferred_leader > INT32_MAX) {
		RRR_MSG_0("Field preferred_leader out of rang in raft instance %s, (%llu>%i)\n",
			config->name, (unsigned long long) data->preferred_leader, INT32_MAX);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(data);
}

static void raft_ack_callback (RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	int ret_tmp = 0;
	struct rrr_array array_tmp = {0};
	struct raft_request request;
	struct rrr_msg_msg *msg;

	request = raft_request_collection_consume (&data->requests, req_index);
	msg = request.msg_orig;

	switch (request.req_type) {
		case RAFT_REQ_PUT: {
			ret_tmp |= rrr_array_push_value_str_with_tag_with_size (
				&array_tmp,
				"raft_topic",
				MSG_TOPIC_LENGTH(msg) > 0 ? MSG_TOPIC_PTR(msg) : "",
				MSG_TOPIC_LENGTH(msg)
			);
			ret_tmp |= rrr_array_push_value_i64_with_tag (
				&array_tmp,
				"raft_status",
				code == RRR_RAFT_OK
			);
			ret_tmp |= rrr_array_push_value_str_with_tag (
				&array_tmp,
				"raft_reason",
				rrr_raft_reason_to_str(code)
			);
			ret_tmp |= rrr_array_push_value_i64_with_tag (
				&array_tmp,
				"raft_server_id",
				server_id
			);
			ret_tmp |= rrr_array_push_value_i64_with_tag (
				&array_tmp,
				"raft_leader_id",
				data->leader_id
			);
			ret_tmp |= rrr_array_push_value_str_with_tag (
				&array_tmp,
				"raft_leader_address",
				data->leader_address
			);
			if (ret_tmp != 0) {
				RRR_MSG_0("Warning: Failed to add array values in %s\n", __func__);
				goto out;
			}
		} break;
		case RAFT_REQ_LEADERSHIP_TRANSFER: {
			RRR_DBG_1("Result of leadership transfer in raft instance %s: %s\n",
				INSTANCE_D_NAME(data->thread_data), rrr_raft_reason_to_str(code));
		} break;
		default: {
			RRR_BUG("BUG: Unknown type %i in %s\n", request.req_type, __func__);
		} break;
	};

	if (code != RRR_RAFT_OK) {
		RRR_MSG_0("Warning: A request failed in raft instance %s, negative ACK with reason '%s' was received from the node.\n",
			INSTANCE_D_NAME(data->thread_data), rrr_raft_reason_to_str(code));
	}

	out:
	raft_request_clear(&request);
	rrr_array_clear(&array_tmp);
}

static int raft_leadership_transfer (
		struct raft_data *data,
		int server_id
) {
	int ret = 0;

	uint32_t req_index;

	if ((ret = rrr_raft_client_leadership_transfer (
			&req_index,
			data->channel,
			server_id
	)) != 0) {
		goto out;
	}

	if ((ret = raft_request_collection_push (
			&data->requests,
			req_index,
			RAFT_REQ_LEADERSHIP_TRANSFER,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void raft_opt_callback (RRR_RAFT_CLIENT_OPT_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(req_index);
	(void)(data);

	struct rrr_raft_server *server;

	strncpy(data->leader_address, leader_address, sizeof(data->leader_address));
	data->leader_address[sizeof(data->leader_address) - 1] = '\0';

	data->leader_id = leader_id;

	if (is_leader && data->preferred_leader > 0 && (int) data->preferred_leader != leader_id) {
		RRR_DBG_1("Raft instance %s id %i transferring leadership to %llu per configuration\n",
			INSTANCE_D_NAME(data->thread_data), server_id, (unsigned long long) data->preferred_leader);

		assert(data->preferred_leader <= INT32_MAX);
		if (raft_leadership_transfer(data, (int) data->preferred_leader) != 0) {
			RRR_MSG_0("Warning: Failed to transfer leadership to %llu in raft instance %s\n",
				(unsigned long long) data->preferred_leader,
				INSTANCE_D_NAME(data->thread_data)
			);
		}
	}

	if (is_leader) {
		RRR_DBG_1("Raft instance %s id %i is leader, cluster status for all nodes:\n",
			INSTANCE_D_NAME(data->thread_data), server_id);
		data->is_leader = 1;
	}
	else {
		RRR_DBG_1("Raft instance %s id %i is not leader, cluster status for all nodes:\n",
			INSTANCE_D_NAME(data->thread_data), server_id);
		data->is_leader = 0;
	}
	
	for (server = *servers; server->id > 0; server++) {
		RRR_DBG_1("- %s id %" PRIi64 " status %s catch up %s\n",
			server->address,
			server->id,
			RRR_RAFT_STATUS_TO_STR(server->status),
			RRR_RAFT_CATCH_UP_TO_STR(server->catch_up)
		);
	}
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

		servers[i].id = rrr_int_from_slength_bug_const(id);
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

static int raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data;

	uint32_t req_index;

	if (rrr_raft_client_request_opt(&req_index, data->channel) != 0) {
		RRR_MSG_0("Failed to send OPT request to raft node in raft instance %s\n",
			INSTANCE_D_NAME(thread_data));
		return RRR_EVENT_ERR;
	}

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
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
			raft_periodic
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

