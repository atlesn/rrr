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

#include <unistd.h>
#include <fcntl.h>

#include "server.h"
#include "common.h"
#include "channel.h"
#include "channel_struct.h"
#include "message_store.h"
#include "bridge.h"
#include "bridge_task.h"
#include "bridge_read.h"

#include "../allocator.h"
#include "../array.h"
#include "../fork.h"
#include "../common.h"
#include "../rrr_strerror.h"
#include "../random.h"
#include "../rrr_path_max.h"
#include "../read_constants.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_client.h"
#include "../ip/ip_helper.h"
#include "../ip/ip_util.h"
#include "../ip/ip.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
#include "../net_transport/net_transport_ctx.h"
#include "../util/rrr_time.h"
#include "../util/gnu.h"

#define RRR_RAFT_SERVER_DBG_EVENT(msg, ...) \
    RRR_DBG_3("Raft [%i][server] " msg "\n", state->bridge->server_id, __VA_ARGS__)

#define RRR_RAFT_SERVER_DBG_FILE(name, msg, ...) \
    RRR_DBG_3("Raft [%i][server][%s] " msg "\n", state->bridge->server_id, name, __VA_ARGS__)

#define RRR_RAFT_SERVER_DBG_NET(address, msg, ...) \
    RRR_DBG_3("Raft [%i][server][%s] " msg "\n", state->bridge->server_id, address, __VA_ARGS__)

#define RRR_RAFT_SERVER_ERR_NET(address, msg, ...) \
    RRR_MSG_0("Raft [%i][server][%s] " msg "\n", state->bridge->server_id, address, __VA_ARGS__)

#define RRR_RAFT_SERVER_NET_FIRST_READ_TIMEOUT_S              2
#define RRR_RAFT_SERVER_NET_HARD_TIMEOUT_S                   30
#define RRR_RAFT_SERVER_NET_TICK_INTERVAL_S                   1
#define RRR_RAFT_SERVER_NET_SEND_CHUNK_COLLECTION_LIMIT  100000

struct rrr_raft_server_fsm_result {
	uint32_t req_index;
	enum rrr_raft_code code;
	struct rrr_msg_msg *msg;
};

struct rrr_raft_server_fsm_result_collection {
	struct rrr_raft_server_fsm_result *results;
	size_t wpos;
	size_t capacity;
};

struct rrr_raft_server_state {
	struct rrr_raft_channel *channel;
	struct rrr_raft_message_store *message_store_state;
	struct rrr_raft_bridge *bridge;
	struct rrr_raft_task_list *tasks;
	struct raft_configuration *configuration;
	struct rrr_net_transport *net_transport;
/*	uint32_t change_req_index;
	uint32_t transfer_req_index;
	uint32_t snapshot_req_index;*/
	struct rrr_raft_server_fsm_result_collection *fsm_results;
	struct {
		rrr_event_handle raft_timeout;
		rrr_event_handle socket;
	} events;
	int exiting;
};

struct rrr_raft_server_connection {
	raft_id server_id;
	char *server_address;
};

static inline void *__rrr_raft_server_malloc (void *data, size_t size) {
	(void)(data);
	return rrr_allocate(size);
}

static inline void __rrr_raft_server_free (void *data, void *ptr) {
	(void)(data);
	return rrr_free(ptr);
}

static inline void *__rrr_raft_server_calloc (void *data, size_t nmemb, size_t size) {
	(void)(data);
	return rrr_callocate(nmemb, size);
}

static inline void *__rrr_raft_server_realloc (void *data, void *ptr, size_t size) {
	(void)(data);
	return rrr_reallocate(ptr, size);
}

static inline void *__rrr_raft_server_aligned_alloc (void *data, size_t alignment, size_t size) {
	(void)(data);
	return rrr_aligned_allocate(alignment, size);
}

static inline void __rrr_raft_server_aligned_free (void *data, size_t alignment, void *ptr) {
	(void)(data);
	return rrr_aligned_free(alignment, ptr);
}

static void __rrr_raft_server_fsm_result_clear (
		struct rrr_raft_server_fsm_result *result
) {
	result->req_index = 0;
	result->code = 0;
	RRR_FREE_IF_NOT_NULL(result->msg);
}

static void __rrr_raft_server_fsm_result_set (
		struct rrr_raft_server_fsm_result *result,
		uint32_t req_index,
		struct rrr_msg_msg **msg,
		enum rrr_raft_code code
) {
	assert(result->msg == NULL);

	result->req_index = req_index;
	result->code = code;
	result->msg = *msg;

	*msg = NULL;
}

static int __rrr_raft_server_fsm_result_collection_push (
		struct rrr_raft_server_fsm_result_collection *results,
		uint32_t req_index,
		struct rrr_msg_msg **msg,
		enum rrr_raft_code code
) {
	int ret = 0;

	size_t i, capacity_new;
	struct rrr_raft_server_fsm_result *slot;

	for (i = 0; i < results->wpos; i++) {
		if ((slot = results->results + i)->msg != NULL)
			continue;

		__rrr_raft_server_fsm_result_set(slot, req_index, msg, code);

		goto out;
	}

	if (results->wpos == results->capacity) {
		capacity_new = results->capacity + 32;
		if ((slot = rrr_reallocate(results->results, sizeof(*slot) * capacity_new)) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memset(slot + results->capacity, '\0', sizeof(*slot) * (capacity_new - results->capacity));
		results->results = slot;
		results->capacity = capacity_new;
	}

	slot = results->results + results->wpos++;

	__rrr_raft_server_fsm_result_set(slot, req_index, msg, code);

	out:
	return ret;
}

static void __rrr_raft_server_fsm_result_collection_pull (
		struct rrr_raft_server_fsm_result *result,
		struct rrr_raft_server_fsm_result_collection *results,
		uint32_t req_index
) {
	size_t i;
	struct rrr_raft_server_fsm_result *slot;

	for (i = 0; i < results->wpos; i++) {
		if ((slot = results->results + i)->req_index != req_index) 
			continue;

		*result = *slot;
		*slot = (struct rrr_raft_server_fsm_result) {0};

		return;
	}

	RRR_BUG("BUG: Request %u not found in %s\n", req_index, __func__);
}

static void __rrr_raft_server_fsm_result_collection_clear (
		size_t *cleared_count,
		struct rrr_raft_server_fsm_result_collection *results
) {
	*cleared_count = 0;

	for (size_t i = 0; i < results->wpos; i++) {
		if (results->results[i].msg)
			(*cleared_count)++;
		__rrr_raft_server_fsm_result_clear(results->results + i);
	}
}

static enum rrr_raft_code __rrr_raft_server_status_translate (
		int status
) {
	switch (status) {
		case 0:
			return 0;
		case RAFT_LEADERSHIPLOST:
		case RAFT_NOTLEADER:
			return RRR_RAFT_NOT_LEADER;
	};

	return RRR_RAFT_ERROR;
}

static void __rrr_raft_server_connection_destroy (
		struct rrr_raft_server_connection *connection
) {
	rrr_free(connection->server_address);
	rrr_free(connection);
}

static void __rrr_raft_server_connection_destroy_void (
		void *arg
) {
	__rrr_raft_server_connection_destroy(arg);
}

static int __rrr_raft_server_connection_new (
		struct rrr_raft_server_connection **result,
		raft_id server_id,
		const char *server_name,
		uint16_t server_port
) {
	int ret = 0;

	struct rrr_raft_server_connection *connection;

	if ((connection = rrr_allocate_zero(sizeof(*connection))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((rrr_asprintf(&connection->server_address, "%s:%u", server_name, server_port)) <= 0) {
		RRR_MSG_0("Failed to allocate memory for server address in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	connection->server_id = server_id;

	*result = connection;

	goto out;
	out_free:
		rrr_free(connection);
	out:
		return ret;
}

struct rrr_raft_server_make_opt_response_server_fields_iterate_cb_data {
	struct rrr_array *array;
};

static int __rrr_raft_server_make_opt_response_server_fields_iterate_cb (
		raft_id server_id,
		const char *server,
		int role,
		int catch_up,
		void *arg
) {
	struct rrr_raft_server_make_opt_response_server_fields_iterate_cb_data *cb_data = arg;

	int ret = 0;

	size_t address_len;
	struct rrr_raft_server server_tmp = {0};

	address_len = strlen(server);
	assert(address_len < sizeof(server_tmp.address));
	memcpy(server_tmp.address, server, address_len + 1);

	server_tmp.id = server_id;

	switch (role) {
		case RAFT_STANDBY:
			server_tmp.status = RRR_RAFT_STANDBY;
			break;
		case RAFT_VOTER:
			server_tmp.status = RRR_RAFT_VOTER;
			break;
		case RAFT_SPARE:
			server_tmp.status = RRR_RAFT_SPARE;
			break;
		default:
			RRR_BUG("Unknown role %i in %s\n", role, __func__);
	};

	switch (catch_up) {
		case -1:
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_UNKNOWN;
			break;
		case RAFT_CATCH_UP_NONE:
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_NONE;
			break;
		case RAFT_CATCH_UP_RUNNING:
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_RUNNING;
			break;
		case RAFT_CATCH_UP_ABORTED:
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_ABORTED;
			break;
		case RAFT_CATCH_UP_FINISHED:
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_FINISHED;
			break;
		default:
			RRR_BUG("BUG: Unknown catch up code %i from raft library in %s\n",
				catch_up, __func__);
	};

	if ((ret = rrr_raft_opt_array_field_server_push (
			cb_data->array,
			&server_tmp
	)) != 0) {
		RRR_MSG_0("Failed to push server in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}


static int __rrr_raft_server_make_opt_response_server_fields (
		struct rrr_array *array,
		struct rrr_raft_server_state *state
) {
	struct rrr_raft_bridge *bridge = state->bridge;

	struct rrr_raft_server_make_opt_response_server_fields_iterate_cb_data cb_data = {
		array
	};

	return rrr_raft_bridge_configuration_iterate (
			bridge,
			__rrr_raft_server_make_opt_response_server_fields_iterate_cb,
			&cb_data
	);
}

static int __rrr_raft_server_make_opt_response (
		struct rrr_msg_msg **result,
		struct rrr_raft_server_state *state,
		rrr_u32 req_index
) {
	struct rrr_raft_bridge *bridge = state->bridge;

	int ret = 0;

	struct rrr_msg_msg *msg = NULL;
	struct rrr_array array_tmp = {0};
	raft_id leader_id;
	const char *leader_address;

	*result = NULL;

	rrr_raft_bridge_get_leader(&leader_id, &leader_address, bridge);

	ret |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_IS_LEADER,
			rrr_raft_bridge_is_leader(bridge)
	);
	ret |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_LEADER_ID,
			leader_id
	);
	ret |= rrr_array_push_value_str_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_LEADER_ADDRESS,
			leader_address != NULL ? leader_address : ""
	);

	if (ret != 0) {
		RRR_MSG_0("Failed to push array values in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_raft_server_make_opt_response_server_fields (
			&array_tmp,
			state
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_new_message_from_array (
			&msg,
			&array_tmp,
			rrr_time_get_64(),
			NULL,
			0
	)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_OPT);
	msg->msg_value = req_index;

	*result = msg;
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_raft_server_send_msg (
		struct rrr_raft_channel *channel,
		struct rrr_msg *msg
) {
	rrr_u32 total_size = MSG_TOTAL_SIZE(msg);

	if (RRR_MSG_IS_RRR_MESSAGE(msg)) {
		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg);
	}
	rrr_msg_checksum_and_to_network_endian(msg);

	if (write(channel->fd_server, msg, total_size) != total_size) {
		if (errno == EPIPE) {
			return RRR_READ_EOF;
		}
		RRR_MSG_0("Failed to send message in %s: %s\n",
			__func__, rrr_strerror(errno));
		return RRR_READ_HARD_ERROR;
	}

	return RRR_READ_OK;
}

static int __rrr_raft_server_send_msg_in_loop (
		struct rrr_raft_server_state *state,
		struct rrr_msg *msg
) {
	int ret = 0;

	if ((ret = __rrr_raft_server_send_msg(state->channel, msg)) != 0) {
		if (ret == RRR_READ_EOF) {
			rrr_event_dispatch_exit(state->channel->queue);
			ret = 0;
			goto out;
		}

		RRR_MSG_0("Failed to send message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}


/*
static void __rrr_raft_server_change_cb_final (
		struct rrr_raft_server_state *callback_data,
		uint64_t req_index,
		int ok,
		enum rrr_raft_code code
) {
	struct rrr_msg msg_ack = {0};
	struct rrr_msg_msg *msg = NULL;

	rrr_msg_populate_control_msg (
			&msg_ack,
			ok ? RRR_MSG_CTRL_F_ACK : RRR_MSG_CTRL_F_NACK_REASON(code),
			req_index
	);

	if (__rrr_raft_server_make_opt_response (
			&msg,
			callback_data->raft,
			req_index
	) != 0) {
		return;
	}

	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);
	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, (struct rrr_msg *) msg);

	rrr_free(msg);
}

static void __rrr_raft_server_server_change_cb (
		struct raft_change *req,
		int status
) {
	struct rrr_raft_server_state *callback_data = req->data;

	enum rrr_raft_code code = __rrr_raft_server_status_translate(status);

	assert(callback_data->change_req_index > 0);

	__rrr_raft_server_change_cb_final (
			callback_data,
			callback_data->change_req_index,
			status == 0,
			code
	);

	req->data = NULL;
	callback_data->change_req_index = 0;
}

static void __rrr_raft_server_leadership_transfer_cb (
		struct raft_transfer *req
) {
	struct rrr_raft_server_state *callback_data = req->data;
	struct raft *raft = callback_data->raft;

	const char *address;
	raft_id id;
	enum rrr_raft_code code;

	assert(callback_data->transfer_req_index > 0);

	raft_leader(raft, &id, &address);

	if (id != (long long unsigned) callback_data->server_id) {
		RRR_DBG_1("Leader transfer OK to %llu %s\n", id, address);
		code = RRR_RAFT_OK;
	}
	else {
		RRR_DBG_1("Leader transfer NOT OK to %llu %s\n", id, address);
		code = RRR_RAFT_ERROR;
	}

	__rrr_raft_server_change_cb_final (
			callback_data,
			callback_data->transfer_req_index,
			req->id == 0 || id == req->id,
			code
	);

	req->data = NULL;
	callback_data->transfer_req_index = 0;
}

static void __rrr_raft_server_suggest_snapshot_cb (
		struct raft_suggest_snapshot *req,
		int status
) {
	struct rrr_raft_server_state *callback_data = req->data;

	struct rrr_msg msg_ack = {0};

	enum rrr_raft_code code = __rrr_raft_server_status_translate(status);

	rrr_msg_populate_control_msg (
			&msg_ack,
			code == RRR_RAFT_OK ? RRR_MSG_CTRL_F_ACK : RRR_MSG_CTRL_F_NACK_REASON(code),
			callback_data->snapshot_req_index
	);

	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);

	req->data = NULL;
	callback_data->snapshot_req_index = 0;
}
*/
static int __rrr_raft_server_handle_cmd (
		struct rrr_raft_server_state *callback_data,
		rrr_u32 req_index,
		const struct rrr_msg_msg *msg
) {
//	struct raft *raft = callback_data->raft;

	(void)(callback_data);
	(void)(req_index);

	int ret = 0;

	struct rrr_array array_tmp = {0};
//	int ret_tmp;
//	int role;
	int64_t cmd, id;
	struct rrr_raft_server *servers;
	uint16_t version_dummy;

	if ((ret = rrr_array_message_append_to_array (
			&version_dummy,
			&array_tmp,
			msg
	)) != 0) {
		goto out;
	}

	if (rrr_array_get_value_signed_64_by_tag (
			&cmd,
			&array_tmp,
			RRR_RAFT_FIELD_CMD,
			0
	) != 0) {
		RRR_BUG("BUG: Command field missing in %s\n", __func__);
	}

	// Switch 1 of 2 (preparation)
	switch (cmd) {
		case RRR_RAFT_CMD_SERVER_ASSIGN:
		case RRR_RAFT_CMD_SERVER_ADD:
		case RRR_RAFT_CMD_SERVER_DEL: {
			if ((ret = rrr_raft_opt_array_field_server_get (
					&servers,
					&array_tmp
			)) != 0) {
				goto out;
			}

			// Only exactly one server may be added/deleted
			assert(servers && servers[0].id > 0 && servers[1].id == 0);

			assert(0 && "Del server not implemented\n");

//			assert(callback_data->change_req.data == NULL && callback_data->change_req_index == 0);
//			callback_data->change_req.data = callback_data;
//			callback_data->change_req_index = req_index;
		} break;
		case RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER: {
			if (rrr_array_get_value_signed_64_by_tag (
					&id,
					&array_tmp,
					RRR_RAFT_FIELD_ID,
					0
			) != 0) {
				RRR_BUG("BUG: ID field not set in transfer command in %s\n", __func__);
			}

			assert(0 && "Transfer leadership not implemented");

//			assert(callback_data->transfer_req.data == NULL && callback_data->transfer_req_index == 0);
//			callback_data->transfer_req.data = callback_data;
//			callback_data->transfer_req_index = req_index;
		} break;
		case RRR_RAFT_CMD_SNAPSHOT: {
			assert(0 && "snapshot cmd not implemented");
//			assert(callback_data->snapshot_req.data == NULL && callback_data->snapshot_req_index == 0);
//			callback_data->snapshot_req.data = callback_data;
//			callback_data->snapshot_req_index = req_index;
		} break;
		default:
			RRR_BUG("BUG: Unknown command %" PRIi64 " in %s\n", cmd, __func__);
	};

	// Switch 2 of 2 (execution)
	switch (cmd) {
		case RRR_RAFT_CMD_SERVER_ASSIGN: {
			switch (servers[0].status) {
				case RRR_RAFT_STANDBY:
//					role = RAFT_STANDBY;
					break;
				case RRR_RAFT_VOTER:
//					role = RAFT_VOTER;
					break;
				case RRR_RAFT_SPARE:
//					role = RAFT_SPARE;
					break;
				default:
					RRR_BUG("BUG: Unknown state %i in %s\n",
						servers[0].status, __func__);
			};

			assert(0 && "Assign not implemented");

/*			if ((ret_tmp = raft_assign (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					role,
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server assign failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_ADD: {
			RRR_DBG_1("Raft CMD add server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			assert(0 && "Server add not implemented");

/*			if ((ret_tmp = raft_add (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					servers[0].address,
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server add failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_DEL: {
			RRR_DBG_1("Raft CMD delete server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			assert(0 && "Server del not implemented");

/*			if ((ret_tmp = raft_remove (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server delete failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER: {
			RRR_DBG_1("Raft CMD transfer leadership to %" PRIi64 "\n", id);

			assert(0 && "Leadership transfer not implemented");

/*			if ((ret_tmp = raft_transfer (
					raft,
					&callback_data->transfer_req,
					rrr_int_from_slength_bug_const(id),
					__rrr_raft_server_leadership_transfer_cb
			)) != 0) {
				RRR_MSG_0("Server leadership transfer failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SNAPSHOT: {
			RRR_DBG_1("Raft CMD snapshot suggestion\n");

			assert(0 && "Snapshot suggestion not implemented");

/*			if ((ret_tmp = raft_suggest_snapshot (
					raft,
					&callback_data->snapshot_req,
					__rrr_raft_server_suggest_snapshot_cb
			)) != 0) {
				RRR_MSG_0("Snapshot suggestion failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/

		} break;
		default:
			RRR_BUG("BUG: Unknown command %" PRIi64 " in %s\n", cmd, __func__);
	};

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_raft_server_make_get_response (
		struct rrr_msg_msg **result,
		struct rrr_raft_message_store *message_store_state,
		rrr_u32 req_index,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	if ((ret = rrr_raft_message_store_get (
			result,
			message_store_state,
			MSG_TOPIC_PTR(msg),
			MSG_TOPIC_LENGTH(msg)
	)) != 0) {
		goto out;
	}

	assert(*result == NULL || MSG_IS_PUT(*result));

	if (*result)
		(*result)->msg_value = req_index;

	out:
	return ret;
}
/*
static void __rrr_raft_server_apply_cb (
		struct raft_apply *req,
		int status,
		void *result
) {
	struct rrr_raft_server_state *callback_data = req->data;
	uint32_t req_index = rrr_u32_from_ptr_bug_const(result);

	struct rrr_raft_server_fsm_result fsm_result;
	struct rrr_msg msg_ack = {0};
	enum rrr_raft_code code;

	__rrr_raft_server_fsm_result_collection_pull(&fsm_result, &callback_data->fsm_results, req_index);

	assert(fsm_result.msg != NULL && fsm_result.req_index == req_index);

	// Check errors from raft library
	if (status != 0) {
	       	if (status != RAFT_NOTLEADER) {
			RRR_MSG_0("Warning: Apply error: %s (%d)\n",
				raft_errmsg(callback_data->raft), status);
		}
		code = __rrr_raft_server_status_translate(status);
		goto nack;
	}

	// Check errors from FSM apply callback
	if (fsm_result.code != 0) {
		code = fsm_result.code;
		goto nack;
	}

	goto ack;
	ack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_ACK, fsm_result.msg->msg_value);
		goto send_msg;
	nack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_NACK_REASON(code), fsm_result.msg->msg_value);
		goto send_msg;

	send_msg:
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);
		__rrr_raft_server_fsm_result_clear(&fsm_result);

	goto out;
	out:
		raft_free(req);
}
*/
static int __rrr_raft_server_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_state *state = arg2;
	struct rrr_raft_bridge *bridge = state->bridge;

	(void)(arg1);

	int ret = 0;

//	int ret_tmp;
//	struct raft_buffer buf = {0};
//	struct raft_apply *req;
	struct rrr_msg msg = {0};
	struct rrr_msg_msg *msg_msg = NULL;

	assert((*message)->msg_value > 0);

	if (MSG_IS_OPT(*message)) {
		if (MSG_IS_ARRAY(*message)) {
			ret = __rrr_raft_server_handle_cmd (
					state,
					(*message)->msg_value,
					(*message)
			);
			goto out;
		}

		if ((ret = __rrr_raft_server_make_opt_response (
				&msg_msg,
				state,
				(*message)->msg_value
		)) != 0) {
			goto out;
		}

		goto out_send_msg_msg;
	}

	if (MSG_IS_GET(*message)) {
		if ((ret = __rrr_raft_server_make_get_response (
				&msg_msg,
				state->message_store_state,
				(*message)->msg_value,
				(*message)
		)) != 0) {
			goto out;
		}

		rrr_msg_populate_control_msg (
				&msg,
				msg_msg != NULL
					? RRR_MSG_CTRL_F_ACK
					: RRR_MSG_CTRL_F_NACK_REASON(RRR_RAFT_ENOENT),
				(*message)->msg_value
		);

		goto out_send_ctrl_msg;
	}

	if (!rrr_raft_bridge_is_leader(bridge)) {
		RRR_MSG_0("Warning: Refusing message to be stored. Not leader.\n");
		rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_NACK_REASON(RRR_RAFT_NOT_LEADER), (*message)->msg_value);
		goto out_send_ctrl_msg;
	}

/*	buf.len = MSG_TOTAL_SIZE(*message) + 8 - MSG_TOTAL_SIZE(*message) % 8;
	if ((buf.base = raft_calloc(1, buf.len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for buffer in %s\n", __func__);
		ret = 1;
		goto out;
	}*/

	// Message in message store on disk stored with network endianess
//	memcpy(buf.base, *message, MSG_TOTAL_SIZE(*message));
//	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) buf.base);
//	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf.base);

	assert(0 && "Raft apply not implemented");

/*
	if ((req = raft_malloc(sizeof(*req))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for request in %s\n", __func__);
		ret = 1;
		goto out;
	}
*/
//	req->data = state;
/*
	if ((ret_tmp = raft_apply(raft, req, &buf, 1, __rrr_raft_server_apply_cb)) != 0) {
		// It appears that this data is usually freed also
		// upon error conditions.
		buf.base = NULL;

		RRR_MSG_0("Apply failed in %s: %s\n", __func__, raft_errmsg(raft));
		ret = 1;
		goto out;
	}
	else {
		buf.base = NULL;
	}
*/
	goto out;
//	out_free_req:
//		raft_free(req);
	out_send_ctrl_msg:
		// Status messages are to be emitted before result messages
		__rrr_raft_server_send_msg_in_loop(state, &msg);
	out_send_msg_msg:
		if (msg_msg != NULL) {
			__rrr_raft_server_send_msg_in_loop(state, (struct rrr_msg *) msg_msg);
		}
	out:
		RRR_FREE_IF_NOT_NULL(msg_msg);
//		if (buf.base != NULL)
//			raft_free(buf.base);
		return ret;
}

static int __rrr_raft_server_msg_to_host (
		struct rrr_msg_msg *msg,
		rrr_length actual_length
) {
	(void)(msg);
	(void)(actual_length);

	int ret = 0;

//	rrr_length stated_length;
//	int ret_tmp;

	assert(0 && "server msg to host not implemented");

/*	if ((ret_tmp = rrr_msg_get_target_size_and_check_checksum (
			&stated_length,
			(struct rrr_msg *) msg,
			actual_length
	)) != 0) {
		RRR_MSG_0("Failed to get size of message in %s: %i\n", __func__, ret_tmp);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (actual_length < stated_length) {
		RRR_MSG_0("Actual length does not hold message stated size %" PRIrrrl "<%" PRIrrrl " in %s\n",
			actual_length, stated_length, __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify((struct rrr_msg *) msg, stated_length) != 0) {
		RRR_MSG_0("Header validation failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_check_data_checksum_and_length((struct rrr_msg *) msg, stated_length) != 0) {
		RRR_MSG_0("Data checksum validation failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify(msg, stated_length) != 0) {
		RRR_MSG_0("Message endian conversion failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}*/

	goto out;
	out:
	return ret;
}

static int __rrr_raft_server_buf_msg_to_host (
		struct rrr_msg_msg **msg,
//		const struct raft_buffer *buf
		const void *buf
) {
	(void)(msg);
	(void)(buf);

	assert(0 && "buf msg to host not implemented");
/*
	int ret = 0;

	struct rrr_msg_msg *msg_tmp;

	assert(buf->len >= sizeof(*msg_tmp) - 1);
	assert(buf->len <= UINT32_MAX);

	if ((msg_tmp = rrr_allocate(buf->len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for message in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	memcpy(msg_tmp, buf->base, buf->len);

	if ((ret = __rrr_raft_server_msg_to_host (msg_tmp, buf->len)) != 0) {
		goto out;
	}

	*msg = msg_tmp;
	msg_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;*/
	return 0;
}

static int __rrr_raft_server_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_state *state = arg2;

	(void)(arg1);

	struct rrr_msg msg = {0};

	assert(RRR_MSG_CTRL_F_HAS(message, RRR_MSG_CTRL_F_PING));

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);

	return __rrr_raft_server_send_msg_in_loop(state, &msg);
}

static void __rrr_raft_server_read_cb (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_raft_server_state *state = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp;
	uint64_t bytes_read_dummy;

	assert(!state->exiting);

	if ((ret_tmp = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&state->channel->read_sessions,
			state->channel->fd_server,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_raft_server_read_msg_cb,
			NULL,
			NULL,
			__rrr_raft_server_read_msg_ctrl_cb,
			NULL,
			NULL, /* first cb data */
			state
	)) != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		rrr_event_dispatch_break(state->channel->queue);
		state->exiting = 1;
	}
}

/*
static int __rrr_raft_server_fsm_apply_cb (
		struct raft_fsm *fsm,
		const struct raft_buffer *buf,
		void **result
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;
	int was_found;
	enum rrr_raft_code code = 0;
	uint32_t req_index;

	*result = NULL;

	assert(buf->len <= UINT32_MAX);

	if ((ret = __rrr_raft_server_buf_msg_to_host(&msg_tmp, buf)) != 0) {
		RRR_MSG_0("Message decoding failed in %s\n", __func__);
		goto out_critical;
	}

	req_index = msg_tmp->msg_value;

	RRR_DBG_3("Raft message %" PRIu32 " being applied in state machine in server %i\n",
		req_index, callback_data->server_id);

	if ((ret = rrr_raft_message_store_push (
			&was_found,
			callback_data->message_store_state,
			msg_tmp
	)) != 0) {
		RRR_MSG_0("Failed to push message to message store during application to state machine in server %i\n",
			callback_data->server_id);
		goto out_critical;
	}

	if ((MSG_IS_DEL(msg_tmp) || MSG_IS_PAT(msg_tmp)) && !was_found) {
		code = RRR_RAFT_ENOENT;
	}

	// If we are leader, the apply_cb giving feedback to
	// the client must see the message which has been applied
	// to the state machine.
	if (__rrr_raft_server_fsm_result_collection_push (
			&callback_data->fsm_results,
			req_index,
			&msg_tmp,
			code
	) != 0) {
		RRR_MSG_0("Failed to push result in %s\n", __func__);
		goto out_critical;
	}

	*result = rrr_ptr_from_biglength_bug_const(req_index);

	goto out_free;
	out_critical:
		assert(ret != 0);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
	out_free:
		RRR_FREE_IF_NOT_NULL(msg_tmp);
		return ret;
}

struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data {
	struct raft_buffer *bufs;
	size_t i;
};

static int __rrr_raft_server_fsm_message_store_snapshot_iterate_callback (
		const struct rrr_msg_msg *msg,
		void *arg
) {
	struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data *callback_data = arg;

	int ret = 0;

	struct raft_buffer *buf;
	
	buf = callback_data->bufs + callback_data->i;

	if ((buf->base = raft_malloc(MSG_TOTAL_SIZE(msg))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	memcpy(buf->base, msg, MSG_TOTAL_SIZE(msg));

	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) buf->base);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf->base);

	RRR_ASSERT(sizeof(buf->len) >= sizeof(MSG_TOTAL_SIZE(msg)),buf_len_must_hold_max_message_size);

	buf->len = MSG_TOTAL_SIZE(msg);

	callback_data->i++;

	out:
	return ret;
}

static int __rrr_raft_server_fsm_message_store_snapshot (
		struct raft_buffer *res_bufs[],
		unsigned *res_n_bufs,
		struct rrr_raft_server_state *callback_data
) {
	struct rrr_raft_message_store *store = callback_data->message_store_state;

	int ret = 0;

	struct raft_buffer *bufs, *buf;
	size_t count, i;

	count = rrr_raft_message_store_count(store);

	if ((bufs = raft_calloc(1, sizeof(*bufs) * count)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data iterate_callback_data = {
		bufs,
		0
	};

	if ((ret = rrr_raft_message_store_iterate (
			store,
			__rrr_raft_server_fsm_message_store_snapshot_iterate_callback,
			&iterate_callback_data
	)) != 0) {
		goto out_free;
	}

	assert(iterate_callback_data.i == count);

	*res_bufs = bufs;
	*res_n_bufs = count;

	goto out;
	out_free:
		for (i = 0; i < count; i++) {
			if ((buf = bufs + i) == NULL)
				break;
			raft_free(buf->base);
		}
		raft_free(bufs);
	out:
		return ret;
}

static int  __rrr_raft_server_fsm_snapshot_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *bufs[],
		unsigned *n_bufs
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	RRR_DBG_3("Raft insert snapshot server %i\n", callback_data->server_id);

	return __rrr_raft_server_fsm_message_store_snapshot (bufs, n_bufs, callback_data);
}

static int __rrr_raft_server_fsm_restore_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *buf
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg;
	size_t pos;
	int was_found;

	assert(buf->len <= UINT32_MAX);

	RRR_DBG_3("Raft restore snapshot server %i\n", callback_data->server_id);

	for (pos = 0; pos < buf->len; rrr_size_t_add_bug(&pos, MSG_TOTAL_SIZE(msg))) {
		assert(buf->len - pos >= sizeof(struct rrr_msg_msg) - 1);

		msg = (void *) buf->base + pos;

		if ((ret = __rrr_raft_server_msg_to_host(msg, buf->len)) != 0) {
			RRR_MSG_0("Message decoding failed in %s\n", __func__);
			goto out;
		}

		RRR_DBG_3("Raft message %i being applied in state machine in server %i during restore\n",
			msg->msg_value, callback_data->server_id);

		if ((ret = rrr_raft_message_store_push (
				&was_found,
				callback_data->message_store_state,
				msg
		)) != 0) {
			RRR_MSG_0("Message push failed in %s\n", __func__);
			goto out;
		}
	}

	assert(pos == buf->len);

	// Only free upon successful return value
	raft_free(buf->base);

	out:
	return ret;
}

*/

struct rrr_raft_server_file_read_cb_data {
	int fd;
};

static ssize_t __rrr_raft_server_file_read_cb (RRR_RAFT_BRIDGE_READ_FILE_CB_ARGS) {
	struct rrr_raft_server_state *state = cb_data->ptr;
	struct rrr_raft_server_file_read_cb_data *file_read_cb_data = (struct rrr_raft_server_file_read_cb_data *) cb_data->data;

	ssize_t bytes;

	if (file_read_cb_data->fd <= 0) {
		if ((file_read_cb_data->fd = rrr_socket_open(name, O_RDONLY, 0777, __func__, 0)) <= 0) {
			if (errno == ENOENT) {
				RRR_RAFT_SERVER_DBG_FILE(name, "file does not exist while opening for reading%s", "");
				bytes = 0;
				goto out;
			}

			RRR_MSG_0("Failed to open file %s for reading in %s: %s\n", name, __func__, rrr_strerror(errno));
			bytes = -1;
			goto out;
		}

		RRR_RAFT_SERVER_DBG_FILE(name, "opened file for reading%s", "");
	}

	assert(buf_size > 0);

	if ((bytes = read(file_read_cb_data->fd, buf, buf_size)) < 0) {
		RRR_MSG_0("Failed to read in %s: %s\n", __func__, rrr_strerror(errno));
		bytes = -1;
		goto out;
	}
	else if (bytes == 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "closing file after reading%s", "");
		assert(file_read_cb_data->fd > 0);
		goto out;
	}

	out:
	return bytes;
}

struct rrr_raft_server_file_write_cb_data {
	int fd;
};

static ssize_t __rrr_raft_server_file_write_cb (RRR_RAFT_BRIDGE_WRITE_FILE_CB_ARGS) {
	struct rrr_raft_server_state *state = cb_data->ptr;
	struct rrr_raft_server_file_write_cb_data *file_write_cb_data = (struct rrr_raft_server_file_write_cb_data *) cb_data->data;

	ssize_t bytes;

	if (file_write_cb_data->fd <= 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "open file to write %llu bytes", (unsigned long long) data_size);

		if ((file_write_cb_data->fd = rrr_socket_open(name, O_CREAT|O_TRUNC|O_RDWR|O_SYNC, 0777, __func__, 0)) <= 0) {
			RRR_MSG_0("Failed to open file %s for writing in %s: %s\n", name, __func__, rrr_strerror(errno));
			bytes = -1;
			goto out;
		}
	}

	if (data_size == 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "closing file after writing%s", "");
		assert(file_write_cb_data->fd > 0);
		rrr_socket_close(file_write_cb_data->fd);
		bytes = 0;
		goto out;
	}

	if ((bytes = write(file_write_cb_data->fd, data, data_size)) <= 0) {
		RRR_MSG_0("Failed to write to file in %s: %s\n", __func__, rrr_strerror(errno));
		bytes = -1;
		goto out;
	}

	out:
	return bytes;
}

static int __rrr_raft_server_connection_data_create (
		struct rrr_raft_server_connection **result_connection,
		raft_id server_id,
		const struct sockaddr *sockaddr,
		socklen_t socklen
) {
	int ret = 0;

	char buf[256];
	uint16_t port;
	struct rrr_raft_server_connection *connection;
	struct sockaddr_storage sockaddr_storage;
	struct sockaddr *sockaddr_clean = (struct sockaddr *) &sockaddr_storage;
	socklen_t socklen_clean;

	memcpy(sockaddr_clean, sockaddr, socklen);
	socklen_clean = socklen;

	// Make sure we don't end up having any ::ffff: prefix in the server_address string
	rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed_alt(sockaddr_clean, &socklen_clean);

	rrr_ip_to_str_and_port (
			&port,
			buf,
			sizeof(buf),
			sockaddr_clean,
			socklen_clean
	);

	if ((ret = __rrr_raft_server_connection_new (
			&connection,
			server_id,
			buf,
			port
	)) != 0) {
		goto out;
	}

	*result_connection = connection;

	out:
	return ret;
}

static void __rrr_raft_server_connection_data_bind (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		struct rrr_raft_server_connection *connection
) {
	rrr_net_transport_handle_application_data_bind (
			transport,
			transport_handle,
			connection,
			__rrr_raft_server_connection_destroy_void
	);
}

struct rrr_raft_server_net_connect_callback_data {
	rrr_net_transport_handle result_handle;
	struct sockaddr_storage result_sockaddr;
	socklen_t result_socklen;
};

static void __rrr_raft_server_net_connect_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *callback_arg
) {
	struct rrr_raft_server_net_connect_callback_data *callback_data = callback_arg;

	memcpy(&callback_data->result_sockaddr, addr, addr_len);
	callback_data->result_socklen = addr_len;
	callback_data->result_handle = RRR_NET_TRANSPORT_CTX_HANDLE(handle);
}

static ssize_t __rrr_raft_server_message_send_cb (RRR_RAFT_BRIDGE_SEND_MESSAGE_CB_ARGS) {
	struct rrr_raft_server_state *state = cb_data->ptr;

	static int test_busy = 0;

	char *server_hostname = NULL;
	uint16_t server_port;
	rrr_net_transport_handle transport_handle;
	ssize_t bytes = 0;
	int ret_tmp;
	struct rrr_raft_server_connection *connection;

	if (++test_busy == 1) {
		bytes = -RRR_RAFT_READ_BUSY;
		goto out;
	}

	if (!((transport_handle = rrr_net_transport_handle_get_by_match (
			state->net_transport,
			"x",
			server_id
	)) > 0)) {
		if ((ret_tmp = rrr_ip_address_string_split (
				&server_hostname,
				&server_port,
				server_address
		)) != 0) {
			goto out;
		}

		struct rrr_raft_server_net_connect_callback_data callback_data = {0};

		if ((ret_tmp = rrr_net_transport_connect (
				state->net_transport,
				server_port,
				server_hostname,
				__rrr_raft_server_net_connect_callback,
				&callback_data
		)) != 0) {
			RRR_RAFT_SERVER_ERR_NET(server_address, "error %i while connecting", ret_tmp);
			bytes = -RRR_RAFT_READ_SOFT_ERROR;
			goto out;
		}

		assert(callback_data.result_handle > 0);
		assert(callback_data.result_socklen > 0);

		if ((ret_tmp = __rrr_raft_server_connection_data_create (
				&connection,
				server_id,
				(const struct sockaddr *) &callback_data.result_sockaddr,
				callback_data.result_socklen
		)) != 0) {
			RRR_MSG_0("Failed to create connection data in %s\n", __func__);
			bytes = -RRR_RAFT_READ_HARD_ERROR;
			goto out;
		}

		printf("Created outvound connection data %p\n", connection);

		__rrr_raft_server_connection_data_bind (
				state->net_transport,
				callback_data.result_handle,
				connection
		);

		RRR_RAFT_SERVER_DBG_NET(connection->server_address, "connection established to remote server%s", "");

		transport_handle = callback_data.result_handle;
	}

	if ((ret_tmp = rrr_net_transport_handle_send_push_const (
			state->net_transport,
			transport_handle,
			data,
			data_size
	)) != 0) {
		if (ret_tmp == RRR_SOCKET_NOT_READY) {
			RRR_RAFT_SERVER_DBG_NET(server_address, "connection not yet ready%s", "");
			bytes = -RRR_RAFT_READ_BUSY;
			goto out;
		}
		else if (ret_tmp == RRR_SOCKET_SOFT_ERROR) {
			RRR_RAFT_SERVER_ERR_NET(server_address, "soft error while connecting%s", "");
			bytes = -RRR_RAFT_READ_SOFT_ERROR;
			goto out;
		}

		RRR_RAFT_SERVER_ERR_NET(server_address, "hard error %i while connecting", ret_tmp);
		bytes = -RRR_RAFT_READ_HARD_ERROR;
		goto out;
	}

	bytes = (ssize_t) data_size;

	out:
	return bytes;
}

static int __rrr_raft_server_process_tasks (
		struct rrr_raft_server_state *state
) {
	struct rrr_raft_task_list *list = state->tasks;

	int ret = 0;

	uint64_t diff, now;
	struct rrr_raft_task *task, *tasks;
	struct rrr_raft_server_file_write_cb_data *file_write_cb_data;
	struct rrr_raft_server_file_read_cb_data *file_read_cb_data;

	if (list->count == 0) {
		goto out;
	}

	tasks = rrr_raft_task_list_get(list);

	now = rrr_time_get_64() / 1000;

	for (size_t i = 0; i < list->count; i++) {
		task = tasks + i;

		switch (task->type) {
			case RRR_RAFT_TASK_TIMEOUT:
				diff = task->timeout.time - now;
				if (diff >= task->timeout.time) {
					diff = 10000;
				}

				RRR_RAFT_SERVER_DBG_EVENT("set timeout to %" PRIu64 " ms", diff);
				EVENT_INTERVAL_SET(state->events.raft_timeout, diff * 1000);
				EVENT_ADD(state->events.raft_timeout);
				break;
			case RRR_RAFT_TASK_READ_FILE:
				// TODO : Read actual file
				RRR_RAFT_SERVER_DBG_EVENT("set read file cb for type %i '%s'",
					task->readfile.type, (char *) rrr_raft_task_list_resolve(list, task->readfile.name));
				RRR_ASSERT(sizeof(file_read_cb_data) <= sizeof(task->readfile.cb_data.data),cb_data_must_hold_server_cb_data);
				file_read_cb_data = (struct rrr_raft_server_file_read_cb_data *) task->readfile.cb_data.data;
				file_read_cb_data->fd = -1;
				task->readfile.read_cb = __rrr_raft_server_file_read_cb;
				task->readfile.cb_data.ptr = state;
				break;
			case RRR_RAFT_TASK_BOOTSTRAP:
				task->bootstrap.configuration = state->configuration;
				break;
			case RRR_RAFT_TASK_WRITE_FILE:
				RRR_RAFT_SERVER_DBG_EVENT("set write file cb for type %i '%s'",
					task->writefile.type, (char *) rrr_raft_task_list_resolve(list, task->writefile.name));
				RRR_ASSERT(sizeof(file_write_cb_data) <= sizeof(task->writefile.cb_data.data),cb_data_must_hold_server_cb_data);
				file_write_cb_data = (struct rrr_raft_server_file_write_cb_data *) task->writefile.cb_data.data;
				file_write_cb_data->fd = -1;
				task->writefile.write_cb = __rrr_raft_server_file_write_cb;
				task->writefile.cb_data.ptr = state;
				break;
			case RRR_RAFT_TASK_SEND_MESSAGE:
				if (task->sendmessage.cb_data.ptr != NULL) {
					RRR_RAFT_SERVER_DBG_EVENT("send message to server %llu (retry)",
						(unsigned long long) task->sendmessage.server_id);
					assert (task->sendmessage.send_cb == __rrr_raft_server_message_send_cb);
					assert (task->sendmessage.cb_data.ptr == state);
				}
				else {
					RRR_RAFT_SERVER_DBG_EVENT("send message to server %llu",
						(unsigned long long) task->sendmessage.server_id);
					task->sendmessage.send_cb = __rrr_raft_server_message_send_cb;
					task->sendmessage.cb_data.ptr = state;
				}
				break;
			default:
				RRR_BUG("BUG: Unknown task type %i in %s\n",
					task->type, __func__);
		};
	}

	out:
	return ret;
}

static int __rrr_raft_server_process_and_acknowledge (
		struct rrr_raft_server_state *state
) {
	int ret = 0;

	struct rrr_raft_task *task;

	if ((ret = __rrr_raft_server_process_tasks(state)) != 0) {
		goto out;
	}

	if ((ret = rrr_raft_bridge_acknowledge(state->tasks, state->bridge)) != 0) {
		goto out;
	}

	assert(state->tasks->count > 0);

	task = rrr_raft_task_list_get(state->tasks);

	if (task->type != RRR_RAFT_TASK_TIMEOUT) {
		// TODO : Consider tight loop instead of activating timeout
		EVENT_ACTIVATE(state->events.raft_timeout);
	}

	out:
	return ret;
}

static void __rrr_raft_server_timeout_cb (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_raft_server_state *state = arg;

	(void)(fd);
	(void)(flags);

	assert(!state->exiting);

	if (__rrr_raft_server_process_and_acknowledge (state) != 0) {
		rrr_event_dispatch_break(state->channel->queue);
		state->exiting = 1;
	}
}

static void __rrr_raft_server_net_accept_callback (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS
) {
	struct rrr_raft_server_state *state = arg;

	struct rrr_raft_server_connection *connection;

	if (__rrr_raft_server_connection_data_create (
			&connection,
			0,
			sockaddr,
			socklen
	) != 0) {
		RRR_RAFT_SERVER_ERR_NET(connection->server_address, "failed to create connection data in %s, connection will be closed", __func__);
		return;
	}

	RRR_RAFT_SERVER_DBG_NET(connection->server_address, "accepted connection from remote server%s", "");

	__rrr_raft_server_connection_data_bind (
			state->net_transport,
			RRR_NET_TRANSPORT_CTX_HANDLE(handle),
			connection
	);
}

static int __rrr_raft_server_net_handshake_complete_callback (
		RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS
) {
	struct rrr_raft_server_connection *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);
	struct rrr_raft_server_state *state = arg;

	int ret = 0;

	raft_id server_id;

	if (connection == NULL) {
		// Error occured in accept callback if connection is
		// not set, and we must close the connection.
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	if ((server_id = rrr_raft_bridge_configuration_server_id_get (
			state->bridge,
			connection->server_address
	)) == 0) {
		RRR_RAFT_SERVER_ERR_NET(connection->server_address, "connection from unknown remote server%s", "");
		goto out;
	}

	connection->server_id = server_id;

	out:
	return ret;
}

struct rrr_raft_server_net_read_callback_data {
	struct rrr_raft_server_state *state;
	struct rrr_net_transport_handle *handle;
	struct rrr_raft_server_connection *connection;
};

static int __rrr_raft_server_net_read_get_target_size_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_raft_server_net_read_callback_data *callback_data = arg;
	struct rrr_raft_server_state *state = callback_data->state;
	struct rrr_raft_server_connection *connection = callback_data->connection;

	int ret = RRR_READ_INCOMPLETE;

	const char *data;
	size_t data_size;
	ssize_t bytes;

	data = read_session->rx_buf_ptr;
	if (rrr_size_from_biglength_err(&data_size, read_session->rx_buf_wpos) != 0) {
		RRR_RAFT_SERVER_ERR_NET(connection->server_address,
			"Read buffer overflow when reading RPC, closing connection.\n%s", "");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if ((bytes = rrr_raft_bridge_read (
			state->bridge,
			connection->server_id,
			connection->server_address,
			data,
			data_size
	)) < 0) {
		RRR_RAFT_SERVER_ERR_NET(connection->server_address,
			"Error while reading RPC, closing connection.\n%s", "");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}
	else if (bytes > 0) {
		read_session->target_size = (rrr_biglength) bytes;
		ret = RRR_READ_OK;
		goto out;
	}

	out:
	return ret;
}

static void __rrr_raft_server_net_read_get_target_size_error_callback (
		struct rrr_read_session *read_session,
		int is_hard_err,
		void *arg
) {
	struct rrr_raft_server_net_read_callback_data *callback_data = arg;

	(void)(read_session);
	(void)(is_hard_err);
	(void)(callback_data);

	// Any error message goes here
}

static int __rrr_raft_server_net_read_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_raft_server_net_read_callback_data *callback_data = arg;

	(void)(read_session);
	(void)(callback_data);

	// Nothing to do

	return RRR_READ_OK;
}

static int __rrr_raft_server_net_read_callback (
		RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS
) {
	struct rrr_raft_server_state *state = arg;
	struct rrr_raft_server_connection *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle);

	int ret = 0;

	struct rrr_raft_server_net_read_callback_data callback_data = {
		.state = state,
		.handle = handle,
		.connection = connection
	};

	if ((ret = rrr_net_transport_ctx_read_message (
			handle,
			4096,            /* 4 kB read step initial */
			1 * 1024 * 1024, /* 1 MB read step max size */
			0,               /*   no read max size */
			0,               /*   no ratelimit interval */
			0,               /*   no ratelimit max bytes */
			__rrr_raft_server_net_read_get_target_size_callback,
			&callback_data,
			__rrr_raft_server_net_read_get_target_size_error_callback,
			&callback_data,
			__rrr_raft_server_net_read_complete_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_raft_server_net_tick_callback (
		RRR_NET_TRANSPORT_TICK_CALLBACK_ARGS
) {
	int ret = 0;

	assert(0 && "net tick callback not implemented");

	out:
	return ret;
}

void __rrr_raft_server_listen_ipv4_and_ipv6_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	const char *server_address = arg;

	(void)(handle);

	RRR_DBG_1("Raft server now listening for incoming connections on %s\n", server_address);
}

static int __rrr_raft_server_net_transport_setup (
		struct rrr_net_transport **net_transport,
		struct rrr_raft_server_state *state,
		struct rrr_event_queue *queue,
		const char *server_address
) {
	int ret = 0;

	char *host;
	uint16_t port;

	if ((ret = rrr_ip_address_string_split (
			&host,
			&port,
			server_address
	)) != 0) {
		goto out;
	}

	struct rrr_net_transport_config net_transport_config = {
		.transport_type_p = RRR_NET_TRANSPORT_PLAIN
	};

	if ((ret = rrr_net_transport_new (
			net_transport,
			&net_transport_config,
			"raft server",
			0,
			queue,
			NULL,
			0,
			RRR_RAFT_SERVER_NET_FIRST_READ_TIMEOUT_S * 1000,
			RRR_RAFT_SERVER_NET_TICK_INTERVAL_S * 1000,
			RRR_RAFT_SERVER_NET_HARD_TIMEOUT_S * 1000,
			RRR_RAFT_SERVER_NET_SEND_CHUNK_COLLECTION_LIMIT,
			__rrr_raft_server_net_accept_callback,
			state,
			__rrr_raft_server_net_handshake_complete_callback,
			state,
			__rrr_raft_server_net_read_callback,
			state,
			__rrr_raft_server_net_tick_callback,
			state,
			NULL,
			NULL
	)) != 0) {
		RRR_MSG_0("Failed to create net transport in %s\n", __func__);
		goto out_free;
	}

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			*net_transport,
			port,
			__rrr_raft_server_listen_ipv4_and_ipv6_callback,
			server_address
	)) != 0) {
		ret = 1;
		goto out_destroy_net_transport;
	}

	goto out_free;
	out_destroy_net_transport:
		rrr_net_transport_destroy(*net_transport);
	out_free:
		rrr_free(host);
	out:
		return ret;
}

int rrr_raft_server (
		struct rrr_raft_channel *channel,
		const char *log_prefix,
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
	int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
) {
	int ret = 0;

	int was_found, ret_tmp;
	int channel_fds[2];
	size_t cleared_count;
	struct raft raft = {0};
	struct raft_configuration configuration;
	struct rrr_raft_server_fsm_result_collection fsm_results = {0};
	struct rrr_raft_server_state state = {0};
	struct rrr_raft_message_store *message_store_state;
	struct rrr_event_collection events = {0};
	struct rrr_raft_bridge bridge = {0};
	struct rrr_raft_task_list tasks_work = {0}, tasks_persistent = {0};
	struct rrr_net_transport *net_transport;
	static struct raft_heap rrr_raft_heap = {
		NULL,                            /* data */
		__rrr_raft_server_malloc,        /* malloc */
		__rrr_raft_server_free,          /* free */
		__rrr_raft_server_calloc,        /* calloc */
		__rrr_raft_server_realloc,       /* realloc */
		__rrr_raft_server_aligned_alloc, /* aligned_alloc */
		__rrr_raft_server_aligned_free   /* aligned_free */
	};

	RRR_DBG_1("Starting raft server %i dir %s address %s\n",
		servers[servers_self].id, dir, servers[servers_self].address);

	rrr_raft_channel_fds_get(channel_fds, channel);
	// rrr_socket_close_all_except_array_no_unlink(channel_fds, sizeof(channel_fds)/sizeof(channel_fds[0]));

	// TODO : Send logs on socket. XXX also enable unregister on function out
	// rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_raft_server_log_hook, channel, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
	assert(was_found);
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	rrr_config_set_log_prefix(log_prefix);

	rrr_event_collection_init(&events, channel->queue);

	if ((ret = rrr_event_collection_push_periodic (
			&state.events.raft_timeout,
			&events,
			__rrr_raft_server_timeout_cb,
			&state,
			1 * 10 * 1000 // Initial timeout 10 ms
	)) != 0) {
		RRR_MSG_0("Failed to create timeout event in %s\n", __func__);
		goto out_cleanup_events;
	}

	EVENT_ADD(state.events.raft_timeout);

	if ((ret = rrr_event_collection_push_read (
			&state.events.socket,
			&events,
			channel->fd_server,
			__rrr_raft_server_read_cb,
			&state,
			1 * 1000 * 1000 // 1 second timeout
	)) != 0) {
		RRR_MSG_0("Failed to create read event in %s\n", __func__);
		goto out_cleanup_events;
	}

	EVENT_ADD(state.events.socket);

	if (chdir(dir) != 0) {
		RRR_MSG_0("Failed to change directory to %s in %s: %s\n", dir, __func__, rrr_strerror(errno));
		ret = 1;
		goto out_cleanup_events;
	}

	if ((ret = rrr_raft_message_store_new (&message_store_state, patch_cb)) != 0) {
		goto out_cleanup_events;
	}

	if ((ret = __rrr_raft_server_net_transport_setup (
			&net_transport,
			&state,
			channel->queue,
			servers[servers_self].address
	)) != 0) {
		goto out_destroy_message_store;
	}

	state.channel = channel;
	state.message_store_state = message_store_state;
	state.fsm_results = &fsm_results;
	state.configuration = &configuration;
	state.net_transport = net_transport;

	bridge.raft = &raft;
	bridge.server_id = servers[servers_self].id;
	state.bridge = &bridge;
	state.tasks = &tasks_work;

	raft_heap_set(&rrr_raft_heap);

	if ((ret_tmp = raft_init (
			&raft,
			NULL,
			NULL,
			servers[servers_self].id,
			servers[servers_self].address
	)) != 0) {
		RRR_MSG_0("Failed to initialize raft in %s: %s: %s\n", __func__,
			raft_strerror(ret_tmp), raft_errmsg(&raft));
		ret = 1;
		goto out_destroy_net_transport;
	}

	raft_seed(&raft, rrr_rand());

	raft_configuration_init(&configuration);

	for (; servers->id > 0; servers++) {
		if ((ret_tmp = raft_configuration_add (
				&configuration,
				servers->id,
				servers->address,
				RAFT_VOTER
		)) != 0) {
			RRR_MSG_0("Failed to add to raft configuration in %s: %s\n", __func__,
				raft_strerror(ret_tmp));
			ret = 1;
			goto out_cleanup_configuration;
		}
	}
/*
	if ((ret_tmp = raft_bootstrap(&raft, &configuration)) != 0 && ret_tmp != RAFT_CANTBOOTSTRAP) {
		RRR_MSG_0("Failed to bootstrap raft in %s: %s\n",
			__func__, raft_strerror(ret_tmp));
		goto out_raft_callback_data_cleanup;
	}

	raft_set_snapshot_threshold(&raft, 32);
	raft_set_snapshot_trailing(&raft, 16);
	raft_set_pre_vote(&raft, true);

	uv_handle_set_data((uv_handle_t *) &poll_server, &callback_data);

	if ((ret_tmp = raft_start(&raft)) != 0) {
		RRR_MSG_0("Failed to start raft: %s\n", raft_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	ret_tmp = uv_run(&loop, UV_RUN_DEFAULT);
*/

	if ((ret = rrr_raft_bridge_begin(&tasks_work, &bridge, &tasks_persistent)) != 0) {
		goto out_cleanup_configuration;
	}

	if ((ret = __rrr_raft_server_process_and_acknowledge(&state)) != 0) {
		goto out_cleanup_bridge;
	}

	ret = rrr_event_dispatch(channel->queue);

	RRR_DBG_1("Event loop completed in raft server, result was %i\n", ret_tmp);

	// TODO : Some expected results are registered when messages are restored and applied, and
	//        in those cases the final apply callback is never called and the results persists.
	//        This might not matter as restoration only happens during startup, but we have to
	//        search past those results each time. Maybe deal with this situation.
	__rrr_raft_server_fsm_result_collection_clear(&cleared_count, &fsm_results);
	RRR_DBG_1("Cleared %llu expected results in raft server %i\n",
		cleared_count, state.bridge->server_id);

	goto out_cleanup_bridge;
	out_cleanup_bridge:
		rrr_raft_bridge_cleanup(&bridge);
//	out_cleanup_tasks:
		rrr_raft_task_list_cleanup(&tasks_work);
		rrr_raft_task_list_cleanup(&tasks_persistent);
	out_cleanup_configuration:
		raft_configuration_close(&configuration);
//	out_raft_close:
		raft_close(&raft, NULL);
//	out_cleanup_fsm_results:
		__rrr_raft_server_fsm_result_collection_clear(&cleared_count, &fsm_results);
	out_destroy_net_transport:
		rrr_net_transport_destroy(net_transport);
	out_destroy_message_store:
		rrr_raft_message_store_destroy(message_store_state);
	out_cleanup_events:
		rrr_event_collection_clear(&events);
//	out:
		// TODO : Enable once handle is registered
		// rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());

/*		if (req != NULL) {
			raft_free(req);
		}*/

		return ret;
}
