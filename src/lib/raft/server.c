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

#include <uv.h>
#include <raft.h>
#include <raft/uv.h>
#include <unistd.h>

#include "server.h"
#include "common.h"
#include "channel.h"
#include "channel_struct.h"
#include "message_store.h"

#include "../allocator.h"
#include "../array.h"
#include "../fork.h"
#include "../common.h"
#include "../rrr_strerror.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../util/rrr_time.h"

struct rrr_raft_server_callback_data {
	struct rrr_raft_channel *channel;
	int ret;
	uv_loop_t *loop;
	struct raft *raft;
	int server_id;
	struct rrr_raft_message_store *message_store_state;
	uint32_t change_req_index;
	uint32_t transfer_req_index;
	struct raft_change change_req;
	struct raft_transfer transfer_req;
};

static int __rrr_raft_server_send_msg_in_loop (
		struct rrr_raft_channel *channel,
		uv_loop_t *loop,
		struct rrr_msg *msg
);

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

static void __rrr_raft_server_tracer_emit_cb (
		struct raft_tracer *t,
		int type,
		const void *info
) {
	struct rrr_raft_server_callback_data *callback_data = t->impl;

	(void)(t);
	(void)(info);
	(void)(type);
	(void)(callback_data);

	// TODO : Not useful until message is extended. Also find
	//        appropriate debuglevel.
	// RRR_DBG_1("tracer server %i: %i\n", callback_data->server_id, type);
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

static int __rrr_raft_server_make_opt_response_server_fields (
		struct rrr_array *array,
		struct raft *raft
) {
	int ret = 0;

	struct rrr_raft_server server_tmp;
	struct raft_server *raft_server;
	int ret_tmp, catch_up;
	unsigned i;
	size_t address_len;

	for (i = 0; i < raft->configuration.n; i++) {
		server_tmp = (struct rrr_raft_server) {0};

		raft_server = raft->configuration.servers + i;
		address_len = strlen(raft_server->address);

		assert(address_len < sizeof(server_tmp.address));
		memcpy(server_tmp.address, raft_server->address, address_len + 1);

		server_tmp.id = raft_server->id;

		switch (raft_server->role) {
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
				RRR_BUG("Unknown role %i in %s\n", raft_server->role, __func__);
		};

		if (raft->state == RAFT_LEADER) {
			if ((ret_tmp = raft_catch_up (raft, raft_server->id, &catch_up)) != 0) {
				RRR_MSG_0("Failed to get catch up status for server %i in %s: %s %s\n",
					raft_server->id, __func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}

			switch (catch_up) {
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
		}
		else {
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_UNKNOWN;
		}

		if ((ret = rrr_raft_opt_array_field_server_push (
				array,
				&server_tmp
		)) != 0) {
			RRR_MSG_0("Failed to push server in %s\n", __func__);
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_raft_server_make_opt_response (
		struct rrr_msg_msg **result,
		struct raft *raft,
		rrr_u32 req_index
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;
	struct rrr_array array_tmp = {0};
	raft_id leader_id;
	const char *leader_address;

	*result = NULL;

	raft_leader(raft, &leader_id, &leader_address);

	ret |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_IS_LEADER,
			raft->state == RAFT_LEADER
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
			raft
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

static void __rrr_raft_server_change_cb_final (
		struct rrr_raft_server_callback_data *callback_data,
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
	struct rrr_raft_server_callback_data *callback_data = req->data;

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
	struct rrr_raft_server_callback_data *callback_data = req->data;
	struct raft *raft = callback_data->raft;

	const char *address;
	raft_id id;
	enum rrr_raft_code code = RRR_RAFT_ERROR;

	assert(callback_data->transfer_req_index > 0);

	raft_leader(raft, &id, &address);

	if (id != (long long unsigned) callback_data->server_id) {
		RRR_DBG_1("Leader transfer OK to %llu %s\n", id, address);
	}
	else {
		RRR_DBG_1("Leader transfer NOT OK to %llu %s\n", id, address);
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

static int __rrr_raft_server_handle_cmd (
		struct rrr_raft_server_callback_data *callback_data,
		rrr_u32 req_index,
		const struct rrr_msg_msg *msg
) {
	struct raft *raft = callback_data->raft;

	int ret = 0;

	struct rrr_array array_tmp = {0};
	int ret_tmp, role;
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

			assert(callback_data->change_req.data == NULL && callback_data->change_req_index == 0);
			callback_data->change_req.data = callback_data;
			callback_data->change_req_index = req_index;
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

			assert(callback_data->transfer_req.data == NULL && callback_data->transfer_req_index == 0);

			callback_data->transfer_req.data = callback_data;
			callback_data->transfer_req_index = req_index;
		} break;
		default:
			RRR_BUG("BUG: Unknown command %" PRIi64 " in %s\n", cmd, __func__);
	};

	// Switch 2 of 2 (execution)
	switch (cmd) {
		case RRR_RAFT_CMD_SERVER_ASSIGN: {
			switch (servers[0].status) {
				case RRR_RAFT_STANDBY:
					role = RAFT_STANDBY;
					break;
				case RRR_RAFT_VOTER:
					role = RAFT_VOTER;
					break;
				case RRR_RAFT_SPARE:
					role = RAFT_SPARE;
					break;
				default:
					RRR_BUG("BUG: Unknown state %i in %s\n",
						servers[0].status, __func__);
			};

			if ((ret_tmp = raft_assign (
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
			}
		} break;
		case RRR_RAFT_CMD_SERVER_ADD: {
			RRR_DBG_1("Raft CMD add server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			if ((ret_tmp = raft_add (
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
			}
		} break;
		case RRR_RAFT_CMD_SERVER_DEL: {
			RRR_DBG_1("Raft CMD delete server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			if ((ret_tmp = raft_remove (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server delete failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}
		} break;
		case RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER: {
			RRR_DBG_1("Raft CMD transfer leadership to %" PRIi64 "\n", id);

			if ((ret_tmp = raft_transfer (
					raft,
					&callback_data->transfer_req,
					rrr_int_from_slength_bug_const(id),
					__rrr_raft_server_leadership_transfer_cb
			)) != 0) {
				RRR_MSG_0("Server leadership transfer failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}
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

static void __rrr_raft_server_apply_cb (
		struct raft_apply *req,
		int status,
		void *result
) {
	struct rrr_raft_server_callback_data *callback_data = req->data;
	struct rrr_msg_msg *msg_orig = result;

	struct rrr_msg msg_ack = {0};
	enum rrr_raft_code code = __rrr_raft_server_status_translate(status);

	if (code != 0) {
		if (code != RRR_RAFT_NOT_LEADER) {
			RRR_MSG_0("Warning: Apply error: %s (%d)\n",
				raft_errmsg(callback_data->raft), status);
		}
		goto nack;
	}

	goto ack;
	ack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_ACK, msg_orig->msg_value);
		goto send_msg;
	nack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_NACK_REASON(code), msg_orig->msg_value);
		goto send_msg;

	send_msg:
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);

	goto out;
	out:
		rrr_free(result);
		raft_free(req);
}

static int __rrr_raft_server_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_callback_data *callback_data = arg2;
	struct raft *raft = callback_data->raft;

	(void)(arg1);

	int ret = 0;

	int ret_tmp;
	struct raft_buffer buf = {0};
	struct raft_apply *req;
	struct rrr_msg msg = {0};
	struct rrr_msg_msg *msg_msg = NULL;

	assert((*message)->msg_value > 0);

	if (MSG_IS_OPT(*message)) {
		if (MSG_IS_ARRAY(*message)) {
			ret = __rrr_raft_server_handle_cmd (
					callback_data,
					(*message)->msg_value,
					(*message)
			);
			goto out;
		}

		if ((ret = __rrr_raft_server_make_opt_response (
				&msg_msg,
				raft,
				(*message)->msg_value
		)) != 0) {
			goto out;
		}

		goto out_send_msg_msg;
	}

	if (MSG_IS_GET(*message)) {
		if ((ret = __rrr_raft_server_make_get_response (
				&msg_msg,
				callback_data->message_store_state,
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

	if (raft->state != RAFT_LEADER) {
		RRR_MSG_0("Warning: Refusing message to be stored. Not leader.\n");
		rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_NACK_REASON(RRR_RAFT_NOT_LEADER), (*message)->msg_value);
		goto out_send_ctrl_msg;
	}

	buf.len = MSG_TOTAL_SIZE(*message) + 8 - MSG_TOTAL_SIZE(*message) % 8;
	if ((buf.base = raft_calloc(1, buf.len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for buffer in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// Message in message store on disk stored with network endianess
	memcpy(buf.base, *message, MSG_TOTAL_SIZE(*message));
	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) buf.base);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf.base);

	if ((req = raft_malloc(sizeof(*req))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for request in %s\n", __func__);
		ret = 1;
		goto out;
	}

	req->data = callback_data;

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

	goto out;
//	out_free_req:
//		raft_free(req);
	out_send_ctrl_msg:
		// Status messages are to be emitted before result messages
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg);
	out_send_msg_msg:
		if (msg_msg != NULL) {
			__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, (struct rrr_msg *) msg_msg);
		}
	out:
		RRR_FREE_IF_NOT_NULL(msg_msg);
		if (buf.base != NULL)
			raft_free(buf.base);
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
		struct rrr_raft_channel *channel,
		uv_loop_t *loop,
		struct rrr_msg *msg
) {
	int ret = 0;

	if ((ret = __rrr_raft_server_send_msg(channel, msg)) != 0) {
		if (ret == RRR_READ_EOF) {
			uv_stop(loop);
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

static int __rrr_raft_server_msg_to_host (
		struct rrr_msg_msg *msg,
		rrr_length actual_length
) {
	int ret = 0;

	rrr_length stated_length;
	int ret_tmp;

	if ((ret_tmp = rrr_msg_get_target_size_and_check_checksum (
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
	}

	out:
	return ret;
}

static int __rrr_raft_server_buf_msg_to_host (
		struct rrr_msg_msg **msg,
		const struct raft_buffer *buf
) {
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
	return ret;
}

static int __rrr_raft_server_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_callback_data *callback_data = arg2;

	(void)(arg1);

	struct rrr_msg msg = {0};

	assert(RRR_MSG_CTRL_F_HAS(message, RRR_MSG_CTRL_F_PING));

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);

	return __rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg);
}

static void __rrr_raft_server_poll_cb (
		uv_poll_t *handle,
		int status,
		int events
) {
	struct rrr_raft_server_callback_data *callback_data = uv_handle_get_data((uv_handle_t *) handle);

	(void)(events);

	int ret_tmp;
	uint64_t bytes_read_dummy;

	if (status != 0) {
		RRR_MSG_0("Error status %i in %s\n", status, __func__);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
		return;
	}

	if ((ret_tmp = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&callback_data->channel->read_sessions,
			callback_data->channel->fd_server,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_raft_server_read_msg_cb,
			NULL,
			NULL,
			__rrr_raft_server_read_msg_ctrl_cb,
			NULL,
			NULL, /* first cb data */
			callback_data
	)) != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
	}
}

static int __rrr_raft_server_fsm_apply_cb (
		struct raft_fsm *fsm,
		const struct raft_buffer *buf,
		void **result
) {
	struct rrr_raft_server_callback_data *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp;

	*result = NULL;

	assert(buf->len <= UINT32_MAX);

	if ((ret = __rrr_raft_server_buf_msg_to_host(&msg_tmp, buf)) != 0) {
		RRR_MSG_0("Message decoding failed in %s\n", __func__);
		goto out;
	}

	// TODO : Check if we are leader and trigger NACK instead of bailing

	RRR_DBG_3("Raft message %i being applied in state machine in server %i\n",
		msg_tmp->msg_value, callback_data->server_id);

	if ((ret = rrr_raft_message_store_push(callback_data->message_store_state, msg_tmp)) != 0) {
		RRR_MSG_0("Failed to push message to message store during application to state machine in server %i\n",
			callback_data->server_id);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
		goto out_free;
	}

	// If we are leader, the apply_cb giving feedback to
	// the client must see the message which has been applied
	// successfully to the state machine.
	*result = msg_tmp;
	msg_tmp = NULL;

	out_free:
		RRR_FREE_IF_NOT_NULL(msg_tmp);
	out:
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
		struct rrr_raft_server_callback_data *callback_data
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
	struct rrr_raft_server_callback_data *callback_data = fsm->data;

	RRR_DBG_3("Raft insert snapshot server %i\n", callback_data->server_id);

	return __rrr_raft_server_fsm_message_store_snapshot (bufs, n_bufs, callback_data);
}

static int __rrr_raft_server_fsm_restore_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *buf
) {
	struct rrr_raft_server_callback_data *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg;
	size_t pos;

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
	uv_loop_t loop;
	uv_poll_t poll_server;
	struct raft_uv_transport transport = {0};
	struct raft_io io = {0};
	struct raft_fsm fsm = {0};
	struct raft raft = {0};
	struct raft_configuration configuration;
	struct raft_change *req = NULL;
	struct rrr_raft_server_callback_data callback_data;
	struct rrr_raft_message_store *message_store_state;
	static struct raft_heap rrr_raft_heap = {
		NULL,                            /* data */
		__rrr_raft_server_malloc,        /* malloc */
		__rrr_raft_server_free,          /* free */
		__rrr_raft_server_calloc,        /* calloc */
		__rrr_raft_server_realloc,       /* realloc */
		__rrr_raft_server_aligned_alloc, /* aligned_alloc */
		__rrr_raft_server_aligned_free   /* aligned_free */
	};
	struct raft_tracer rrr_raft_tracer = {
		NULL,
		2,
		__rrr_raft_server_tracer_emit_cb
	};

	rrr_raft_channel_fds_get(channel_fds, channel);
	rrr_socket_close_all_except_array_no_unlink(channel_fds, sizeof(channel_fds)/sizeof(channel_fds[0]));

	// TODO : Send logs on socket. XXX also enable unregister on function out
	// rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_raft_server_log_hook, channel, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
	assert(was_found);
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	rrr_config_set_log_prefix(log_prefix);

	if ((ret = rrr_raft_message_store_new (&message_store_state, patch_cb)) != 0) {
		goto out;
	}

	if (uv_loop_init(&loop) != 0) {
		RRR_MSG_0("Failed to initialize uv loop in %s\n", __func__);
		ret = 1;
		goto out_destroy_message_store;
	}

	if (uv_poll_init(&loop, &poll_server, channel->fd_server) != 0) {
		RRR_MSG_0("Failed to initialize receive handle in %s\n", __func__);
		ret = 1;
		goto out_loop_close;
	}

	if (uv_poll_start(&poll_server, UV_READABLE|UV_DISCONNECT, __rrr_raft_server_poll_cb) != 0) {
		RRR_MSG_0("Failed to start reading in %s\n", __func__);
		ret = 1;
		goto out_loop_close;
	}

	transport.version = 1;
	transport.data = NULL;

	if ((ret_tmp = raft_uv_tcp_init(&transport, &loop)) != 0) {
		RRR_MSG_0("Failed to initialize raft UV TCP in %s: %s\n", __func__, raft_strerror(ret_tmp));
		ret = 1;
		goto out_loop_close;
	}

	if ((ret_tmp = raft_uv_init(&io, &loop, dir, &transport)) != 0) {
		RRR_MSG_0("Failed to initialize raft UV in %s: %i\n", __func__, ret_tmp);
		ret = 1;
		goto out_raft_uv_tcp_close;
	}

	rrr_raft_tracer.impl = &callback_data;

	raft_uv_set_tracer(&io, &rrr_raft_tracer);

	fsm.version = 2;
	fsm.apply = __rrr_raft_server_fsm_apply_cb;
	fsm.snapshot = __rrr_raft_server_fsm_snapshot_cb;
	fsm.restore = __rrr_raft_server_fsm_restore_cb;
	fsm.data = &callback_data;

	RRR_DBG_1("Starting raft server %i dir %s address %s\n",
		servers[servers_self].id, dir, servers[servers_self].address);

	raft_heap_set(&rrr_raft_heap);

	if ((ret_tmp = raft_init (
			&raft,
			&io,
			&fsm,
			servers[servers_self].id,
			servers[servers_self].address
	)) != 0) {
		RRR_MSG_0("Failed to initialize raft in %s: %s: %s\n", __func__,
			raft_strerror(ret_tmp), raft_errmsg(&raft));
		ret = 1;
		goto out_raft_uv_close;
	}

	callback_data = (struct rrr_raft_server_callback_data) {
		channel,
		0,
		&loop,
		&raft,
		servers[servers_self].id,
		message_store_state,
		0,
		0,
		{0},
		{0}
	};

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
			goto out_raft_configuration_close;
		}
	}

	if ((ret_tmp = raft_bootstrap(&raft, &configuration)) != 0 && ret_tmp != RAFT_CANTBOOTSTRAP) {
		RRR_MSG_0("Failed to bootstrap raft in %s: %s\n",
			__func__, raft_strerror(ret_tmp));
		ret = 1;
		goto out_raft_configuration_close;
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

	RRR_DBG_1("Event loop completed in raft server, result was %i\n", ret_tmp);

	ret = callback_data.ret;

	// During normal operation, don't clean up the
	// raft stuff explicitly as this causes uv threads
	// to use freed data.
	goto out_loop_close;
	out_raft_configuration_close:
		raft_configuration_close(&configuration);
//	out_raft_close:
		raft_close(&raft, NULL);
	out_raft_uv_close:
		raft_uv_close(&io);
	out_raft_uv_tcp_close:
		raft_uv_tcp_close(&transport);
	out_loop_close:
		uv_loop_close(&loop);
		uv_library_shutdown();
	out_destroy_message_store:
		rrr_raft_message_store_destroy(message_store_state);
	out:
		// TODO : Enable once handle is registered
		// rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());

		if (req != NULL) {
			raft_free(req);
		}

		return ret;
}
