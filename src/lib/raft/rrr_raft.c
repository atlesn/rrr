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

#include "rrr_raft.h"
#include "../allocator.h"
#include "../fork.h"
#include "../rrr_strerror.h"
#include "../common.h"
#include "../read.h"
#include "../messages/msg_msg.h"
#include "../util/bsd.h"
#include "../util/posix.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../socket/rrr_socket.h"

#include <uv.h>
#include <assert.h>
#include <errno.h>
#include <raft.h>
#include <raft/uv.h>

#define RRR_RAFT_SERVER_COUNT 3

static int __rrr_raft_server_send_msg_in_loop (
		struct rrr_raft_channel *channel,
		uv_loop_t *loop,
		struct rrr_msg *msg
);

struct rrr_raft_channel_callbacks {
	void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS);
	void (*ack_callback)(RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS);
	void *arg;
};

struct rrr_raft_channel {
	int fd_client;
	int fd_server;
	int server_id;
	uint32_t req_index;
	struct rrr_event_queue *queue;
	struct rrr_event_collection events;
	struct rrr_read_session_collection read_sessions;
	struct rrr_raft_channel_callbacks callbacks;
};

struct rrr_raft_message_store {
	struct rrr_msg_msg **msgs;
	size_t count;
	size_t capacity;
};

struct rrr_raft_server_callback_data {
	struct rrr_raft_channel *channel;
	int ret;
	uv_loop_t *loop;
	struct raft *raft;
	int server_id;
	struct rrr_raft_message_store *message_store_state;
	struct rrr_raft_message_store *message_store_incoming;
};

static int __rrr_raft_message_store_expand (
		struct rrr_raft_message_store *store
) {
	int ret = 0;

	struct rrr_msg_msg **msgs_new;
	size_t capacity_new;

	assert(store->count <= store->capacity);

	if (store->count != store->capacity) {
		goto out;
	}

	capacity_new = store->capacity;

	rrr_size_t_add_bug(&capacity_new, 128);

	if ((msgs_new = rrr_reallocate(store->msgs, capacity_new * sizeof(*msgs_new))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for pointers in %s\n", __func__);
		ret = 1;
		goto out;
	}

	store->msgs = msgs_new;
	store->capacity = capacity_new;

	out:
	return ret;
}

static void __rrr_raft_message_store_clear (
		struct rrr_raft_message_store *store
) {
	for (size_t i = 0; i < store->count; i++) {
		RRR_FREE_IF_NOT_NULL(store->msgs[i]);
	}

	RRR_FREE_IF_NOT_NULL(store->msgs);

	memset(store, '\0', sizeof(*store));
}

static struct rrr_msg_msg *__rrr_raft_message_store_push (
		struct rrr_raft_message_store *store,
		struct rrr_msg_msg **msg
) {
	struct rrr_msg_msg *msg_save = NULL;

	switch (MSG_TYPE(*msg)) {
		case MSG_TYPE_PUT: {
			for (size_t i = 0; i < store->count; i++) {
				if (store->msgs[i] == NULL)
					continue;

				if (rrr_msg_msg_topic_equals_msg(*msg, store->msgs[i])) {
					rrr_u32 value_orig = store->msgs[i]->msg_value;

					rrr_free(store->msgs[i]);
					store->msgs[i] = *msg;

					printf("Replaced message in message store %u->%u\n",
						value_orig, (*msg)->msg_value);

					goto out_consumed;
				}
			}
		} break;
		default:
			RRR_BUG("BUG: Message type %s not implemented in %s\n", MSG_TYPE_NAME(*msg), __func__);
	};

	for (size_t i = 0; i < store->count; i++) {
		if (store->msgs[i] != NULL)
			continue;

		store->msgs[i] = *msg;

		printf("Inserted message into message store %u count is now %llu\n",
			(*msg)->msg_value, (unsigned long long) store->count);

		goto out_consumed;
	}

	if (__rrr_raft_message_store_expand(store) != 0) {
		goto out;
	}

	store->msgs[store->count++] = *msg;

	printf("Pushed message to message store %u\n",
		(*msg)->msg_value);

	out_consumed:
		msg_save = *msg;
		*msg = NULL;
	out:
		return msg_save;
}

static inline void *__rrr_raft_malloc (void *data, size_t size) {
	(void)(data);
	return rrr_allocate(size);
}

static inline void __rrr_raft_free (void *data, void *ptr) {
	(void)(data);
	return rrr_free(ptr);
}

static inline void *__rrr_raft_calloc (void *data, size_t nmemb, size_t size) {
	(void)(data);
	return rrr_callocate(nmemb, size);
}

static inline void *__rrr_raft_realloc (void *data, void *ptr, size_t size) {
	(void)(data);
	return rrr_reallocate(ptr, size);
}

static inline void *__rrr_raft_aligned_alloc (void *data, size_t alignment, size_t size) {
	(void)(data);
	return rrr_aligned_allocate(alignment, size);
}

static inline void __rrr_raft_aligned_free (void *data, size_t alignment, void *ptr) {
	(void)(data);
	return rrr_aligned_free(alignment, ptr);
}

static void __rrr_raft_channel_after_fork_client (
		struct rrr_raft_channel *channel
) {
	rrr_socket_close(channel->fd_server);
	channel->fd_server = -1;
}

static void __rrr_raft_channel_after_fork_server (
		struct rrr_raft_channel *channel
) {
	rrr_socket_close(channel->fd_client);
	channel->fd_client = -1;
	channel->queue = NULL;
	memset(&channel->callbacks, '\0', sizeof(channel->callbacks));
}

static void __rrr_raft_channel_fds_get (
		int fds[2],
		const struct rrr_raft_channel *channel
) {
	fds[0] = channel->fd_client;
	fds[1] = channel->fd_server;
}

static int __rrr_raft_channel_new (
		struct rrr_raft_channel **result,
		int fd_client,
		int fd_server,
		int server_id,
		struct rrr_event_queue *queue,
		struct rrr_raft_channel_callbacks *callbacks
) {
	int ret = 0;

	struct rrr_raft_channel *channel;

	if ((channel = rrr_allocate_zero(sizeof(*channel))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	channel->fd_client = fd_client;
	channel->fd_server = fd_server;
	channel->server_id = server_id;
	channel->queue = queue;
	channel->callbacks = *callbacks;
	channel->req_index = 1;
	rrr_event_collection_init(&channel->events, queue);
	rrr_read_session_collection_init(&channel->read_sessions);

	*result = channel;

	out:
	return ret;
}

static void __rrr_raft_channel_destroy (
		struct rrr_raft_channel *channel
) {
	if (channel->fd_client > 0)
		rrr_socket_close(channel->fd_client);
	if (channel->fd_server > 0)
		rrr_socket_close(channel->fd_server);

	rrr_read_session_collection_clear(&channel->read_sessions);

	rrr_free(channel);
}

static void __rrr_raft_server_apply_cb (
		struct raft_apply *req,
		int status,
		void *result
) {
	struct rrr_raft_server_callback_data *callback_data = req->data;
	struct rrr_msg_msg *msg_orig = result;

	struct rrr_msg msg_ack = {0};

	if (status != 0) {
		if (status != RAFT_LEADERSHIPLOST) {
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
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_NACK, msg_orig->msg_value);
		goto send_msg;

	send_msg:
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);

	goto out;
	out:
		raft_free(req);
}

/*
static void __rrr_raft_server_change_cb (
		struct raft_change *req,
		int status
) {
	struct rrr_raft_server_callback_data *callback_data = req->data;

	if (status != 0) {
		RRR_MSG_0("Warning: Change request index %i failed: %s (%d)\n",
			raft_errmsg(callback_data->raft), status);
	}

	raft_free(req);
}
*/

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
	struct raft_buffer buf;
	struct raft_apply *req;
	struct rrr_msg msg = {0};

	assert((*message)->msg_value > 0);

	if (raft->state != RAFT_LEADER) {
		RRR_MSG_0("Warning: Refusing message. Not leader.\n");
		rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_NACK, (*message)->msg_value);
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg);
		goto out;
	}

	buf.len = MSG_TOTAL_SIZE(*message) + 8 - MSG_TOTAL_SIZE(*message) % 8;
	if ((buf.base = raft_calloc(1, buf.len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for buffer in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// Message in message store on disk stored with network endianess
	memcpy(buf.base, *message, MSG_TOTAL_SIZE(*message));
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf.base);

	if ((req = raft_malloc(sizeof(*req))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for request in %s\n", __func__);
		ret = 1;
		goto out_free_buffer;
	}

	req->data = callback_data;

	if ((ret_tmp = raft_apply(raft, req, &buf, 1, __rrr_raft_server_apply_cb)) != 0) {
		// It appears that this data is usually freed also
		// upon error conditions.
		buf.base = NULL;

		RRR_MSG_0("Apply failed in %s: %s\n", __func__, raft_errmsg(raft));
		ret = 1;
		goto out_free_buffer;
	}

	//assert(0 && "Read msg not implemented");

	goto out;
//	out_free_req:
//		raft_free(req);
	out_free_buffer:
		if (buf.base != NULL)
			raft_free(buf.base);
	out:
		return ret;
}

static int __rrr_raft_server_send_msg (
		struct rrr_raft_channel *channel,
		struct rrr_msg *msg
) {
	rrr_u32 total_size = MSG_TOTAL_SIZE(msg);

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

	if (rrr_msg_get_target_size_and_check_checksum (
			&stated_length,
			(struct rrr_msg *) msg,
			actual_length
	) != 0) {
		RRR_MSG_0("Failed to get size of message in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (actual_length < stated_length || actual_length != stated_length + 8 - stated_length % 8) {
		RRR_MSG_0("Size mismatch between buffer and message header %" PRIrrrl "<>%" PRIrrrl " in %s\n",
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

	//printf("Send pong\n");

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);

	//printf("servers: %u\n", callback_data->raft->configuration.n);

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

	struct rrr_msg_msg *msg_tmp, *msg_save;

	*result = NULL;

	assert(buf->len <= UINT32_MAX);

	if ((ret = __rrr_raft_server_buf_msg_to_host(&msg_tmp, buf)) != 0) {
		RRR_MSG_0("Message decoding failed in %s\n", __func__);
		goto out;
	}

	// TODO : Check if we are leader and trigger NACK instead of bailing

	printf("State machine push message\n");

	if ((msg_save = __rrr_raft_message_store_push(callback_data->message_store_state, &msg_tmp)) == NULL) {
		RRR_MSG_0("Failed to push message to message store during application to state machine in server %i\n",
			callback_data->server_id);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
		goto out_free;
	}

	RRR_DBG_1("Message %i now applied in state machine in server %i\n",
		msg_save->msg_value, callback_data->server_id);

	// If we are leader, the apply_cb giving feedback to
	// the client must see the message which has been applied
	// successfully to the state machine.
	*result = msg_save;

	out_free:
		rrr_free(msg_tmp);
	out:
		return ret;
}

static int  __rrr_raft_server_fsm_snapshot_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *bufs[],
		unsigned *n_bufs
) {
	struct rrr_raft_server_callback_data *callback_data = fsm->data;

	struct raft_buffer *buf;
	struct rrr_msg_msg *msg;

	if ((buf = bufs[0] = raft_calloc(1, sizeof(*buf))) == NULL) {
		RRR_MSG_0("Failed to allocate buffer in %s\n", __func__);
		return RAFT_NOMEM;
	}

	if (rrr_msg_msg_new_empty (
			&msg,
			MSG_TYPE_TAG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			0,
			0
	) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		return RAFT_NOMEM;
	}

	msg->msg_value = UINT32_MAX;

	printf("Insert snapshot server %i\n", callback_data->server_id);

	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg);

	buf->len = MSG_TOTAL_SIZE(msg);
	buf->base = msg;

	*n_bufs = 1;

	return 0;
}

static int __rrr_raft_server_fsm_restore_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *buf
) {
	struct rrr_msg_msg *msg = buf->base;

	(void)(fsm);

	int ret = 0;

	assert(buf->len <= UINT32_MAX);

	if ((ret = __rrr_raft_server_msg_to_host(msg, buf->len)) != 0) {
		RRR_MSG_0("Message decoding failed in %s\n", __func__);
		goto out;
	}

	assert(msg->msg_value == UINT32_MAX);

	printf("Restore snapshot with value 0x%08x\n", msg->msg_value);

	// Only free upon successful return value
	raft_free(buf->base);

	out:
	return ret;
}

static int __rrr_raft_server (
		struct rrr_raft_channel *channel,
		const char *log_prefix,
		int server_id,
		const char *dir
) {
	int ret = 0;

	int was_found, ret_tmp, i;
	int channel_fds[2];
	uv_loop_t loop;
	uv_poll_t poll_server;
	struct raft_uv_transport transport = {0};
	struct raft_io io = {0};
	struct raft_fsm fsm = {0};
	struct raft raft = {0};
	struct raft_configuration configuration;
	struct raft_change *req = NULL;
	char address[64];
	struct rrr_raft_server_callback_data callback_data;
	struct rrr_raft_message_store message_store_state = {0};
	static struct raft_heap rrr_raft_heap = {
		NULL,                     /* data */
		__rrr_raft_malloc,        /* malloc */
		__rrr_raft_free,          /* free */
		__rrr_raft_calloc,        /* calloc */
		__rrr_raft_realloc,       /* realloc */
		__rrr_raft_aligned_alloc, /* aligned_alloc */
		__rrr_raft_aligned_free   /* aligned_free */
	};

	__rrr_raft_channel_fds_get(channel_fds, channel);
	rrr_socket_close_all_except_array_no_unlink(channel_fds, sizeof(channel_fds)/sizeof(channel_fds[0]));

	// TODO : Send logs on socket. XXX also enable unregister on function out
	// rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_raft_server_log_hook, channel, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
	assert(was_found);
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	rrr_config_set_log_prefix(log_prefix);

	if (uv_loop_init(&loop) != 0) {
		RRR_MSG_0("Failed to initialize uv loop in %s\n", __func__);
		ret = 1;
		goto out;
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

	fsm.version = 2;
	fsm.apply = __rrr_raft_server_fsm_apply_cb;
	fsm.snapshot = __rrr_raft_server_fsm_snapshot_cb;
	fsm.restore = __rrr_raft_server_fsm_restore_cb;
	fsm.data = &callback_data;

	sprintf(address, "127.0.0.1:900%d", server_id);

	RRR_DBG_1("Starting raft server %i dir %s address %s\n",
		server_id, dir, address);

	raft_heap_set(&rrr_raft_heap);

	if ((ret_tmp = raft_init(&raft, &io, &fsm, server_id, address)) != 0) {
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
		server_id,
		&message_store_state,
		NULL
	};

	raft_configuration_init(&configuration);

	for (i = 0; i < RRR_RAFT_SERVER_COUNT; i++) {
		sprintf(address, "127.0.0.1:900%d", i + 1);

		if ((ret_tmp = raft_configuration_add (
				&configuration,
				i + 1,
				address,
				RAFT_VOTER
		)) != 0) {
			RRR_MSG_0("Failed to add to raft configuration in %s: %s\n", __func__,
				raft_strerror(ret_tmp));
			ret = 1;
			goto out_raft_configuration_close;
		}
/* ASYNC SERVER ADD DOES NOT BELONG HERE 
		if ((req = raft_malloc(sizeof(*req))) == NULL) {
			RRR_MSG_0("Failed to allocate change request in %s\n", __func__);
			ret = 1;
			goto out_raft_configuration_close;
		}

		memset(req, '\0', sizeof(*req));

		req->data = &callback_data;

		if ((ret_tmp = raft_add (
				&raft,
				req,
				i + 1,
				address,
				__rrr_raft_server_change_cb
		)) != 0) {
			RRR_MSG_0("Failed to add raft server in %s: %s\n", __func__,
				raft_strerror(ret_tmp));
			ret = 1;
			goto out_raft_configuration_close;
		}*/
	}

	if ((ret_tmp = raft_bootstrap(&raft, &configuration)) != 0 && ret_tmp != RAFT_CANTBOOTSTRAP) {
		RRR_MSG_0("Failed to bootstrap raft in %s: %s\n",
			__func__, raft_strerror(ret_tmp));
		ret = 1;
		goto out_raft_configuration_close;
	}

//	raft.configuration.n = configuration;

	raft_set_snapshot_threshold(&raft, 64);
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
	out:
		// TODO : Enable once handle is registered
		// rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());

		if (req != NULL) {
			raft_free(req);
		}
		__rrr_raft_message_store_clear(&message_store_state);

		return ret;

}

static int __rrr_raft_client_send_msg (
		struct rrr_raft_channel *channel,
		struct rrr_msg *msg
) {
	rrr_u32 total_size = MSG_TOTAL_SIZE(msg);

	rrr_msg_checksum_and_to_network_endian(msg);

	if (write(channel->fd_client, msg, total_size) != total_size) {
		RRR_MSG_0("Failed to send message in %s: %s\n",
			__func__, rrr_strerror(errno));
		return RRR_READ_HARD_ERROR;
	}

	return RRR_READ_OK;
}

static int __rrr_raft_client_send_ping (
		struct rrr_raft_channel *channel
) {
	struct rrr_msg msg = {0};

	//printf("Send ping\n");

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);

	return __rrr_raft_client_send_msg(channel, &msg);
}
/*
static int __rrr_raft_client_send_close (
		struct rrr_raft_channel *channel
) {
	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_CLOSE, 0);
	return __rrr_raft_client_send_msg(channel, &msg);
}
*/
static void __rrr_raft_client_periodic_cb (evutil_socket_t fd, short flags, void *arg) {
	struct rrr_raft_channel *channel = arg;

	(void)(fd);
	(void)(flags);

	if (__rrr_raft_client_send_ping(channel) != 0) {
		rrr_event_dispatch_break(channel->queue);
	}
}

static int __rrr_raft_client_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	int ret = 0;

	(void)(message);
	(void)(arg1);
	(void)(arg2);

	assert(0 && "Read msg not implemented for client");

	return ret;
}

static int __rrr_raft_client_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_channel *channel = arg2;

	(void)(arg1);
	(void)(arg2);

	switch (RRR_MSG_CTRL_FLAGS(message) & ~(RRR_MSG_CTRL_F_RESERVED)) {
		case RRR_MSG_CTRL_F_PONG:
			channel->callbacks.pong_callback(channel->server_id, channel->callbacks.arg);
			break;
		case RRR_MSG_CTRL_F_ACK:
			channel->callbacks.ack_callback(channel->server_id, message->msg_value, 1 /* ack */, channel->callbacks.arg);
			break;
		case RRR_MSG_CTRL_F_NACK:
			channel->callbacks.ack_callback(channel->server_id, message->msg_value, 0 /* nack */, channel->callbacks.arg);
			break;
		default:
			RRR_BUG("BUG: Unknown flags %u in %s\n",
				RRR_MSG_CTRL_FLAGS(message), __func__);
	}

	return 0;
}

static void __rrr_raft_client_read_cb (evutil_socket_t fd, short flags, void *arg) {
	struct rrr_raft_channel *channel = arg;

	(void)(fd);

	int ret_tmp;
	uint64_t bytes_read_dummy;

	if (flags & EV_TIMEOUT) {
		RRR_MSG_0("Hard timeout in %s\n", __func__);
		rrr_event_dispatch_break(channel->queue);
		return;
	}

	if ((ret_tmp = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&channel->read_sessions,
			channel->fd_client,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_raft_client_read_msg_cb,
			NULL,
			NULL,
			__rrr_raft_client_read_msg_ctrl_cb,
			NULL,
			NULL, /* first cb data */
			channel
	)) != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		rrr_event_dispatch_break(channel->queue);
	}
}

static void __rrr_raft_fork_exit_notify_handler (pid_t pid, void *arg) {
	(void)(arg);

	RRR_DBG_1("Received SIGCHLD for raft child fork pid %i\n", pid);
}

/*
static void __rrr_cmodule_raft_server_log_hook (RRR_LOG_HOOK_ARGS) {
	struct rrr_raft_channel *channel = private_arg;

	(void)(channel);
	(void)(file);
	(void)(line);
	(void)(loglevel_translated);
	(void)(loglevel_orig);
	(void)(prefix);
	(void)(message);

	assert(0 && "log hook not implemented");
}
*/

int rrr_raft_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		int socketpair[2],
		int server_id,
		const char *dir,
		void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS),
		void (*ack_callback)(RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_raft_channel *channel;
	rrr_event_handle event_periodic = {0};
	rrr_event_handle event_read = {0};

	struct rrr_raft_channel_callbacks callbacks = {
		pong_callback,
		ack_callback,
		callback_arg
	};

	if ((ret = __rrr_raft_channel_new (
			&channel,
			socketpair[0],
			socketpair[1],
			server_id,
			queue,
			&callbacks
	)) != 0) {
		goto out;
	}

	socketpair[0] = -1;
	socketpair[1] = -1;

	pid_t pid = rrr_fork (
			fork_handler,
			__rrr_raft_fork_exit_notify_handler,
			NULL
	);

	if (pid < 0) {
		// Don't use rrr_strerror() due to use of global lock
		RRR_MSG_0("Failed to create raft fork: %i\n", errno);
		ret = 1;
		goto out_destroy_channel;
	}
	else if (pid == 0) {
		// CHILD

		rrr_setproctitle("[raft server %s]", name);

		rrr_log_hook_unregister_all_after_fork();

		rrr_event_hook_disable();
		rrr_event_queue_destroy(queue);

		__rrr_raft_channel_after_fork_server(channel);

		ret = __rrr_raft_server(channel, name, server_id, dir);

		exit(ret != 0);
	}

	// PARENT

	if ((ret = rrr_event_collection_push_periodic (
			&event_periodic,
			&channel->events,
			__rrr_raft_client_periodic_cb,
			channel,
			250 * 1000 // 250 ms
	)) != 0) {
		RRR_MSG_0("Failed to push periodic function in %s\n", __func__);
		goto out_destroy_channel;
	}

	EVENT_ADD(event_periodic);

	if ((ret = rrr_event_collection_push_read (
			&event_read,
			&channel->events,
			channel->fd_client,
			__rrr_raft_client_read_cb,
			channel,
			1 * 1000 * 1000 // 1 second hard timeout
	)) != 0) {
		RRR_MSG_0("Failed to push read function in %s\n", __func__);
		goto out_destroy_channel;
	}

	EVENT_ADD(event_read);

	__rrr_raft_channel_after_fork_client(channel);

	//assert(0 && "rrr_raft_fork not implemented");

	*result = channel;

	goto out;
	out_destroy_channel:
		__rrr_raft_channel_destroy(channel);
	out:
		return ret;
}

void rrr_raft_cleanup (
		struct rrr_raft_channel *channel
) {
	__rrr_raft_channel_destroy(channel);
}

static int __rrr_raft_client_request (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const void *data,
		size_t data_size,
		uint8_t msg_type
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	// Counter must begin at 1
	assert(channel->req_index > 0);

	if ((ret = rrr_msg_msg_new_with_data (
			&msg,
			msg_type,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			NULL,
			0,
			data,
			rrr_u32_from_biglength_bug_const(data_size)
	)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	msg->msg_value = channel->req_index;

	printf("Send request type %s size %lu fd %i message size %u req %u\n",
		MSG_TYPE_NAME(msg), data_size, channel->fd_client, MSG_TOTAL_SIZE(msg), channel->req_index);

	if ((ret = __rrr_raft_client_send_msg (
			channel,
			(struct rrr_msg *) msg
	)) != 0) {
		goto out;
	}

	*req_index = channel->req_index++;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

int rrr_raft_client_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const void *data,
		size_t data_size
) {
	return __rrr_raft_client_request(req_index, channel, data, data_size, MSG_TYPE_PUT);
}
