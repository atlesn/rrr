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
#include "../util/bsd.h"
#include "../util/posix.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../socket/rrr_socket.h"

#include <uv.h>
#include <assert.h>
#include <errno.h>

struct rrr_raft_channel_callbacks {
	void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS);
	void *arg;
};

struct rrr_raft_channel {
	int fd_client;
	int fd_server;
	struct rrr_event_queue *queue;
	struct rrr_event_collection events;
	struct rrr_read_session_collection read_sessions;
	struct rrr_raft_channel_callbacks callbacks;
};

static void __rrr_raft_channel_after_fork_client (
		struct rrr_raft_channel *channel
) {
	channel->fd_server = -1;
}

static void __rrr_raft_channel_after_fork_server (
		struct rrr_raft_channel *channel
) {
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
	channel->queue = queue;
	channel->callbacks = *callbacks;
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

static void __rrr_raft_fork_exit_notify_handler (pid_t pid, void *arg) {
	(void)(arg);

	RRR_DBG_1("Received SIGCHLD for raft child fork pid %i\n", pid);
}

static void __rrr_cmodule_raft_server_log_hook (RRR_LOG_HOOK_ARGS) {
	struct rrr_raft_channel *channel = private_arg;

	assert(0 && "log hook not implemented");
}

struct rrr_raft_server_callback_data {
	struct rrr_raft_channel *channel;
	int ret;
	uv_loop_t *loop;
};

static int __rrr_raft_server_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	int ret = 0;

	assert(0 && "Read msg not implemented");

	out:
	return ret;
}

static int __rrr_raft_server_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_callback_data *callback_data = arg2;

	int ret = 0;

	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);
	rrr_msg_checksum_and_to_network_endian(&msg);

	if (write(callback_data->channel->fd_server, &msg, sizeof(msg)) != sizeof(msg)) {
		RRR_MSG_0("Failed to send pong message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void __rrr_raft_server_poll_cb (
		uv_poll_t *handle,
		int status,
		int events
) {
	struct rrr_raft_server_callback_data *callback_data = uv_handle_get_data((uv_handle_t *) handle);

	int ret_tmp;
	uint64_t bytes_read_dummy;

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
	)) != 0) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
	}
}

static int __rrr_raft_server (
		struct rrr_raft_channel *channel,
		const char *log_prefix
) {
	int ret = 0;

	int log_hook_handle, was_found;
	int channel_fds[2];
	uv_loop_t loop;
	uv_poll_t poll_server;

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

	struct rrr_raft_server_callback_data callback_data = {
		channel,
		0,
		&loop
	};

	uv_handle_set_data((uv_handle_t *) &poll_server, &callback_data);

	if (uv_run(&loop, UV_RUN_DEFAULT) != 0) {
		RRR_MSG_0("uv_run failed in %s\n", __func__);
		ret = 1;
		goto out_loop_close;
	}

	ret = callback_data.ret;

	goto out_loop_close;
	out_loop_close:
		uv_loop_close(&loop);
	out:
		// TODO : Enable once handle is registered
		// rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());
		return ret;

}

static int __rrr_raft_client_send_ping (
		struct rrr_raft_channel *channel
) {
	int ret = 0;

	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);
	rrr_msg_checksum_and_to_network_endian(&msg);

	if (write(channel->fd_client, &msg, sizeof(msg)) != sizeof(msg)) {
		RRR_MSG_0("Failed to send ping message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void __rrr_raft_client_periodic_cb (evutil_socket_t fd, short flags, void *arg) {
	struct rrr_raft_channel *channel = arg;

	(void)(fd);
	(void)(flags);

	if (__rrr_raft_client_send_ping(channel) != 0) {
		rrr_event_dispatch_break(channel->queue);
	}

	if (channel
}

static int __rrr_raft_client_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	int ret = 0;

	assert(0 && "Read msg not implemented for client");

	out:
	return ret;
}

static int __rrr_raft_client_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_channel *channel = arg2;

	int ret = 0;

	channel->callbacks.pong_callback(channel->callbacks.arg);

	out:
	return ret;
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
	)) != 0) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		rrr_event_dispatch_break(channel->queue);
	}
}

int rrr_raft_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		void (*pong_callback)(RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	int sv[2];
	struct rrr_raft_channel *channel;
	rrr_event_handle event_periodic = {0};
	rrr_event_handle event_read = {0};

	// TODO : Cannot create sockets here due to forking context

	if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, "raft", sv)) != 0) {
		RRR_MSG_0("Failed to create sockets in %s: %s\n",
			rrr_strerror(errno));
		goto out;
	}

	struct rrr_raft_channel_callbacks callbacks = {
		pong_callback,
		callback_arg
	};

	if ((ret = __rrr_raft_channel_new (
			&channel,
			sv[0],
			sv[1],
			queue,
			&callbacks
	)) != 0) {
		goto out_close;
	}

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

		ret = __rrr_raft_server(channel, name);

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
	out_close:
		rrr_socket_close(sv[0]);
		rrr_socket_close(sv[1]);
	out:
		return ret;
}

void rrr_raft_cleanup (
		struct rrr_raft_channel *channel
) {
	__rrr_raft_channel_destroy(channel);
}
