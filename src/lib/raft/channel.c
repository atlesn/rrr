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

#include <string.h>

#include "channel.h"
#include "channel_struct.h"
#include "server.h"
#include "client.h"
#include "common.h"

#include "../allocator.h"
#include "../fork.h"
#include "../event/event.h"
#include "../util/bsd.h"
#include "../socket/rrr_socket.h"

static void __rrr_raft_channel_after_fork_client (
		struct rrr_raft_channel *channel
) {
	rrr_socket_close(channel->fd_server);
	channel->fd_server = -1;
}

static int __rrr_raft_channel_after_fork_server (
		struct rrr_raft_channel *channel
) {
	int ret = 0;

	// Ensure that fork receives completely clean event queue
	// without any events added. No need to destroy old queue,
	// just overwrite pointer.
	if ((ret = rrr_event_queue_new(&channel->queue, 1)) != 0) {
		RRR_MSG_0("Failed to create event queue in %s\n",
			__func__);
		goto out;
	}

	rrr_socket_close(channel->fd_client);
	channel->fd_client = -1;
	memset(&channel->callbacks, '\0', sizeof(channel->callbacks));

	out:
	return ret;
}

void rrr_raft_channel_fds_get (
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

	rrr_event_collection_clear(&channel->events);

	rrr_free(channel);
}

static void __rrr_raft_channel_fork_exit_notify_handler (pid_t pid, void *arg) {
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

int rrr_raft_channel_fork (
		struct rrr_raft_channel **result,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		const char *name,
		int socketpair[2],
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
		void (*pong_callback)(RRR_RAFT_PONG_CALLBACK_ARGS),
		void (*ack_callback)(RRR_RAFT_ACK_CALLBACK_ARGS),
		void (*opt_callback)(RRR_RAFT_OPT_CALLBACK_ARGS),
		void (*msg_callback)(RRR_RAFT_MSG_CALLBACK_ARGS),
		void *callback_arg,
		int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
) {
	int ret = 0;

	struct rrr_raft_channel *channel;

	struct rrr_raft_channel_callbacks callbacks = {
		pong_callback,
		ack_callback,
		opt_callback,
		msg_callback,
		callback_arg
	};

	if ((ret = __rrr_raft_channel_new (
			&channel,
			socketpair[0],
			socketpair[1],
			servers[servers_self].id,
			queue,
			&callbacks
	)) != 0) {
		goto out;
	}

	socketpair[0] = -1;
	socketpair[1] = -1;

	pid_t pid = rrr_fork (
			fork_handler,
			__rrr_raft_channel_fork_exit_notify_handler,
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

		if ((ret = __rrr_raft_channel_after_fork_server(channel)) != 0) {
			goto fork_out;
		}

		ret = rrr_raft_server (
				channel,
				name,
				servers,
				servers_self,
				dir,
				patch_cb
		);

		__rrr_raft_channel_destroy(channel);

		fork_out:
		exit(ret != 0);
	}

	// PARENT

	if ((ret = rrr_raft_client_setup (
			channel
	)) != 0) {
		goto out_destroy_channel;
	}

	__rrr_raft_channel_after_fork_client(channel);

	*result = channel;

	goto out;
	out_destroy_channel:
		__rrr_raft_channel_destroy(channel);
	out:
		return ret;
}

void rrr_raft_channel_cleanup (
		struct rrr_raft_channel *channel
) {
	__rrr_raft_channel_destroy(channel);
}

int rrr_raft_channel_request_put (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
) {
	return rrr_raft_client_request_put(req_index, channel, topic, topic_length, data, data_size);
}

int rrr_raft_channel_request_patch (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length,
		const void *data,
		size_t data_size
) {
	return rrr_raft_client_request_patch(req_index, channel, topic, topic_length, data, data_size);
}

int rrr_raft_channel_request_put_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
) {
	return rrr_raft_client_request_put_native(req_index, channel, msg);
}

int rrr_raft_channel_request_patch_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
) {
	return rrr_raft_client_request_patch_native(req_index, channel, msg);
}

int rrr_raft_channel_request_delete_native (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_msg_msg *msg
) {
	return rrr_raft_client_request_delete_native(req_index, channel, msg);
}

int rrr_raft_channel_request_opt (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
) {
	return rrr_raft_client_request_opt(req_index, channel);
}

int rrr_raft_channel_request_get (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length
) {
	return rrr_raft_client_request_get(req_index, channel, topic, topic_length);
}

int rrr_raft_channel_request_delete (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const char *topic,
		size_t topic_length
) {
	return rrr_raft_client_request_delete(req_index, channel, topic, topic_length);
}

int rrr_raft_channel_servers_add (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return rrr_raft_client_servers_add(req_index, channel, servers);
}

int rrr_raft_channel_servers_del (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return rrr_raft_client_servers_del(req_index, channel, servers);
}

int rrr_raft_channel_servers_assign (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		const struct rrr_raft_server *servers
) {
	return rrr_raft_client_servers_assign(req_index, channel, servers);
}

int rrr_raft_channel_leadership_transfer (
		uint32_t *req_index,
		struct rrr_raft_channel *channel,
		int server_id
) {
	return rrr_raft_client_leadership_transfer(req_index, channel, server_id);
}

int rrr_raft_channel_snapshot (
		uint32_t *req_index,
		struct rrr_raft_channel *channel
) {
	return rrr_raft_client_snapshot(req_index, channel);
}
