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
#include "../util/bsd.h"
#include "../util/posix.h"
#include "../event/event.h"
#include "../socket/rrr_socket.h"

#include <uv.h>
#include <assert.h>
#include <errno.h>

struct rrr_raft_channel {
	int fd_client;
	int fd_server;
};

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
		int fd_server
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

static void __rrr_raft_server_poll_cb (
		uv_poll_t *handle,
		int status,
		int events
) {
	assert(0 && "read not implemented");
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

	rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_raft_server_log_hook, channel, NULL);

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

	uv_run(&loop, UV_RUN_DEFAULT);

	//while (rrr_posix_usleep(5000)) {
	//}
//	assert(0 && "event loop not implemented");

	goto out_loop_close;
	out_loop_close:
		uv_loop_close(&loop);
	out:
		rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());
		return ret;

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

	// TODO : Cannot create sockets here due to forking context

	if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, "raft", sv)) != 0) {
		RRR_MSG_0("Failed to create sockets in %s: %s\n",
			rrr_strerror(errno));
		goto out;
	}

	if ((ret = __rrr_raft_channel_new (
			&channel,
			sv[0],
			sv[1]
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
		goto out_close;
	}
	else if (pid == 0) {
		// CHILD
		rrr_setproctitle("[raft server %s]", name);

		rrr_log_hook_unregister_all_after_fork();

		rrr_event_hook_disable();
		rrr_event_queue_destroy(queue);

		ret = __rrr_raft_server(channel, name);

		exit(ret != 0);
	}

	// PARENT

	//assert(0 && "rrr_raft_fork not implemented");

	while (1) {
		printf("bytes written %li\n", write(channel->fd_client, "aaa", 3));
		rrr_posix_usleep(500000);
	}

	*result = channel;

	goto out;
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
