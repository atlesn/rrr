/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <stdint.h>
#include <poll.h>
#include <read.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../global.h"
#include "linked_list.h"
#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "rrr_socket_msg.h"
#include "rrr_strerror.h"
#include "read.h"
#include "vl_time.h"

struct rrr_socket_read_message_default_callback_data {
	struct rrr_read_session_collection *read_sessions;
	int fd;
	struct sockaddr src_addr;
	socklen_t src_addr_len;
	int socket_read_flags;
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg);
	void *get_target_size_arg;
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg);
	void *complete_callback_arg;
};

static int __rrr_socket_read_message_default_poll(int read_flags, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	(void)(read_flags);

	int ret = RRR_SOCKET_OK;

	ssize_t items = 0;
	struct pollfd pollfd = { callback_data->fd, POLLIN, 0 };

	poll_retry:
	items = poll(&pollfd, 1, 0);
	if (items == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = RRR_SOCKET_READ_INCOMPLETE;
			goto out;
		}
		else if (errno == EINTR) {
			goto poll_retry;
		}
		RRR_MSG_ERR("Poll error in rrr_socket_read_message\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if ((pollfd.revents & (POLLERR|POLLNVAL)) != 0) {
		RRR_MSG_ERR("Poll error in rrr_socket_read_message\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if (items == 0) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
		goto out;
	}

	if ((pollfd.revents & POLLHUP) != 0) {
		RRR_DBG_3("Socket POLLHUP in rrr_socket_read_message, read EOF imminent\n");
	}

	out:
	return ret;
}

static struct rrr_read_session *__rrr_socket_read_message_default_get_read_session_with_overshoot(void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return rrr_read_session_collection_get_session_with_overshoot(callback_data->read_sessions);
}

static struct rrr_read_session *__rrr_socket_read_message_default_get_read_session(void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return rrr_read_session_collection_maintain_and_find_or_create (
		callback_data->read_sessions,
		&callback_data->src_addr,
		callback_data->src_addr_len
	);
}

static int __rrr_socket_read_message_default_get_socket_options (struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	int so_type = 0;
	socklen_t optlen = sizeof(so_type);

	int ret = getsockopt(callback_data->fd, SOL_SOCKET, SO_TYPE, &so_type, &optlen);

	if (ret != 0) {
		RRR_MSG_ERR("Error from getsockopt on fd %i: %s\n", callback_data->fd, rrr_strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session->socket_options = so_type;

	out:
	return ret;
}

static void __rrr_socket_read_message_default_remove_read_session(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	RRR_LL_REMOVE_NODE(
			callback_data->read_sessions,
			struct rrr_read_session,
			read_session,
			rrr_read_session_destroy(node)
	);
}

static int __rrr_socket_read_message_default_get_target_size(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

static int __rrr_socket_read_message_default_complete_callback(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

static int __rrr_socket_read_message_default_read (
		char *buf,
		ssize_t *read_bytes,
		ssize_t read_step_max_size,
		void *private_arg
) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	int ret = 0;

	*read_bytes = 0;

	ssize_t bytes = 0;

	callback_data->src_addr_len = sizeof(callback_data->src_addr);
	memset(&callback_data->src_addr, '\0', callback_data->src_addr_len);

	read_retry:
	if ((callback_data->socket_read_flags & RRR_SOCKET_READ_METHOD_RECVFROM) != 0) {
		/* Read and distinguish between senders based on source addresses */
		bytes = recvfrom (
				callback_data->fd,
				buf,
				read_step_max_size,
				0,
				&callback_data->src_addr,
				&callback_data->src_addr_len
		);
	}
	else if ((callback_data->socket_read_flags & RRR_SOCKET_READ_METHOD_RECV) != 0) {
		/* Read and don't distinguish between senders */
		bytes = recv (
				callback_data->fd,
				buf,
				read_step_max_size,
				0
		);
	}
	else if ((callback_data->socket_read_flags & RRR_SOCKET_READ_METHOD_READ_FILE) != 0) {
		/* Read from file */
		bytes = read (
				callback_data->fd,
				buf,
				read_step_max_size
		);
	}
	else {
		RRR_BUG("Unknown read method %i in __rrr_socket_read_message_default_read\n", callback_data->socket_read_flags);
	}

	if (bytes == -1) {
		if (errno == EINTR) {
			goto read_retry;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if ((callback_data->socket_read_flags & RRR_SOCKET_READ_USE_TIMEOUT) != 0) {
				usleep(10 * 1000);
			}
			goto out;
		}
		RRR_MSG_ERR("Error from read in __rrr_socket_read_message_default_read: %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if (bytes == 0) {
		if ((callback_data->socket_read_flags & RRR_SOCKET_READ_CHECK_EOF) != 0) {
			ret = RRR_READ_EOF;
			goto out;
		}
	}

	*read_bytes = bytes;

	out:
	return ret;
}

int rrr_socket_read_message_default (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int socket_read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	struct rrr_socket_read_message_default_callback_data callback_data = {0};

	callback_data.fd = fd;
	callback_data.read_sessions = read_session_collection;
	callback_data.get_target_size = get_target_size;
	callback_data.get_target_size_arg = get_target_size_arg;
	callback_data.complete_callback = complete_callback;
	callback_data.complete_callback_arg = complete_callback_arg;
	callback_data.socket_read_flags = socket_read_flags;

	return rrr_read_message_using_callbacks (
			read_step_initial,
			read_step_max_size,
			read_flags,
			__rrr_socket_read_message_default_get_target_size,
			__rrr_socket_read_message_default_complete_callback,
			__rrr_socket_read_message_default_poll,
			__rrr_socket_read_message_default_read,
			__rrr_socket_read_message_default_get_read_session_with_overshoot,
			__rrr_socket_read_message_default_get_read_session,
			__rrr_socket_read_message_default_remove_read_session,
			((socket_read_flags & RRR_SOCKET_READ_NO_GETSOCKOPTS) != RRR_SOCKET_READ_NO_GETSOCKOPTS
				? __rrr_socket_read_message_default_get_socket_options
				: NULL
			),
			&callback_data
	);
}
