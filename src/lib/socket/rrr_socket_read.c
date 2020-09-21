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
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "../log.h"

#include "rrr_socket.h"
#include "rrr_socket_read.h"

#include "../rrr_strerror.h"
#include "../read.h"
#include "../messages/msg.h"
#include "../util/posix.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../input/input.h"

struct rrr_socket_read_message_default_callback_data {
	struct rrr_read_session_collection *read_sessions;
	int fd;
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len;
	int socket_read_flags;
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg);
	void *get_target_size_arg;
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg);
	void *complete_callback_arg;
};

static int __rrr_socket_read_message_poll (
		int *got_pollhup_pollerr,
		int fd
) {
	int ret = RRR_SOCKET_OK;

	*got_pollhup_pollerr = 0;

	ssize_t items = 0;
	struct pollfd pollfd = { fd, POLLIN, 0 };

	// Don't print errors here as errors will then be printed when a remote closes
	// connection. Higher level should print error if needed.

	poll_retry:

	items = poll(&pollfd, 1, 0);
	// Noisy message, disabled by default
/*	if (items > 0) {
		RRR_DBG_7("Socket %i poll result was %i items\n", callback_data->fd, items);
	}*/

	// Don't do else if's, check everything
	if (items == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = RRR_SOCKET_READ_INCOMPLETE;
			goto out;
		}
		else if (errno == EINTR) {
			goto poll_retry;
		}
		RRR_DBG_7("Socket %i poll error: %s\n", fd, rrr_strerror(errno));

		*got_pollhup_pollerr = 1;
		ret = RRR_SOCKET_SOFT_ERROR;
	}
	if ((pollfd.revents & (POLLERR|POLLNVAL)) != 0) {
		RRR_DBG_7("Socket %i poll: Got POLLERR or POLLNVAL\n", fd);

		*got_pollhup_pollerr = 1;
		ret = RRR_SOCKET_SOFT_ERROR;
	}
	if ((pollfd.revents & POLLHUP) != 0) {
		RRR_DBG_7("Socket %i POLLHUP, read EOF imminent\n", fd);

		// Don't set error, caller chooses what to do
		*got_pollhup_pollerr = 1;
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
		(struct sockaddr *) &callback_data->src_addr,
		callback_data->src_addr_len
	);
}

static int __rrr_socket_read_message_default_get_socket_options (struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	int so_type = 0;
	socklen_t optlen = sizeof(so_type);

	int ret = getsockopt(callback_data->fd, SOL_SOCKET, SO_TYPE, &so_type, &optlen);

	if (ret != 0) {
		RRR_MSG_0("Error from getsockopt on fd %i: %s\n", callback_data->fd, rrr_strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session->socket_options = so_type;

	out:
	return ret;
}

static void __rrr_socket_read_message_default_remove_read_session(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	if (read_session->rx_buf_ptr != NULL && read_session->rx_buf_wpos > 0) {
		RRR_DBG_1("Note: Removing read session for fd %i with %li unprocessed bytes left in read buffer\n",
				callback_data->fd, read_session->rx_buf_wpos);
	}
	if (read_session->rx_overshoot != NULL && read_session->rx_overshoot_size > 0) {
		RRR_DBG_1("Note: Removing read session for fd %i with %li unprocessed overshoot bytes left in read buffer\n",
				callback_data->fd, read_session->rx_overshoot_size);
	}

	rrr_read_session_collection_remove_session(callback_data->read_sessions, read_session);
}

static int __rrr_socket_read_message_default_get_target_size(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

static int __rrr_socket_read_message_default_complete_callback(struct rrr_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

int rrr_socket_read (
		char *buf,
		ssize_t *read_bytes,
		int fd,
		ssize_t read_step_max_size,
		struct sockaddr *src_addr,
		socklen_t *src_addr_len,
		int flags
) {
	int ret = 0;

	*read_bytes = 0;

	ssize_t bytes = 0;

	read_retry:
	if ((flags & RRR_SOCKET_READ_METHOD_RECVFROM) != 0) {
		/* Read and distinguish between senders based on source addresses */
		bytes = recvfrom (
				fd,
				buf,
				read_step_max_size,
				0,
				src_addr,
				src_addr_len
		);
	}
	else if ((flags & RRR_SOCKET_READ_METHOD_RECV) != 0) {
		/* Read and don't distinguish between senders */
		bytes = recv (
				fd,
				buf,
				read_step_max_size,
				0
		);
	}
	else if ((flags & RRR_SOCKET_READ_METHOD_READ_FILE) != 0) {
		/* Read from file */
		bytes = read (
				fd,
				buf,
				read_step_max_size
		);
	}
	else {
		RRR_BUG("Unknown read method %i in rrr_socket_read\n", flags);
	}

	if (bytes > 0) {
		RRR_DBG_7("Socket %i recvfrom/recv/read %li bytes time %" PRIu64 "\n", fd, bytes, rrr_time_get_64());
	}

	if (bytes == -1) {
		if (errno == EINTR) {
			goto read_retry;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if ((flags & RRR_SOCKET_READ_USE_TIMEOUT) != 0) {
				rrr_posix_usleep(10 * 1000);
			}
			goto out;
		}
		RRR_MSG_0("Error from read in rrr_socket_read: %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if (bytes == 0) {
		int got_pollhup_pollerr = 0;

		ret = __rrr_socket_read_message_poll(&got_pollhup_pollerr, fd);
		if (ret & (RRR_READ_INCOMPLETE|RRR_READ_HARD_ERROR)) {
			goto out;
		}

// Noisy message, not enabled by default
//		RRR_DBG_7("Socket %i return from poll was %i\n", fd, ret);

		if ( (flags & RRR_SOCKET_READ_CHECK_EOF) ||
			((flags & RRR_SOCKET_READ_CHECK_POLLHUP) && got_pollhup_pollerr)
		) {
			RRR_DBG_7("Socket %i recvfrom/recv/read emit EOF as instructed per flag\n", fd);
			ret = RRR_READ_EOF;
			goto out;
		}
		else if (ret != 0) {
			goto out;
		}
	}

	*read_bytes = bytes;

	out:
	return ret;
}

static int __rrr_socket_read_message_input_device (
		char *buf,
		ssize_t *read_bytes,
		ssize_t read_step_max_size,
		void *private_arg
) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	*read_bytes = 0;

	if (read_step_max_size < 1) {
		RRR_BUG("BUG: read_step_max_size too small in __rrr_socket_read_message_input_device\n");
	}

	int ret = RRR_READ_OK;

	char result = 0;
	while (*read_bytes < read_step_max_size &&
		(ret = rrr_input_device_read_key_character (
			&result,
			callback_data->fd,
			callback_data->socket_read_flags
		)) == RRR_READ_OK
	) {
		if (result <= 0) {
			continue;
		}

		*(buf + (*read_bytes)++) = result;
	}

	return ret & (~RRR_READ_INCOMPLETE); // Incomplete may not propagate
}

static int __rrr_socket_read_message_default_read (
		char *buf,
		ssize_t *read_bytes,
		ssize_t read_step_max_size,
		void *private_arg
) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	callback_data->src_addr_len = sizeof(callback_data->src_addr);
	memset(&callback_data->src_addr, '\0', callback_data->src_addr_len);

	return rrr_socket_read (
			buf,
			read_bytes,
			callback_data->fd,
			read_step_max_size,
			(struct sockaddr *) &callback_data->src_addr,
			&callback_data->src_addr_len,
			callback_data->socket_read_flags
	);
}

int rrr_socket_read_message_default (
		uint64_t *bytes_read,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max,
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

	// NOTE : Double check order of integer arguments, don't mix them up
	return rrr_read_message_using_callbacks (
			bytes_read,
			read_step_initial,
			read_step_max_size,
			read_max,
			__rrr_socket_read_message_default_get_target_size,
			__rrr_socket_read_message_default_complete_callback,
			(socket_read_flags & RRR_SOCKET_READ_INPUT_DEVICE
					? __rrr_socket_read_message_input_device
					: __rrr_socket_read_message_default_read
			),
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
