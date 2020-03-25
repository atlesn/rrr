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
#include "vl_time.h"

static struct rrr_socket_read_session *__rrr_socket_read_session_new (
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_socket_read_session *read_session = malloc(sizeof(*read_session));
	if (read_session == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_socket_read_session_new\n");
		return NULL;
	}
	memset(read_session, '\0', sizeof(*read_session));

	read_session->last_read_time = rrr_time_get_64();
	read_session->src_addr = *src_addr;
	read_session->src_addr_len = src_addr_len;

	return read_session;
}

static int __rrr_socket_read_session_destroy (
		struct rrr_socket_read_session *read_session
) {
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
	RRR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
	free(read_session);
	return 0;
}

void rrr_socket_read_session_collection_init (
		struct rrr_socket_read_session_collection *collection
) {
	memset(collection, '\0', sizeof(*collection));
}

void rrr_socket_read_session_collection_clear (
		struct rrr_socket_read_session_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_socket_read_session,__rrr_socket_read_session_destroy(node));
}

static struct rrr_socket_read_session *__rrr_socket_read_session_collection_get_session_with_overshoot (
		struct rrr_socket_read_session_collection *collection
) {

	RRR_LL_ITERATE_BEGIN(collection,struct rrr_socket_read_session);
		if (node->rx_overshoot != NULL) {
			return node;
		}
	RRR_LL_ITERATE_END(collection);
	return NULL;
}

static struct rrr_socket_read_session *__rrr_socket_read_session_collection_maintain_and_find_or_create (
		struct rrr_socket_read_session_collection *collection,
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_socket_read_session *res = NULL;

	uint64_t time_now = rrr_time_get_64();
	uint64_t time_limit = time_now - RRR_SOCKET_CLIENT_TIMEOUT_S * 1000 * 1000;

	RRR_LL_ITERATE_BEGIN(collection,struct rrr_socket_read_session);
		if (node->last_read_time < time_limit) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (memcmp(src_addr, &node->src_addr, sizeof(*src_addr)) == 0) {
			if (res != NULL) {
				RRR_BUG("Two equal src_addr in rrr_socket_read_session_collection_maintain_and_find\n");
			}
			res = node;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection,__rrr_socket_read_session_destroy(node));

	if (res == NULL) {
		res = __rrr_socket_read_session_new(src_addr, src_addr_len);
		if (res == NULL) {
			RRR_MSG_ERR("Could not allocate memory for read session in rrr_socket_read_message\n");
			goto out;
		}

		RRR_LL_PUSH(collection,res);
	}

	out:
	return res;
}

struct rrr_socket_read_message_default_callback_data {
	struct rrr_socket_read_session_collection *read_sessions;
	struct sockaddr src_addr;
	socklen_t src_addr_len;
	int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg);
	void *get_target_size_arg;
	int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg);
	void *complete_callback_arg;
};

static int __rrr_socket_read_message_default_poll(int fd, int read_flags, void *private_arg) {
	(void)(private_arg);
	(void)(read_flags);

	int ret = RRR_SOCKET_OK;

	ssize_t items = 0;
	struct pollfd pollfd = { fd, POLLIN, 0 };

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

static struct rrr_socket_read_session *__rrr_socket_read_message_default_get_read_session_with_overshoot(void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return __rrr_socket_read_session_collection_get_session_with_overshoot(callback_data->read_sessions);
}

static struct rrr_socket_read_session *__rrr_socket_read_message_default_get_read_session(void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return __rrr_socket_read_session_collection_maintain_and_find_or_create (
		callback_data->read_sessions,
		&callback_data->src_addr,
		callback_data->src_addr_len
	);
}

static void __rrr_socket_read_message_default_remove_read_session(struct rrr_socket_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	RRR_LL_REMOVE_NODE(
			callback_data->read_sessions,
			struct rrr_socket_read_session,
			read_session,
			__rrr_socket_read_session_destroy(node)
	);
}

static int __rrr_socket_read_message_default_get_target_size(struct rrr_socket_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

static int __rrr_socket_read_message_default_complete_callback(struct rrr_socket_read_session *read_session, void *private_arg) {
	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

static int __rrr_socket_read_message_default_read (
		char *buf,
		ssize_t *read_bytes,
		int fd,
		int read_flags,
		ssize_t read_step_max_size,
		void *private_arg
) {
	int ret = 0;

	struct rrr_socket_read_message_default_callback_data *callback_data = private_arg;

	*read_bytes = 0;

	ssize_t bytes = 0;

	callback_data->src_addr_len = sizeof(callback_data->src_addr);
	memset(&callback_data->src_addr, '\0', callback_data->src_addr_len);

	read_retry:
	if ((read_flags & RRR_SOCKET_READ_METHOD_RECVFROM) != 0) {
		/* Read and distinguish between senders based on source addresses */
		bytes = recvfrom (
				fd,
				buf,
				read_step_max_size,
				0,
				&callback_data->src_addr,
				&callback_data->src_addr_len
		);
	}
	else if ((read_flags & RRR_SOCKET_READ_METHOD_RECV) != 0) {
		/* Read and don't distinguish between senders */
		bytes = recv (
				fd,
				buf,
				read_step_max_size,
				0
		);
	}
	else if ((read_flags & RRR_SOCKET_READ_METHOD_READ_FILE) != 0) {
		/* Read from file */
		bytes = read (
				fd,
				buf,
				read_step_max_size
		);
	}
	else {
		RRR_BUG("Unknown read method %i in rrr_socket_read_message\n", read_flags);
	}

	if (bytes == -1) {
		if (errno == EINTR) {
			goto read_retry;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if ((read_flags & RRR_SOCKET_READ_USE_TIMEOUT) != 0) {
				usleep(10 * 1000);
			}
			goto out;
		}
		RRR_MSG_ERR("Error from read in rrr_socket_read_message: %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	*read_bytes = bytes;

	out:
	return ret;
}

int rrr_socket_read_message_using_callbacks (
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int									 (*function_get_target_size) (
													struct rrr_socket_read_session *read_session,
													void *private_arg
											 ),
		int									 (*function_complete_callback) (
													struct rrr_socket_read_session *read_session,
													void *private_arg
											 ),
		int									 (*function_poll) (
													int fd,
													int read_flags,
													void *private_arg
											 ),
		int									 (*function_read) (
													char *buf,
													ssize_t *read_bytes,
													int fd,
													int read_flags,
													ssize_t read_step_max_size,
													void *private_arg
	 	 	 	 	 	 	 	 	 	 	 ),
		struct rrr_socket_read_session		*(*function_get_read_session_with_overshoot) (
													void *private_arg
											 ),
		struct rrr_socket_read_session		*(*function_get_read_session) (
													void *private_arg
											 ),
		void								 (*function_read_session_remove) (
													struct rrr_socket_read_session *read_session,
													void *private_arg
											 ),
		void *functions_callback_arg
) {
	int ret = RRR_SOCKET_OK;

	char buf[read_step_max_size];
	struct rrr_socket_read_session *read_session = NULL;

	read_session = function_get_read_session_with_overshoot(functions_callback_arg);
	if (read_session != NULL) {
		goto process_overshoot;
	}

	if ((ret = function_poll(fd, read_flags, functions_callback_arg)) != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			if ((read_flags & RRR_SOCKET_READ_NO_SLEEPING) == 0) {
				usleep(10 * 1000);
			}
		}
		else {
			RRR_MSG_ERR("Error from poll callback in rrr_socket_read_message_using_callbacks\n");
		}
		goto out;
	}

	ssize_t bytes;

	/* Read */
	ret = function_read (buf, &bytes, fd, read_flags, read_step_max_size, functions_callback_arg);
	if (ret != 0) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			goto out;
		}
		RRR_MSG_ERR("Error from read callback in rrr_socket_read_message_using_callbacks\n");
		goto out;
	}

	/* Check for new read session */
	if ((read_session = function_get_read_session(functions_callback_arg)) == NULL) {
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	/* Check for EOF / connection close */
	if (bytes == 0) {
		// Possible connection close or file truncation
		if ((read_flags & RRR_SOCKET_READ_METHOD_READ_FILE) != 0) {
			ret = RRR_SOCKET_READ_EOF;
			goto out;
		}
		else if (read_session->read_complete_method == RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE) {
			if (read_session->target_size > 0) {
				RRR_BUG("Target size was set in rrr_socket_read_message while complete method was connection closed\n");
			}
			read_session->target_size = read_session->rx_buf_wpos;
		}
		else if ((read_flags & RRR_SOCKET_READ_CHECK_EOF) != 0) {
			ret = RRR_SOCKET_READ_EOF;
			goto out;
		}
		else {
			RRR_MSG_ERR("Read returned 0 in rrr_socket_read_message, possible close of connection\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
	}

	process_overshoot:
	if (read_session->rx_buf_ptr == NULL) {
		if (read_session->rx_overshoot != NULL) {
			read_session->rx_buf_ptr = read_session->rx_overshoot;
			read_session->rx_buf_size = read_session->rx_overshoot_size;
			read_session->rx_buf_wpos = read_session->rx_overshoot_size;

			read_session->rx_overshoot = NULL;
			read_session->rx_overshoot_size = 0;
		}
		else {
			read_session->rx_buf_ptr = malloc(bytes > read_step_max_size ? bytes : read_step_max_size);
			if (read_session->rx_buf_ptr == NULL) {
				RRR_MSG_ERR("Could not allocate memory in rrr_socket_read_message\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
			read_session->rx_buf_size = read_step_max_size;
			read_session->rx_buf_wpos = 0;
		}

		read_session->target_size = 0;
	}

	if (read_session->read_complete != 0) {
		RRR_BUG("Read complete was non-zero in rrr_socket_read_message, read session must be cleared prior to reading more data\n");
	}

	/* Check for expansion of buffer */
	if (bytes > 0) {
		if (bytes + read_session->rx_buf_wpos > read_session->rx_buf_size) {
			ssize_t new_size = read_session->rx_buf_size + (bytes > read_step_max_size ? bytes : read_step_max_size);
			char *new_buf = realloc(read_session->rx_buf_ptr, new_size);
			if (new_buf == NULL) {
				RRR_MSG_ERR("Could not re-allocate memory in rrr_socket_read_message\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
			read_session->rx_buf_ptr = new_buf;
			read_session->rx_buf_size = new_size;
		}

		memcpy (read_session->rx_buf_ptr + read_session->rx_buf_wpos, buf, bytes);
		read_session->rx_buf_wpos += bytes;
		read_session->last_read_time = rrr_time_get_64();
	}

	if (function_get_target_size == NULL) {
		read_session->target_size = read_step_initial;
	}
	else if (read_session->target_size == 0 &&
			read_session->read_complete_method == RRR_SOCKET_READ_COMPLETE_METHOD_TARGET_LENGTH
	) {
		read_session->rx_buf_skip = 0;

		// In the first read, we take a sneak peak at the first bytes to find a length field
		// if it is present. If there is not target size function, the target size becomes
		// the initial bytes parameter (set at the top of the function). The target size function
		// may change the read complete method.
		if ((ret = function_get_target_size(read_session, functions_callback_arg)) != RRR_SOCKET_OK) {
			goto out;
		}

		// The function may choose to skip bytes in the buffer. If it does, we must align the data here (costly).
		if (read_session->rx_buf_skip != 0) {
			if (read_session->rx_buf_skip < 0) {
				RRR_BUG("read_session rx_data_pos out of range after get_target_size in rrr_socket_read_message\n");
			}

			RRR_DBG_1("Aligning buffer, skipping %li bytes while reading from socket\n", read_session->rx_buf_skip);

			char *new_buf = malloc(read_session->rx_buf_size);
			if (new_buf == NULL) {
				RRR_MSG_ERR("Could not allocate memory while aligning buffer in rrr_socket_read_message\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
			memcpy(new_buf, read_session->rx_buf_ptr + read_session->rx_buf_skip, read_session->rx_buf_wpos - read_session->rx_buf_skip);

			free(read_session->rx_buf_ptr);

			read_session->rx_buf_ptr = new_buf;
			read_session->rx_buf_wpos -= read_session->rx_buf_skip;
		}

		if (read_session->target_size == 0 &&
				read_session->read_complete_method == RRR_SOCKET_READ_COMPLETE_METHOD_TARGET_LENGTH
		) {
			RRR_BUG("target_size was still zero after get_target_size in rrr_socket_read_message\n");
		}
	}

	if (read_session->rx_buf_wpos > read_session->target_size &&
			read_session->read_complete_method != RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE
	) {
		if (read_session->rx_overshoot != NULL) {
			RRR_BUG("overshoot was not NULL in rrr_socket_read_message\n");
		}

		read_session->rx_overshoot_size = read_session->rx_buf_wpos - read_session->target_size;
		read_session->rx_buf_wpos -= read_session->rx_overshoot_size;

		read_session->rx_overshoot = malloc(read_session->rx_overshoot_size);
		if (read_session->rx_overshoot == NULL) {
			RRR_MSG_ERR("Could not allocate memory for overshoot in rrr_socket_read_message\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		memcpy(read_session->rx_overshoot, read_session->rx_buf_ptr + read_session->rx_buf_wpos, read_session->rx_overshoot_size);
	}

	if (read_session->rx_buf_wpos == read_session->target_size && read_session->target_size > 0) {
		read_session->read_complete = 1;
		if (function_complete_callback != NULL) {
			ret = function_complete_callback (read_session, functions_callback_arg);
			if (ret != 0) {
				RRR_MSG_ERR("Error from callback in rrr_socket_read_message\n");
				goto out;
			}

			RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
			read_session->read_complete = 0;
		}
	}
	else if (read_session->read_complete_method == RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
		goto out;
	}

	out:
	if (ret != RRR_SOCKET_OK && ret != RRR_SOCKET_READ_INCOMPLETE && read_session != NULL) {
		function_read_session_remove(read_session, functions_callback_arg);
	}
	return ret;
}

int rrr_socket_read_message_default (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	struct rrr_socket_read_message_default_callback_data callback_data = {0};

	callback_data.read_sessions = read_session_collection;
	callback_data.get_target_size = get_target_size;
	callback_data.get_target_size_arg = get_target_size_arg;
	callback_data.complete_callback = complete_callback;
	callback_data.complete_callback_arg = complete_callback_arg;

	return rrr_socket_read_message_using_callbacks (
			fd,
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
			&callback_data
	);
}
