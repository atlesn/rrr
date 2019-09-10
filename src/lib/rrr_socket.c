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

#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include "rrr_endian.h"
#include "../global.h"
#include "rrr_socket.h"
#include "vl_time.h"
#include "crc32.h"

/*
 * The meaning with this global tracking of sockets is to make sure that
 * forked processes can close not-needed sockets.
 *
 * The forked process will have access to this global data in the state
 * which it had when the fork was created. New sockets created in the
 * main process can be added later, but they are not visible to
 * the fork. Also, new sockets in the fork are not visible to main.
 */

struct rrr_socket_holder {
	char creator[128];
	struct rrr_socket_holder *next;
	int fd;
};

static struct rrr_socket_holder *first_socket = NULL;
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;

void rrr_socket_msg_populate_head (
		struct rrr_socket_msg *message,
		vl_u16 type,
		vl_u32 msg_size,
		vl_u64 value
) {
	if (msg_size < sizeof(*message)) {
		VL_BUG("Size was too small in rrr_socket_msg_head_to_network\n");
	}

	message->network_size = msg_size;
	message->msg_type = type;
	message->msg_size = msg_size;
	message->msg_value = value;
}

void rrr_socket_msg_checksum_and_to_network_endian (
	struct rrr_socket_msg *message
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < message->msg_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%02x-", *(buf+i));
	}
	printf("\n");*/

	message->header_crc32 = 0;
	message->data_crc32 = 0;

	char *data_begin = ((char *) message) + sizeof(*message);
	ssize_t data_size = message->network_size - sizeof(*message);

	if (data_size > 0) {
		message->data_crc32 = crc32buf(data_begin, data_size);
	}

//	printf ("Put crc32 %lu data size %li\n", message->data_crc32, message->network_size - sizeof(*message));

	message->network_size = htobe32(message->network_size);
	message->msg_type = htobe16(message->msg_type);
	message->msg_size = htobe32(message->msg_size);
	message->msg_value = htobe64(message->msg_value);
	message->data_crc32 = htobe32(message->data_crc32);

	char *head_begin = ((char *) message) + sizeof(message->header_crc32);
	ssize_t head_size = sizeof(*message) - sizeof(message->header_crc32);

	message->header_crc32 = htobe32(crc32buf(head_begin, head_size));
}

void rrr_socket_msg_head_to_host (struct rrr_socket_msg *message) {
	message->header_crc32 = 0;
	message->network_size = be32toh(message->network_size);
	message->data_crc32 = be32toh(message->data_crc32);
	message->msg_type = be16toh(message->msg_type);
	message->msg_size = be32toh(message->msg_size);
	message->msg_value = be64toh(message->msg_value);
}

int rrr_socket_msg_get_packet_target_size_and_checksum (
		ssize_t *target_size,
		struct rrr_socket_msg *socket_msg,
		ssize_t buf_size
) {
	if (buf_size < (ssize_t) sizeof(struct rrr_socket_msg)) {
		return RRR_SOCKET_READ_INCOMPLETE;
	}

	*target_size = 0;

	if (crc32cmp (
			((char*) socket_msg) + sizeof(socket_msg->header_crc32),
			sizeof(*socket_msg) - sizeof(socket_msg->header_crc32),
			be32toh(socket_msg->header_crc32)
	) != 0) {
		return RRR_SOCKET_SOFT_ERROR;
	}

	*target_size = be32toh(socket_msg->network_size);

	return RRR_SOCKET_OK;
}

int rrr_socket_msg_checksum_check (
	struct rrr_socket_msg *message,
	ssize_t data_size
) {
	// HEX dumper
/*	for (unsigned int i = 0; i < data_size; i++) {
		unsigned char *buf = (unsigned char *) message;
		printf("%02x-", *(buf+i));
	}
	printf("\n");
	printf ("Check crc32 %lu data size %li\n", message->data_crc32, data_size - sizeof(*message));*/

	vl_u32 checksum = message->data_crc32;

	char *data_begin = ((char *) message) + sizeof(*message);
	return crc32cmp(data_begin, data_size - sizeof(*message), checksum) != 0;
}

int rrr_socket_msg_head_validate (struct rrr_socket_msg *message) {
	int ret = 0;

	if (RRR_SOCKET_MSG_IS_CTRL(message)) {
		// Clear all known control flags
		vl_u16 type = message->msg_type;
		type = type & ~(RRR_SOCKET_MSG_CTRL_F_ALL);
		if (type != 0) {
			VL_MSG_ERR("Unknown control flags in message: %u\n", type);
			ret = 1;
		}
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message) || RRR_SOCKET_MSG_IS_VL_MESSAGE(message)) {
		ret = 0;
	}
	else {
		ret = 1;
	}

	if (ret != 0) {
		VL_MSG_ERR("Received message with invalid type %u in rrr_socket_msg_head_validate\n", message->msg_type);
		ret = 1;
	}

	return ret;
}

int rrr_socket_with_lock_do (
		int (*callback)(void *arg),
		void *arg
) {
	int ret = 0;
	pthread_mutex_lock(&socket_lock);
	ret = callback(arg);
	pthread_mutex_unlock(&socket_lock);
	return ret;
}

static void __rrr_socket_dump_unlocked (void) {
	struct rrr_socket_holder *cur = first_socket;
	while (cur) {
		VL_DEBUG_MSG_7 ("fd %i pid %i creator %s\n", cur->fd, getpid(), cur->creator);
		cur = cur->next;
	}
	VL_DEBUG_MSG_7("---\n");
}

static void __rrr_socket_add_unlocked (
		int fd,
		const char *creator
) {
	if (strlen(creator) > 127) {
		VL_BUG("Creator name too long in __rrr_socket_add_unlocked\n");
	}
	struct rrr_socket_holder *holder = malloc(sizeof(*holder));
	holder->fd = fd;
	holder->next = first_socket;
	strcpy(holder->creator, creator);
	first_socket = holder;

	if (VL_DEBUGLEVEL_7) {
		VL_DEBUG_MSG_7("rrr_socket add fd %i pid %i, sockets are now:\n", fd, getpid());
		__rrr_socket_dump_unlocked();
	}
}

int rrr_socket_accept (
		int fd_in,
		struct sockaddr *addr,
		socklen_t *__restrict addr_len,
		const char *creator
) {
	int fd_out = 0;
	pthread_mutex_lock(&socket_lock);
	fd_out = accept(fd_in, addr, addr_len);
	if (fd_out != -1) {
		__rrr_socket_add_unlocked(fd_out, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd_out;
}

int rrr_socket_mkstemp (
		char *filename,
		const char *creator
) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = mkstemp(filename);
	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket (
		int domain,
		int type,
		int protocol,
		const char *creator
) {
	int fd = 0;
	pthread_mutex_lock(&socket_lock);
	fd = socket(domain, type, protocol);

	if (fd != -1) {
		__rrr_socket_add_unlocked(fd, creator);
	}
	pthread_mutex_unlock(&socket_lock);
	return fd;
}

int rrr_socket_close (int fd) {
	if (fd <= 0) {
		VL_BUG("rrr_socket_close called with fd <= 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close fd %i pid %i\n", fd, getpid());

	int ret = close(fd);

	if (ret != 0) {
		// A socket is sometimes closed by the other host
		if (errno != EBADF) {
			VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close: %s\n", fd, strerror(errno));
		}
	}

	pthread_mutex_lock(&socket_lock);

	int did_free = 0;

	__rrr_socket_dump_unlocked();

	if (first_socket != NULL && first_socket->fd == fd) {
		struct rrr_socket_holder *cur = first_socket;
		first_socket = first_socket->next;
		free(cur);
		did_free = 1;
	}
	else {
		struct rrr_socket_holder *cur = first_socket;
		while (cur) {
			struct rrr_socket_holder *next = cur->next;

			if (next->fd == fd) {
				cur->next = next->next;
				free (next);
				did_free = 1;
				break;
			}

			cur = next;
		}
	}

	__rrr_socket_dump_unlocked();

	pthread_mutex_unlock(&socket_lock);

	if (did_free == 0) {
		VL_BUG("rrr_socket_close called with fd %i which was not in the list\n", fd);
	}

	return ret;
}

int rrr_socket_close_all_except (int fd) {
	int ret = 0;

	if (fd < 0) {
		VL_BUG("rrr_socket_close_all_except called with fd < 0: %i\n", fd);
	}

	VL_DEBUG_MSG_7("rrr_socket_close_all_except fd %i pid %i\n", fd, getpid());

	int err_count = 0;
	int count = 0;

	pthread_mutex_lock(&socket_lock);

	struct rrr_socket_holder *found = NULL;

	struct rrr_socket_holder *cur = first_socket;
	while (cur) {
		struct rrr_socket_holder *next = cur->next;

		if (cur->fd == fd) {
			if (found != NULL) {
				VL_BUG("At least two equal fds found in rrr_socket_close_all_except: %i\n", fd);
			}
			found = cur;
			goto next;
		}

		ret |= close(cur->fd);
		if (ret != 0) {
			err_count++;
			VL_MSG_ERR("Warning: Socket close of fd %i failed in rrr_socket_close_all_except: %s\n", fd, strerror(errno));
		}

		free(cur);
		count++;

		next:
		cur = next;
	}

	if (found == NULL && fd != 0) {
		VL_BUG ("rrr_socket_close_all_except called with fd %i which was not in the list\n", fd);
	}

	if (found != NULL) {
		found->next = NULL;
		first_socket = found;
	}
	else {
		first_socket = NULL;
	}

	if (VL_DEBUGLEVEL_7) {
		__rrr_socket_dump_unlocked();
	}

	pthread_mutex_unlock(&socket_lock);

	VL_DEBUG_MSG_1("Closed %i sockets with %i errors pid %i\n", count, err_count, getpid());

	return ret;
}

int rrr_socket_close_all (void) {
	return rrr_socket_close_all_except(0);
}

static struct rrr_socket_read_session *__rrr_socket_read_session_new (
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_socket_read_session *read_session = malloc(sizeof(*read_session));
	if (read_session == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_socket_read_session_new\n");
		return NULL;
	}
	memset(read_session, '\0', sizeof(*read_session));

	read_session->last_read_time = time_get_64();
	read_session->src_addr = *src_addr;
	read_session->src_addr_len = src_addr_len;

	return read_session;
}

static int __rrr_socket_read_session_destroy (
		struct rrr_socket_read_session *read_session
) {
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
	RRR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
	return 0;
}

void rrr_socket_read_session_collection_init (
		struct rrr_socket_read_session_collection *collection
) {
	memset(collection, '\0', sizeof(*collection));
}

void rrr_socket_read_session_collection_destroy (
		struct rrr_socket_read_session_collection *collection
) {
	RRR_LINKED_LIST_DESTROY(collection,struct rrr_socket_read_session,__rrr_socket_read_session_destroy(node));
}

static struct rrr_socket_read_session *__rrr_socket_read_session_collection_maintain_and_find_or_create (
		struct rrr_socket_read_session_collection *collection,
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_socket_read_session *res = NULL;

	uint64_t time_now = time_get_64();
	uint64_t time_limit = time_now - RRR_SOCKET_READ_TIMEOUT * 1000 * 1000;

	RRR_LINKED_LIST_ITERATE_BEGIN(collection,struct rrr_socket_read_session);
		if (node->last_read_time < time_limit) {
			RRR_LINKED_LIST_SET_DESTROY();
		}
		else if (memcmp(src_addr, &node->src_addr, sizeof(*src_addr)) == 0) {
			if (res != NULL) {
				VL_BUG("Two equal src_addr in rrr_socket_read_session_collection_maintain_and_find\n");
			}
			res = node;
		}
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(collection,__rrr_socket_read_session_destroy(node));

	if (res == NULL) {
		res = __rrr_socket_read_session_new(src_addr, src_addr_len);
		if (res == NULL) {
			VL_MSG_ERR("Could not allocate memory for read session in rrr_socket_read_message\n");
			goto out;
		}

		RRR_LINKED_LIST_PUSH(collection,res);
	}

	out:
	return res;
}

int rrr_socket_read_session_get_target_length_from_message_and_checksum (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	if (arg != NULL) {
		VL_BUG("arg was not NULL in rrr_socket_get_target_length_from_msg\n");
	}

	ssize_t target_size = 0;
	int ret = rrr_socket_msg_get_packet_target_size_and_checksum(
			&target_size,
			(struct rrr_socket_msg *) read_session->rx_buf_ptr,
			read_session->rx_buf_wpos
	);

	if (ret != 0) {
		if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			VL_MSG_ERR("Warning: Header checksum of message failed in rrr_socket_get_target_length_from_msg\n");
		}
		goto out;
	}

	read_session->target_size = target_size;

	out:
	return ret;
}

int rrr_socket_read_message (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_socket_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_socket_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	int ret = RRR_SOCKET_OK;

	char buf[read_step_max_size];
	struct rrr_socket_read_session *read_session = NULL;

	struct pollfd pollfd = { fd, POLLIN, 0 };
	ssize_t bytes = 0;
	ssize_t items = 0;
	int bytes_int = 0;

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
		VL_MSG_ERR("Poll error in rrr_socket_read_message\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if ((pollfd.revents & (POLLERR|POLLNVAL)) != 0) {
		VL_MSG_ERR("Poll error in rrr_socket_read_message\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if (items == 0) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
		goto out;
	}

	if (ioctl (fd, FIONREAD, &bytes_int) != 0) {
		VL_MSG_ERR("Error from ioctl in rrr_socket_read_message: %s\n", strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	bytes = bytes_int;

	if (bytes == 0) {
		goto out;
	}

	struct sockaddr src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	/* Read */
	read_retry:
	bytes = recvfrom (
			fd,
			buf,
			read_step_max_size,
			0,
			&src_addr,
			&src_addr_len
	);

	if (bytes == -1) {
		if (errno == EINTR) {
			goto read_retry;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto out;
		}
		VL_MSG_ERR("Error from read in rrr_socket_read_message: %s\n", strerror(errno));
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	if (bytes == 0) {
		VL_MSG_ERR("Bytes was 0 after read in rrr_socket_read_message, despite polling first\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session = __rrr_socket_read_session_collection_maintain_and_find_or_create (
			read_session_collection,
			&src_addr,
			src_addr_len
	);

	if (read_session == NULL) {
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	/* Check for new read session */
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
				VL_MSG_ERR("Could not allocate memory in rrr_socket_read_message\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
			read_session->rx_buf_size = read_step_max_size;
			read_session->rx_buf_wpos = 0;
		}

		/* This number will change after the fixed header is parsed. The first round we can
		 * only read 2 bytes to make sure we don't read in many packets at a time. */
		read_session->target_size = 0;
	}

	if (read_session->read_complete != 0) {
		VL_BUG("Read complete was non-zero in rrr_socket_read_message, read session must be cleared prior to reading more data\n");
	}

	/* Check for expansion of buffer */
	if (bytes + read_session->rx_buf_wpos > read_session->rx_buf_size) {
		ssize_t new_size = read_session->rx_buf_size + (bytes > read_step_max_size ? bytes : read_step_max_size);
		char *new_buf = realloc(read_session->rx_buf_ptr, new_size);
		if (new_buf == NULL) {
			VL_MSG_ERR("Could not re-allocate memory in rrr_socket_read_message\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
		read_session->rx_buf_ptr = new_buf;
		read_session->rx_buf_size = new_size;
	}

	memcpy (read_session->rx_buf_ptr + read_session->rx_buf_wpos, buf, bytes);
	read_session->rx_buf_wpos += bytes;
	read_session->last_read_time = time_get_64();

	if (get_target_size == NULL) {
		read_session->target_size = read_step_initial;
	}
	else if (read_session->target_size == 0) {
		// In the first read, we take a sneak peak at the first bytes to find a length field
		// if it is present. If there is not target size function, the target size becomes
		// the initial bytes parameter (set at the top of the function).
		if (read_session->rx_buf_wpos < read_session->target_size) {
			ret = RRR_SOCKET_READ_INCOMPLETE;
			goto out;
		}

		if ((ret = get_target_size(read_session, get_target_size_arg)) != RRR_SOCKET_OK) {
			goto out;
		}

		if (read_session->target_size == 0) {
			VL_BUG("target_size was still zero after get_target_size in rrr_socket_read_message\n");
		}
	}

	if (read_session->rx_buf_wpos > read_session->target_size) {
			if (read_session->rx_overshoot != NULL) {
				VL_BUG("overshoot was not NULL in rrr_socket_read_message\n");
			}

			read_session->rx_overshoot_size = read_session->rx_buf_wpos - read_session->target_size;
			read_session->rx_buf_wpos -= read_session->rx_overshoot_size;

			read_session->rx_overshoot = malloc(read_session->rx_overshoot_size);
			if (read_session->rx_overshoot == NULL) {
				VL_MSG_ERR("Could not allocate memory for overshoot in rrr_socket_read_message\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}

			memcpy(read_session->rx_overshoot, read_session->rx_buf_ptr + read_session->rx_buf_wpos, read_session->rx_overshoot_size);
	}

	if (read_session->rx_buf_wpos == read_session->target_size && read_session->target_size > 0) {
		read_session->read_complete = 1;
		if (complete_callback != NULL) {
			ret = complete_callback (read_session, complete_callback_arg);
			if (ret != 0) {
				VL_MSG_ERR("Error from callback in rrr_socket_read_message\n");
				goto out;
			}
			RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
			read_session->read_complete = 0;
		}
	}

	out:
	if (ret != RRR_SOCKET_OK && ret != RRR_SOCKET_READ_INCOMPLETE && read_session != NULL) {
		RRR_LINKED_LIST_REMOVE_NODE(
				read_session_collection,
				struct rrr_socket_read_session,
				read_session,
				__rrr_socket_read_session_destroy(node)
		);
	}
	return ret;
}
