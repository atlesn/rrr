/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include "../../../config.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "../log.h"
#include "../allocator.h"
#include "../rrr_strerror.h"
#include "rrr_socket_eventfd.h"
#include "rrr_socket.h"

#ifdef RRR_HAVE_EVENTFD
#	include <sys/eventfd.h>
#endif

void rrr_socket_eventfd_cleanup (
		struct rrr_socket_eventfd *eventfd
) {
#ifdef RRR_HAVE_EVENTFD
	if (eventfd->fd > 0) {
		rrr_socket_close(eventfd->fd);
	}
#else
	if (eventfd->fds[0] > 0) {
		rrr_socket_close(eventfd->fds[0]);
	}
	if (eventfd->fds[1] > 0) {
		rrr_socket_close(eventfd->fds[1]);
	}
#endif
	memset(eventfd, '\0', sizeof(*eventfd));
}

int rrr_socket_eventfd_init (
		struct rrr_socket_eventfd *eventfd
) {
	int ret = 0;

#ifdef RRR_HAVE_EVENTFD
	if ((ret = rrr_socket_eventfd("rrr_socket_eventfd_init")) < 0) {
		RRR_MSG_0("Failed to create eventfd in rrr_socket_eventfd_init\n");
		ret = 1;
		goto out;
	}

	eventfd->fd = ret;
	ret = 0;
#else
	int fds[2];

	if ((ret = rrr_socket_pipe(fds, "rrr_socket_eventfd_init")) != 0) {
		RRR_MSG_0("Failed to create pipe in rrr_socket_eventfd_init\n");
		goto out;
	}

	rrr_socket_eventfd_cleanup(eventfd);	

	memcpy(eventfd->fds, fds, sizeof(fds));
#endif

	out:
	return ret;
}

#ifndef RRR_HAVE_EVENTFD
static int __rrr_socket_eventfd_notify (
		struct rrr_socket_eventfd *eventfd,
		uint8_t count
) {
	int ret = 0;

	if (write(eventfd->fds[1], &count, sizeof(count)) != 1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = RRR_SOCKET_NOT_READY;
			goto out;
		}
		RRR_MSG_0("fd %i<-%i (pipe) error while writing in __rrr_socket_eventfd_notify_if_needed: %s\n",
				eventfd->fds[0], eventfd->fds[1], rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}
#endif

int rrr_socket_eventfd_write (
		struct rrr_socket_eventfd *eventfd,
		uint8_t count
) {
	int ret = RRR_SOCKET_OK;

	if (!RRR_SOCKET_EVENTFD_INITIALIZED(eventfd)) {
		RRR_BUG("BUG: Not initialized in rrr_socket_eventfd_write\n");
	}

#ifdef RRR_HAVE_EVENTFD
	uint64_t count_64 = count;
	if (write(eventfd->fd, &count_64, sizeof(count_64)) != sizeof(count_64)) {
		if (errno == EAGAIN) {
			ret = RRR_SOCKET_NOT_READY;
			goto out;
		}
		RRR_MSG_0("fd %i (eventfd) error while writing in rrr_socket_eventfd_write: %s\n",
				eventfd->fd, rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}
#else
	if ((ret = __rrr_socket_eventfd_notify (eventfd, count)) != 0) {
		goto out;
	}
#endif

	out:
	return ret;
}

int rrr_socket_eventfd_read (
		uint64_t *count,
		struct rrr_socket_eventfd *eventfd
) {
	int ret = 0;

	*count = 0;
	errno = 0;

#ifdef RRR_HAVE_EVENTFD

	ssize_t bytes = read(eventfd->fd, count, sizeof(*count));
	if (bytes == sizeof(*count)) {
		// OK
	}
	else if (errno == EAGAIN) {
		// EAGAIN means count is zero
		*count = 0;
	}
	else {
		RRR_MSG_0("fd %i (eventfd) error while reading in rrr_socket_eventfd_read: %s\n",
				eventfd->fd, rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}
#else
	uint8_t buf[64];
	ssize_t res = read(eventfd->fds[0], buf, sizeof(buf));
	if (res > 0) {
		// OK
	}
	else if (res == 0) {
		RRR_DBG_7("fd %i<-%i (pipe) read returned 0 in rrr_socket_eventfd_read, other end was closed\n", eventfd->fds[0], eventfd->fds[1]);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}
	else if (errno == EWOULDBLOCK || errno == EAGAIN) {
		goto out;
	}
	else {
		RRR_MSG_0("fd %i<-%i (pipe) error while reading in rrr_socket_eventfd_read: %s\n",
				eventfd->fds[0], eventfd->fds[1], rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	uint64_t count_tmp = 0;
	for (ssize_t i = 0; i < res; i++) {
		count_tmp += buf[i];
	}

	*count = count_tmp;
#endif

	out:
	return ret;
}

