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

#include <stdlib.h>
#include <string.h>

#include "msgdb_common.h"
#include "../log.h"
#include "../rrr_strerror.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"

static int __rrr_msgdb_common_msg_send_raw_blocking (
	int fd,
	const struct rrr_msg *msg_network,
	ssize_t msg_size
) {
	return rrr_socket_sendto_blocking (
			fd,
			msg_network,
			msg_size,
			NULL,
			0
	);
}

static int __rrr_msgdb_common_msg_send_raw_nonblock (
	int fd,
	const struct rrr_msg *msg_network,
	ssize_t msg_size
) {
	int ret = 0;

	int err = 0;
	ssize_t written_bytes = 0;

	if ((ret = rrr_socket_sendto_nonblock (
		&err,
		&written_bytes,
		fd,
		msg_network,
		msg_size,
		NULL,
		0
	)) != 0) {
		if (ret == RRR_SOCKET_WRITE_INCOMPLETE) {
			if (written_bytes != 0) {
				// Not OK, partial write
				RRR_DBG_2("Partial write in __rrr_msgdb_common_msg_send_raw_nonblock, this cannot be handled. Triggering soft error.\n");
				ret = RRR_SOCKET_SOFT_ERROR;
			}
			else {
				// OK, no bytes were sent
			}
		}
		else {
			RRR_DBG_2("Failed to send message in __rrr_msgdb_common_msg_send_raw_nonblock, return was %i errno is '%s'\n", ret, rrr_strerror(err));
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_common_ctrl_msg_send (
	int fd,
	int flags,
	int do_nonblock
) {
	struct rrr_msg msg = {0};

	rrr_msg_populate_control_msg (
		&msg,
		flags,
		0
	);

	rrr_msg_checksum_and_to_network_endian (
		&msg
	);

	RRR_DBG_3("msgdb fd %i send CTRL flags %i %s\n", fd, flags, (do_nonblock ? "nonblock" : "blocking"));

	return do_nonblock
		? __rrr_msgdb_common_msg_send_raw_nonblock(fd, &msg, sizeof(msg))
		: __rrr_msgdb_common_msg_send_raw_blocking(fd, &msg, sizeof(msg))
	;
}

int rrr_msgdb_common_ctrl_msg_send_nonblock (
	int fd,
	int flags
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, flags, 1);
}

int rrr_msgdb_common_ctrl_msg_send_blocking (
	int fd,
	int flags
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, flags, 0);
}

static int __rrr_msgdb_common_msg_send (
	int fd,
	const struct rrr_msg_msg *msg,
	int do_nonblock
) {
	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;

	RRR_DBG_3("msgdb fd %i send MSG size %" PRIrrrl " %s\n", fd, MSG_TOTAL_SIZE(msg), (do_nonblock ? "nonblock" : "blocking"));

	if ((msg_tmp = malloc(MSG_TOTAL_SIZE(msg))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_msgdb_common_msg_send\n");
		ret = 1;
		goto out;
	}

	memcpy(msg_tmp, msg, MSG_TOTAL_SIZE(msg));

	rrr_msg_msg_prepare_for_network(msg_tmp);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_tmp);

	ret = do_nonblock
		? __rrr_msgdb_common_msg_send_raw_nonblock(fd, (const struct rrr_msg *) msg_tmp, MSG_TOTAL_SIZE(msg))
		: __rrr_msgdb_common_msg_send_raw_blocking(fd, (const struct rrr_msg *) msg_tmp, MSG_TOTAL_SIZE(msg))
	;

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

int rrr_msgdb_common_msg_send_nonblock (
	int fd,
	const struct rrr_msg_msg *msg
) {
	return __rrr_msgdb_common_msg_send(fd, msg, 1);
}

int rrr_msgdb_common_msg_send_blocking (
	int fd,
	const struct rrr_msg_msg *msg
) {
	return __rrr_msgdb_common_msg_send(fd, msg, 0);
}
