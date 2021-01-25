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

#include "../log.h"
#include "msgdb_client.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket_client.h"

int rrr_msgdb_client_open (
	struct rrr_msgdb_client_conn *conn,
	const char *path
) {
	int ret = 0;

	if (conn->fd != 0) {
		goto out;
	}

	if ((ret = rrr_socket_unix_connect (&conn->fd, "msgdb_client", path, 0)) != 0) {
		goto out;
	}

	out:
	return ret;
}

void rrr_msgdb_client_close (
	struct rrr_msgdb_client_conn *conn
) {
	if (conn->fd > 0) {
		rrr_socket_close_no_unlink(conn->fd);
		conn->fd = 0;
	}
}

void rrr_msgdb_client_close_void (
	void *conn
) {
	rrr_msgdb_client_close(conn);
}

int rrr_msgdb_client_put (
	struct rrr_msgdb_client_conn *conn,
	const struct rrr_msg_msg *msg
) {
	int ret = 0;

	out:
	return ret;
}
