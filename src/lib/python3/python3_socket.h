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

#ifndef RRR_PYTHON3_SOCKET_H
#define RRR_PYTHON3_SOCKET_H

#include "python3_headers.h"

#include "../socket/rrr_msg.h"

// Tell a python3 fork to start calling it's function continuously without
// sending data to it
#define RRR_PYTHON3_MSG_CTRL_START_SOURCING \
	RRR_MSG_CTRL_F_USR_A

struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_mmap_channel;
struct rrr_cmodule_worker;

PyObject *rrr_python3_socket_new (struct rrr_cmodule_worker *worker);
int rrr_python3_socket_send (
		PyObject *socket,
		struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
);

#endif /* RRR_PYTHON3_SOCKET_H */
