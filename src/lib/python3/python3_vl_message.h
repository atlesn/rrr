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

#ifndef RRR_PYTHON3_RRR_MESSAGE_H
#define RRR_PYTHON3_RRR_MESSAGE_H

struct rrr_socket_msg;
struct rrr_message;
struct rrr_message_addr;
struct PyObject;

struct rrr_message *rrr_python3_rrr_message_get_message (
		struct rrr_message_addr *message_addr,
		PyObject *self
);
PyObject *rrr_python3_rrr_message_new_from_message_and_address (
		const struct rrr_socket_msg *msg,
		const struct rrr_message_addr *message_addr
);
PyObject *rrr_python3_rrr_message_new_from_message (
		const struct rrr_socket_msg *msg
);

#endif /* RRR_PYTHON3_RRR_MESSAGE_H */
