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

#include <Python.h>

struct rrr_socket_msg;

int rrr_python3_socket_get_fd (PyObject *self);
int rrr_python3_socket_get_connected_fd (PyObject *self);
const char *rrr_python3_socket_get_filename(PyObject *self);
PyObject *rrr_python3_socket_new (const char *filename);
int rrr_python3_socket_poll (PyObject *socket, int timeout);
int rrr_python3_socket_send (PyObject *socket, struct rrr_socket_msg *message);
int rrr_python3_socket_recv (struct rrr_socket_msg **result, PyObject *socket, int timeout);
int rrr_python3_socket_accept (PyObject *self);
void rrr_python3_socket_close (PyObject *self);

#endif /* RRR_PYTHON3_SOCKET_H */
