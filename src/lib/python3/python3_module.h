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

#ifndef RRR_PYTHON3_MODULE_H
#define RRR_PYTHON3_MODULE_H

#include "python3_headers.h"

extern PyTypeObject rrr_python3_socket_type;
extern PyTypeObject rrr_python3_rrr_msg_msg_type;
extern PyTypeObject rrr_python3_config_type;
extern PyTypeObject rrr_python3_array_type;
extern PyTypeObject rrr_python3_array_value_type;

static inline int rrr_python3_socket_check(PyObject *op) { return (Py_TYPE(op) == &rrr_python3_socket_type); }
static inline int rrr_python3_rrr_msg_msg_check(PyObject *op) { return (Py_TYPE(op) == &rrr_python3_rrr_msg_msg_type); }
static inline int rrr_python3_config_check(PyObject *op) { return (Py_TYPE(op) == &rrr_python3_config_type); }

int rrr_python3_module_append_inittab(void);
void rrr_python3_module_dump_dict_keys(void);

#endif /* RRR_PYTHON3_MODULE_H */
