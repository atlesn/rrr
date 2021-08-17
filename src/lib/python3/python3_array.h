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

#ifndef RRR_PYTHON3_ARRAY_H
#define RRR_PYTHON3_ARRAY_H

#include "python3_headers.h"

#include <stdio.h>

struct rrr_python3_array_data;
struct rrr_python3_array_value_data;

//int rrr_python3_array_value_count (struct rrr_python3_array_value_data *data);
Py_ssize_t rrr_python3_array_count (struct rrr_python3_array_data *data);
int rrr_python3_array_check (PyObject *object);
int rrr_python3_array_value_check (PyObject *object);

PyObject *rrr_python3_array_new (void);
int rrr_python3_array_iterate (
		PyObject *self,
		int (*callback)(PyObject *tag, PyObject *value, uint8_t type_orig, void *arg),
		void *callback_arg
);
int rrr_python3_array_append_value_with_list (
		PyObject *self,
		PyObject *tag,
		PyObject *value,
		uint8_t type_orig
);

#endif /* RRR_PYTHON3_ARRAY_H */
