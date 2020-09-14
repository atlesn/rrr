/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_PYTHON3_HEADERS_H
#define RRR_PYTHON3_HEADERS_H

// Must be included BEFORE libc-files due to problems on BSD
#include "../util/rrr_time.h"

// Must include these BEFORE python due to problems on BSD
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

// Due to warnings in python (which defines this)
#undef _POSIX_C_SOURCE
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#undef _POSIX_C_SOURCE

#include <structmember.h>
#include <object.h>

#endif /* RRR_PYTHON3_HEADERS_H */

