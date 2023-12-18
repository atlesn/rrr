/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_LIMITS_H
#define RRR_LIMITS_H

#include <limits.h>

/* FreeBSD name */
#ifdef _POSIX_HOST_NAME_MAX
#  define RRR_HOST_NAME_MAX       _POSIX_HOST_NAME_MAX
#else
#  define RRR_HOST_NAME_MAX       HOST_NAME_MAX
#endif

#endif /* RRR_LIMITS_H */
