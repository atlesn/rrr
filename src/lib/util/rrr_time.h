/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TIME_H
#define RRR_TIME_H

#include <inttypes.h>

struct timeval;
struct timespec;

uint64_t rrr_time_get_64(void);
void rrr_time_gettimeofday (struct timeval *__restrict __tv, uint64_t usec_add);
void rrr_time_gettimeofday_timespec (struct timespec *tspec, uint64_t usec_add);

#endif /* RRR_TIME_H */
