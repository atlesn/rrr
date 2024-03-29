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

#ifndef RRR_EVENT_HANDLE_STRUCT_H
#define RRR_EVENT_HANDLE_STRUCT_H

#include <sys/time.h>

typedef void *rrr_event;
typedef struct rrr_event_handle {
	rrr_event event;
	struct timeval interval;
} rrr_event_handle;

#define RRR_EVENT_HANDLE_STRUCT_INITIALIZER \
    {NULL,{0,0}}

#define EVENT_INITIALIZED(e) \
    (e.event != NULL)

#endif /* RRR_EVENT_HANDLE_STRUCT_H */
