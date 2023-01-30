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

#ifndef RRR_EVENT_COLLECTION_STRUCT_H
#define RRR_EVENT_COLLECTION_STRUCT_H

#include <stddef.h>

#define RRR_EVENT_COLLECTION_STRUCT_MAX 8

struct event_base;
struct event;

struct rrr_event_collection {
	struct event_base *event_base;
	struct event *events[RRR_EVENT_COLLECTION_STRUCT_MAX];
	size_t event_count;
};

#define RRR_EVENT_COLLECTION_STRUCT_INITIALIZER \
    {NULL,{NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL},0}

#endif /* RRR_EVENT_COLLECTION_STRUCT_H */
