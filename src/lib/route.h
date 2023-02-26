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

#ifndef RRR_ROUTE_H
#define RRR_ROUTE_H

#include "util/linked_list.h"

struct rrr_route;
struct rrr_parse_pos;

struct rrr_route_collection {
	RRR_LL_HEAD(struct rrr_route);
};

enum rrr_route_fault {
	RRR_ROUTE_FAULT_OK,
	RRR_ROUTE_FAULT_CRITICAL,
	RRR_ROUTE_FAULT_END_MISSING,
	RRR_ROUTE_FAULT_SYNTAX_ERROR,
	RRR_ROUTE_FAULT_INVALID_VALUE,
	RRR_ROUTE_FAULT_VALUE_MISSING,
	RRR_ROUTE_FAULT_INVALID_TYPE,
	RRR_ROUTE_FAULT_STACK_COUNT
};

void rrr_route_collection_clear (
		struct rrr_route_collection *list
);
const struct rrr_route *rrr_route_collection_get (
		const struct rrr_route_collection *list,
		const char *name
);
int rrr_route_collection_add_cloned (
		struct rrr_route_collection *list,
		const struct rrr_route *route
);
void rrr_route_collection_iterate_names (
		const struct rrr_route_collection *list,
		void (*callback)(const char *name, void *arg),
		void *callback_arg
);
int rrr_route_execute (
		enum rrr_route_fault *fault,
		const struct rrr_route *route,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		int (*apply_cb)(int result, const char *instance, void *arg),
		void *callback_arg
);
int rrr_route_interpret (
		struct rrr_route_collection *target,
		enum rrr_route_fault *fault,
		struct rrr_parse_pos *pos,
		const char *name
);

#endif /* RRR_ROUTE_H */
