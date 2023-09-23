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

#ifndef RRR_DISCERN_STACK_H
#define RRR_DISCERN_STACK_H

#include "util/linked_list.h"
#include "rrr_types.h"

struct rrr_mqtt_topic_linear;
struct rrr_discern_stack;
struct rrr_parse_pos;

struct rrr_discern_stack_collection {
	RRR_LL_HEAD(struct rrr_discern_stack);
};

struct rrr_discern_stack_index_entry {
	rrr_length id;
};

enum rrr_discern_stack_fault {
	RRR_DISCERN_STACK_FAULT_OK,
	RRR_DISCERN_STACK_FAULT_CRITICAL,
	RRR_DISCERN_STACK_FAULT_END_MISSING,
	RRR_DISCERN_STACK_FAULT_SYNTAX_ERROR,
	RRR_DISCERN_STACK_FAULT_INVALID_VALUE,
	RRR_DISCERN_STACK_FAULT_VALUE_MISSING,
	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT
};

#define RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS \
    rrr_length *result, struct rrr_discern_stack_index_entry **new_index, rrr_length *new_index_size, const char *tag, void *arg

#define RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS \
    rrr_length *result, const char *topic_filter, rrr_length topic_filter_size, void *arg

void rrr_discern_stack_collection_clear (
		struct rrr_discern_stack_collection *list
);
const struct rrr_discern_stack *rrr_discern_stack_collection_get (
		const struct rrr_discern_stack_collection *list,
		const char *name
);
int rrr_discern_stack_collection_add_cloned (
		struct rrr_discern_stack_collection *list,
		const struct rrr_discern_stack *discern_stack
);
void rrr_discern_stack_collection_iterate_names (
		const struct rrr_discern_stack_collection *list,
		void (*callback)(const char *name, void *arg),
		void *callback_arg
);
int rrr_discern_stack_collection_execute (
		enum rrr_discern_stack_fault *fault,
		const struct rrr_discern_stack_collection *collection,
		int (*resolve_topic_filter_cb)(RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS),
		int (*resolve_array_tag_cb)(RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS),
		void *resolve_callback_arg,
		int (*apply_cb)(rrr_length result, const char *destination, void *arg),
		void *apply_callback_arg
);
int rrr_discern_stack_collection_iterate_destination_names (
		const struct rrr_discern_stack_collection *collection,
		int (*callback)(const char *discern_stack_name, const char *destination_name, void *arg),
		void *callback_arg
);
int rrr_discern_stack_interpret (
		struct rrr_discern_stack_collection *target,
		enum rrr_discern_stack_fault *fault,
		struct rrr_parse_pos *pos,
		const char *name
);

#endif /* RRR_DISCERN_STACK_H */
