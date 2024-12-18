/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MAP_H
#define RRR_MAP_H

#include "util/linked_list.h"
#include "rrr_types.h"

#define RRR_MAP_ITERATE_BEGIN(map)									\
	do { RRR_LL_ITERATE_BEGIN(map,struct rrr_map_item);				\
		const char *node_tag = node->tag;							\
		const char *node_value = node->value;						\
		const long long int value_length = node->value_length;			\
		(void)(node_tag); (void)(node_value); (void)(value_length)

#define RRR_MAP_ITERATE_BEGIN_CONST(map)							\
	do { RRR_LL_ITERATE_BEGIN(map,const struct rrr_map_item);		\
		const char *node_tag = node->tag;							\
		const char *node_value = node->value;						\
		const long long int value_length = node->value_length;			\
		(void)(node_tag); (void)(node_value); (void)(value_length)

#define RRR_MAP_ITERATE_END()										\
	RRR_LL_ITERATE_END(); } while (0)

#define RRR_MAP_ITERATE_IS_FIRST()									\
	RRR_LL_ITERATE_IS_FIRST()

#define RRR_MAP_ITERATE_IS_LAST()									\
	RRR_LL_ITERATE_IS_LAST()

#define RRR_MAP_ITERATE_BREAK() \
	RRR_LL_ITERATE_BREAK()

#define RRR_MAP_COUNT(map)											\
	RRR_LL_COUNT(map)

#define RRR_MAP_CLEAR(map)											\
	rrr_map_clear(map)

#define RRR_MAP_ITERATOR_CREATE(name,map) \
	struct rrr_map_iterator name = { 0, map, NULL }

#define RRR_MAP_ITERATOR_NEXT(iterator) \
	rrr_map_iterator_next(iterator)

#define RRR_MAP_MERGE_AND_CLEAR_SOURCE_HEAD(target,source) \
	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(target,source)

// Make sure this is EQUAL to rrr_linked_list_node. Different
// pointer types are OK.
struct rrr_map_item {
	RRR_LL_NODE(struct rrr_map_item);
	char *tag;
	char *value;
	rrr_length value_length;
};

struct rrr_map {
	RRR_LL_HEAD(struct rrr_map_item);
};

struct rrr_map_iterator {
	rrr_length rpos;
	struct rrr_map *source;
	struct rrr_map_item *cur;
};

static inline struct rrr_map_item *rrr_map_iterator_next (
		struct rrr_map_iterator *iterator
) {
	if (iterator->cur == NULL) {
		if (iterator->rpos == 0) {
			iterator->cur = iterator->source->ptr_first;
		}
	}
	else {
		iterator->cur = iterator->cur->ptr_next;
		iterator->rpos++;
	}

	return iterator->cur;
}

void rrr_map_item_destroy (
		struct rrr_map_item *item
);
int rrr_map_item_value_set (
		struct rrr_map_item *item,
		const char *value
);
void rrr_map_clear (
		struct rrr_map *map
);
int rrr_map_item_new (
		struct rrr_map_item **target,
		rrr_length field_size
);
int rrr_map_item_add (
		struct rrr_map *map,
		struct rrr_map_item *item
);
int rrr_map_item_replace_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
);
int rrr_map_item_replace_new_with_callback (
		struct rrr_map *map,
		const char *tag,
		const char *value,
		int (*callback_confirm)(void *arg),
		void *callback_arg
);
int rrr_map_item_replace_new_with_callback (
		struct rrr_map *map,
		const char *tag,
		const char *value,
		int (*callback_confirm)(void *arg),
		void *callback_arg
);
int rrr_map_item_add_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
);
int rrr_map_item_add_new_with_size (
		struct rrr_map *map,
		const char *tag,
		const void *value,
		rrr_length value_length
);
int rrr_map_item_prepend_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
);
int rrr_map_parse_pair (
		const char *input,
		struct rrr_map *target,
		const char *delimeter
);
int rrr_map_parse_pair_arrow (const char *input, void *arg);
int rrr_map_parse_pair_equal (const char *input, void *arg);
int rrr_map_parse_tag_only (const char *input, void *arg);
const char *rrr_map_get_value (
		const struct rrr_map *map,
		const char *tag
);

#endif /* RRR_MAP_H */
