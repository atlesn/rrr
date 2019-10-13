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

#ifndef RRR_MAP_H
#define RRR_MAP_H

#include "linked_list.h"

struct rrr_map_item {
	RRR_LINKED_LIST_NODE(struct rrr_map_item);
	char *tag;
	char *value;
};

struct rrr_map {
	RRR_LINKED_LIST_HEAD(struct rrr_map_item);
};

void rrr_map_item_destroy (struct rrr_map_item *item);
void rrr_map_clear (struct rrr_map *map);
int rrr_map_init (struct rrr_map *map);
int rrr_map_item_new (struct rrr_map_item **target, ssize_t field_size);
int rrr_map_item_add (struct rrr_map *map, struct rrr_map_item *item);
int rrr_map_parse_pair (const char *input, void *arg, const char *delimeter);
int rrr_map_parse_pair_arrow (const char *input, void *arg);
int rrr_map_parse_pair_equal (const char *input, void *arg);

#endif /* RRR_MAP_H */
