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

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "map.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

void rrr_map_item_destroy (
		struct rrr_map_item *item
) {
	RRR_FREE_IF_NOT_NULL(item->tag);
	RRR_FREE_IF_NOT_NULL(item->value);
	free(item);
}

void rrr_map_clear (
		struct rrr_map *map
) {
	RRR_LL_DESTROY(map, struct rrr_map_item, rrr_map_item_destroy(node));
}

int rrr_map_item_new (
		struct rrr_map_item **target,
		ssize_t field_size
) {
	int ret = 0;

	struct rrr_map_item *item = malloc(sizeof(*item));
	if (item == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_map_item_new\n");
		ret = 1;
		goto out;
	}
	memset (item, '\0', sizeof(*item));

	item->tag = malloc(field_size);
	item->value = malloc(field_size);

	if (item->tag == NULL || item->value == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_map_item_new\n");
		ret = 1;
		goto out;
	}

	memset(item->tag, '\0', field_size);
	memset(item->value, '\0', field_size);

	*target = item;
	item = NULL;

	out:
	if (item != NULL) {
		rrr_map_item_destroy(item);
	}
	return ret;
}

int rrr_map_item_add (
		struct rrr_map *map,
		struct rrr_map_item *item
) {
	RRR_LL_APPEND(map, item);
	return 0;
}

static int __rrr_map_item_add_new (
		struct rrr_map *map,
		const char *tag,
		const char *value,
		int do_prepend
) {
	int ret = 0;

	struct rrr_map_item *item_new = NULL;

	// Remember + 1 and minimum size 1
	size_t tag_size = (tag != NULL ? strlen(tag) + 1 : 1);
	size_t value_size = (value != NULL ? strlen(value) + 1 : 1);
	size_t max_size = (tag_size > value_size ? tag_size : value_size);

	if ((ret = rrr_map_item_new(&item_new, max_size)) != 0) {
		goto out;
	}

	if (tag != NULL) {
		memcpy(item_new->tag, tag, tag_size);
	}
	if (value != NULL) {
		memcpy(item_new->value, value, value_size);
	}

	if (do_prepend) {
		RRR_LL_UNSHIFT(map, item_new);
	}
	else {
		RRR_LL_APPEND(map, item_new);
	}
	item_new = NULL;

	out:
	if (item_new != NULL) {
		rrr_map_item_destroy(item_new);
	}
	return ret;
}

int rrr_map_item_add_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
) {
	return __rrr_map_item_add_new(map, tag, value, 0);
}

int rrr_map_item_prepend_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
) {
	return __rrr_map_item_add_new(map, tag, value, 1);
}

int rrr_map_parse_pair (
		const char *input,
		struct rrr_map *target,
		const char *delimeter
) {
	int ret = 0;
	struct rrr_map_item *column = NULL;

	ssize_t input_length = strlen(input);

	if ((ret = rrr_map_item_new (&column, input_length + 1)) != 0) {
		goto out;
	}

	if (delimeter == NULL || *delimeter == '\0') {
		strcpy(column->tag, input);
	}
	else {
		char *delimeter_pos = strstr(input, delimeter);
		size_t delimeter_length = strlen(delimeter);

		if (delimeter_pos != NULL) {
			strncpy(column->tag, input, delimeter_pos - input);

			const char *pos = delimeter_pos + delimeter_length;
			if (*pos == '\0' || pos > (input + input_length)) {
				RRR_MSG_0("Missing value after delimeter '%s' in definition '%s'\n", delimeter, input);
				ret = 1;
				goto out;
			}

			strcpy(column->value, pos);
		}
		else {
			strcpy(column->tag, input);
		}
	}

	rrr_map_item_add(target, column);
	column = NULL;

	out:
	if (column != NULL) {
		rrr_map_item_destroy(column);
	}

	return ret;
}

int rrr_map_parse_pair_arrow (const char *input, void *arg) {
	return rrr_map_parse_pair (input, arg, "->");
}

int rrr_map_parse_pair_equal (const char *input, void *arg) {
	return rrr_map_parse_pair (input, arg, "=");
}

int rrr_map_parse_tag_only (const char *input, void *arg) {
	return rrr_map_parse_pair (input, arg, NULL);
}

const char *rrr_map_get_value (
		const struct rrr_map *map, const char *tag
) {
	RRR_LL_ITERATE_BEGIN(map, const struct rrr_map_item);
		if (strcmp (node->tag, tag) == 0) {
			return node->value;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}
