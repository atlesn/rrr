/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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
#include "allocator.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

void rrr_map_item_destroy (
		struct rrr_map_item *item
) {
	RRR_FREE_IF_NOT_NULL(item->tag);
	RRR_FREE_IF_NOT_NULL(item->value);
	rrr_free(item);
}

void rrr_map_clear (
		struct rrr_map *map
) {
	RRR_LL_DESTROY(map, struct rrr_map_item, rrr_map_item_destroy(node));
}

static int __rrr_map_item_new (
		struct rrr_map_item **target,
		rrr_length tag_size,
		rrr_length value_size
) {
	int ret = 0;

	struct rrr_map_item *item = rrr_allocate(sizeof(*item));
	if (item == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_map_item_new\n");
		ret = 1;
		goto out;
	}
	memset (item, '\0', sizeof(*item));

	item->tag = rrr_allocate_zero(tag_size + 1);
	item->value = rrr_allocate_zero(value_size);

	if (item->tag == NULL || item->value == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_map_item_new\n");
		ret = 1;
		goto out;
	}

	*target = item;
	item = NULL;

	out:
	if (item != NULL) {
		rrr_map_item_destroy(item);
	}
	return ret;
}

int rrr_map_item_new (
		struct rrr_map_item **target,
		rrr_length field_size
) {
	return __rrr_map_item_new(target, field_size, field_size);
}

static void __rrr_map_item_remove_by_tag (
		struct rrr_map *map,
		const char *tag
) {
	RRR_LL_ITERATE_BEGIN(map, struct rrr_map_item);
		if (tag == NULL && node->tag == NULL) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (tag != NULL && node->tag != NULL) {
			if (strcmp(tag, node->tag) == 0) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(map, 0; rrr_map_item_destroy(node));
}

static void __rrr_map_item_add (
		struct rrr_map *map,
		struct rrr_map_item *item,
		int do_prepend,
		int do_unique
) {
	if (do_unique) {
		__rrr_map_item_remove_by_tag(map, item->tag);
	}

	if (do_prepend) {
		RRR_LL_UNSHIFT(map, item);
	}
	else {
		RRR_LL_APPEND(map, item);
	}
}

int rrr_map_item_add (
		struct rrr_map *map,
		struct rrr_map_item *item
) {
	__rrr_map_item_add(map, item, 0, 0);
	return 0;
}

static int __rrr_map_item_new_with_values (
		struct rrr_map_item **result,
		const char *tag,
		const char *value
) {
	int ret = 0;

	*result = NULL;

	struct rrr_map_item *item_new = NULL;

	// Remember + 1 and minimum size 1
	rrr_length tag_size = rrr_length_from_size_t_bug_const (tag != NULL ? strlen(tag) + 1 : 1);
	rrr_length value_size = rrr_length_from_size_t_bug_const(value != NULL ? strlen(value) + 1 : 1);
	rrr_length max_size = (tag_size > value_size ? tag_size : value_size);

	if ((ret = rrr_map_item_new(&item_new, max_size)) != 0) {
		goto out;
	}

	if (tag != NULL) {
		memcpy(item_new->tag, tag, tag_size);
	}
	if (value != NULL) {
		memcpy(item_new->value, value, value_size);
	}

	*result = item_new;
	item_new = NULL;

	out:
	if (item_new != NULL) {
		rrr_map_item_destroy(item_new);
	}
	return ret;
}

static int __rrr_map_item_add_new (
		struct rrr_map *map,
		const char *tag,
		const char *value,
		int do_prepend,
		int do_unique
) {
	int ret = 0;

	struct rrr_map_item *item_new = NULL;

	if ((ret = __rrr_map_item_new_with_values (&item_new, tag, value)) != 0) {
		goto out;
	}

	__rrr_map_item_add(map, item_new, do_prepend, do_unique);

	out:
	return ret;
}

int rrr_map_item_replace_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
) {
	return __rrr_map_item_add_new(map, tag, value, 0, 1);
}

int rrr_map_item_replace_new_with_callback (
		struct rrr_map *map,
		const char *tag,
		const char *value,
		int (*callback_confirm)(void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_map_item *item_new = NULL;

	if ((ret = __rrr_map_item_new_with_values (&item_new, tag, value)) != 0) {
		goto out;
	}

	if ((ret = callback_confirm(callback_arg)) != 0) {
		goto out_destroy_item;
	}

	__rrr_map_item_add(map, item_new, 0, 1);

	goto out;
	out_destroy_item:
		rrr_map_item_destroy(item_new);
	out:
		return ret;
}

int rrr_map_item_add_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
) {
	return __rrr_map_item_add_new(map, tag, value, 0, 0);
}

int rrr_map_item_add_new_with_size (
		struct rrr_map *map,
		const char *tag,
		const void *value,
		rrr_length value_size
) {
	int ret = 0;

	struct rrr_map_item *item_new = NULL;

	if ((ret = __rrr_map_item_new (&item_new, rrr_length_from_size_t_bug_const(strlen(tag)), value_size)) != 0) {
		goto out;
	}

	strcpy(item_new->tag, tag);
	memcpy(item_new->value, value, value_size);

	__rrr_map_item_add(map, item_new, 0, 0);

	out:
	return ret;
}

int rrr_map_item_prepend_new (
		struct rrr_map *map,
		const char *tag,
		const char *value
) {
	return __rrr_map_item_add_new(map, tag, value, 1, 0);
}

int rrr_map_parse_pair (
		const char *input,
		struct rrr_map *target,
		const char *delimeter
) {
	int ret = 0;
	struct rrr_map_item *column = NULL;

	rrr_length input_length = rrr_length_from_size_t_bug_const(strlen(input));

	if ((ret = rrr_map_item_new (&column, input_length + 1)) != 0) {
		goto out;
	}

	if (delimeter == NULL || *delimeter == '\0') {
		strcpy(column->tag, input);
	}
	else {
		const char *delimeter_pos = strstr(input, delimeter);
		const size_t delimeter_length = strlen(delimeter);

		if (delimeter_pos != NULL) {
			strncpy(column->tag, input, rrr_length_from_ptr_sub_bug_const(delimeter_pos, input));

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
