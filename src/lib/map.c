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

#include "../global.h"
#include "map.h"
#include "linked_list.h"

void rrr_map_item_destroy (struct rrr_map_item *item) {
	RRR_FREE_IF_NOT_NULL(item->tag);
	RRR_FREE_IF_NOT_NULL(item->value);
	free(item);
}

void rrr_map_clear (struct rrr_map *map) {
	RRR_LINKED_LIST_DESTROY(map, struct rrr_map_item, rrr_map_item_destroy(node));
}

int rrr_map_init (struct rrr_map *map) {
	memset (map, '\0', sizeof(*map));
	return 0;
}

int rrr_map_item_new (struct rrr_map_item **target, ssize_t field_size) {
	int ret = 0;

	struct rrr_map_item *item = malloc(sizeof(*item));
	if (item == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_map_item_new\n");
		ret = 1;
		goto out;
	}
	memset (item, '\0', sizeof(*item));

	item->tag = malloc(field_size);
	item->value = malloc(field_size);

	if (item->tag == NULL || item->value == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_map_item_new\n");
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

int rrr_map_item_add (struct rrr_map *map, struct rrr_map_item *item) {
	RRR_LINKED_LIST_APPEND(map, item);
	return 0;
}

int rrr_map_parse_pair (const char *input, void *arg, const char *delimeter) {
	struct rrr_map *target = arg;

	int ret = 0;
	struct rrr_map_item *column = NULL;

	ssize_t input_length = strlen(input);

	if ((ret = rrr_map_item_new (&column, input_length + 1)) != 0) {
		goto out;
	}

	char *delimeter_pos = strstr(input, delimeter);
	if (delimeter_pos != NULL) {
		strncpy(column->tag, input, delimeter_pos - input);

		const char *pos = delimeter_pos + 2;
		if (*pos == '\0' || pos > (input + input_length)) {
			VL_MSG_ERR("Missing column name after -> in column definition\n");
			ret = 1;
			goto out;
		}

		strcpy(column->value, pos);
	}
	else {
		strcpy(column->tag, input);
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
