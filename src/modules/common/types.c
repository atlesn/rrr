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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../global.h"
#include "types.h"

struct rrr_data_collection *rrr_types_parse_data (
		const char *data, const ssize_t length,
		const struct rrr_type_definition definitions[], const unsigned int definition_length
) {
	struct rrr_data_collection *collection = malloc(sizeof(struct rrr_data_collection));
	if (collection == NULL) {
		VL_MSG_ERR("Could not allocate memory for data collection");
		return NULL;
	}

	collection->count = definition_length;

	collection->definitions = malloc(collection->count * sizeof(*(collection->definitions)));
	if (collection->definitions == NULL) {
		VL_MSG_ERR("Could not allocate memory for %d collection definitions", definition_length);
		goto out_free_collection;
	}
	memset(collection->definitions, '\0', collection->count * sizeof(*(collection->definitions)));

	for (int i = 0; i < definition_length; i++) {
		VL_ASSERT (sizeof(collection->definitions[i]) == sizeof(definitions[i]), type_size_mismatch_in_collection_definition)
		memcpy (&(collection->definitions[i]), &definitions[i], sizeof(collection->definitions[i]));
		collection->data[i] = malloc (definitions[i].length);
		if (collection->data[i] == NULL) {
			VL_MSG_ERR("Could not allocate %d bytes of memory for collection type data", definitions[i].length);
			goto out_free_elements;
		}
	}

	return collection;

	out_free_elements:
	for (int i = 0; i < collection->count; i++) {
		if (collection->data[i] != NULL) {
			free(collection->data[i]);
		}
	}

	out_free_collection_definitions:
	free(collection->definitions);

	out_free_collection:
	free (collection);

	return NULL;
}

void rrr_types_destroy_data (struct rrr_data_collection *collection) {
	for (int i = 0; i < collection->count; i++) {
		free(collection->data[i]);
	}
	free (collection->definitions);
	free (collection);
}
