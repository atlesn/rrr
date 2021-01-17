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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "type_conversion.h"
#include "type.h"
#include "rrr_types.h"
#include "map.h"
#include "util/macro_utils.h"

#define RRR_TYPE_CONVERT_ARGS \
		struct rrr_type_value **target, const struct rrr_type_value *source

struct rrr_type_conversion_definition {
	const char *name;
	int identifier;
	const struct rrr_type_definition *from;
	const struct rrr_type_definition *to;
	int (*convert)(RRR_TYPE_CONVERT_ARGS);
};

struct rrr_type_conversion_collection {
	size_t item_count;
	const struct rrr_type_conversion_definition **items;
};

static int __rrr_type_convert_h2str (RRR_TYPE_CONVERT_ARGS) {
	int ret = 0;

	char *buf = NULL;

	if (source->element_count == 0) {
		RRR_BUG("BUG: Element count was 0 in __rrr_type_convert_h2str\n");
	}
	if (source->total_stored_length % sizeof(uint64_t) != 0) {
		RRR_BUG("BUG: Stored length not divisible by 8 in __rrr_type_convert_h2str\n");
	}

	rrr_biglength new_size = 0;

	if (source->element_count == 1) {
		if ((ret = rrr_type_definition_h.to_str(&buf, source)) != 0) {
			goto out;
		}
		new_size = strlen(buf);
	}
	else {
		// Maximum output is 20 characters
		// 2^63 =  9,223,372,036,854,775,808
		// 2^64 = 18,446,744,073,709,551,616

		// We use a custom to string function as we have to prefix
		// pad numbers with spaces to make them equal length when there
		// are more than one element

		const size_t max_out_length = 20;
		new_size = max_out_length * source->element_count;

		if (new_size > RRR_LENGTH_MAX) {
			RRR_MSG_0("Can't convert h2str, resulting string data would exceed maximum size (%" PRIrrrbl ">%" PRIrrrl ")\n",
					new_size, RRR_LENGTH_MAX);
			ret = RRR_TYPE_CONVERSION_SOFT_ERROR;
			goto out;
		}

		if ((buf = malloc(new_size)) == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_type_convert_h2str\n");
			ret = RRR_TYPE_CONVERSION_HARD_ERROR;
			goto out;
		}

		memset (buf, ' ', new_size); // Set whole buffer to spaces

		for (size_t i = 0; i < source->element_count; i++) {
			const rrr_biglength rpos = i * (source->total_stored_length / source->element_count);
			const rrr_biglength wpos = max_out_length * i;

			char tmp[max_out_length + 1];

			const int number_length = (
					RRR_TYPE_FLAG_IS_SIGNED(source->flags)
					? snprintf(tmp, sizeof(tmp), "%" PRIi64, *((int64_t *) source->data + rpos))
					: snprintf(tmp, sizeof(tmp), "%" PRIu64, *((uint64_t *) source->data + rpos))
			);

			if (number_length <= 0) {
				RRR_MSG_0("Error from snprintf in __rrr_type_convert_h2str\n");
				ret = RRR_TYPE_CONVERSION_HARD_ERROR;
				goto out;
			}

			tmp[sizeof(tmp) - 1] = '\0';

			// Write right justified in the slot
			const size_t wpos_with_offset = wpos + max_out_length - (unsigned int) number_length;
			memcpy(buf + wpos_with_offset, buf, (unsigned int) number_length);
		}
	}

	if ((ret = rrr_type_value_new_simple (
			target,
			&rrr_type_definition_str,
			0,
			source->tag_length,
			source->tag
	)) != 0) {
		goto out;
	}

	// Length of new_size must be checked prior to allocation
	(*target)->data = buf;
	(*target)->total_stored_length = (rrr_length) new_size;

	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

#define RRR_TYPE_CONVERSION_DEFINE(name_lc,from_uc,to_uc)                                        \
		const struct rrr_type_conversion_definition RRR_PASTE(rrr_type_conversion_,name_lc) = {  \
				RRR_PASTE(RRR_TYPE_NAME_,from_uc) "2" RRR_PASTE(RRR_TYPE_NAME_,to_uc),           \
				RRR_PASTE_4(RRR_TYPE_CONVERSION_,from_uc,2,to_uc),                               \
				&RRR_PASTE(RRR_TYPE_DEFINITION_,from_uc),                                        \
				&RRR_PASTE(RRR_TYPE_DEFINITION_,to_uc),                                          \
				RRR_PASTE(__rrr_type_convert_,name_lc)                                           \
		}

enum rrr_type_conversion {
	RRR_TYPE_CONVERSION_NONE,
	RRR_TYPE_CONVERSION_H2STR
};

RRR_TYPE_CONVERSION_DEFINE(h2str,H,STR);

static const struct rrr_type_conversion_definition *rrr_type_conversions[] = {
		&rrr_type_conversion_h2str,
		NULL
};

const struct rrr_type_conversion_definition *rrr_type_convert_definition_get_from_str (
		const char *str
) {
	for (const struct rrr_type_conversion_definition *method = *rrr_type_conversions; method != NULL; method += sizeof(method)) {
		if (strcmp(str, method->name) == 0) {
			return method;
		}
	}
	return NULL;
}

int rrr_type_convert (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_conversion_definition *method
) {
	int ret = 0;

	*target = NULL;

	if (source->definition != method->from) {
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	ret = method->convert(target, source);

	out:
	return ret;
}

int rrr_type_convert_using_list (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		struct rrr_type_conversion_collection *list
) {

}

void rrr_type_conversion_collection_destroy (
		struct rrr_type_conversion_collection *target
) {
	free(target);
}

int rrr_type_conversion_collection_new_from_map (
		struct rrr_type_conversion_collection **target,
		const struct rrr_map *map
) {
	int ret = 0;

	*target = NULL;

	struct rrr_type_conversion_collection *result = NULL;

	const size_t elements = (size_t) RRR_MAP_COUNT(map);
	const size_t new_size = sizeof(*result) + (sizeof(result->items) * (elements - 1));

	if ((result = malloc(new_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_type_conversion_collection_new_from_map\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	size_t wpos = 0;

	RRR_MAP_ITERATE_BEGIN_CONST(map);
		if (node_tag == NULL || *node_tag == '\0') {
			RRR_BUG("BUG: Node tag was NULL or empty in rrr_type_conversion_collection_new_from_map\n");
		}
		if (wpos == (size_t) map->node_count) {
			RRR_BUG("BUG: wpos out of bounds in rrr_type_conversion_collection_new_from_map, the map must not change while we use it\n");
		}

		if ((result->items[wpos++] = rrr_type_convert_definition_get_from_str(node_tag)) == NULL) {
			RRR_MSG_0("Unknown conversion method '%s' while parsing conversion method list at position %llu\n",
					node_tag, (unsigned long long) wpos - 1);
			ret = RRR_TYPE_CONVERSION_SOFT_ERROR;
			goto out;
		}
	RRR_MAP_ITERATE_END();

	result->item_count = elements;

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		rrr_type_conversion_collection_destroy(result);
	}
	return ret;
}
