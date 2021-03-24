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
#include "util/hex.h"

#define RRR_TYPE_CONVERT_ARGS \
		struct rrr_type_value **target, const struct rrr_type_value *source, const int flags

struct rrr_type_conversion_definition {
	const char *name;
	int identifier;
	const struct rrr_type_definition *from;
	const struct rrr_type_definition *to;
	int (*convert)(RRR_TYPE_CONVERT_ARGS);
};

struct rrr_type_conversion_collection {
	size_t item_count;
	const struct rrr_type_conversion_definition *items[1];
};

static int __rrr_type_convert_clone_set_new_definition (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_definition *new_definition,
		int with_data
) {
	int ret = 0;

	if ((ret = rrr_type_value_clone(target, source, with_data)) != 0) {
		goto out;
	}

	(*target)->definition = new_definition;

	out:
	return ret;
}

static int __rrr_type_convert_clone_set_new_definition_with_data (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_definition *new_definition
) {
	return __rrr_type_convert_clone_set_new_definition (target, source, new_definition, 1);
}

static int __rrr_type_convert_clone_set_new_definition_no_data (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_definition *new_definition
) {
	return __rrr_type_convert_clone_set_new_definition (target, source, new_definition, 0);
}

#define TYPE_H_ENSURE()                                                                                            \
    (void)(flags);                                                                                                 \
    do {if (!RRR_TYPE_IS_64(source->definition->type)) { return RRR_TYPE_CONVERSION_NOT_POSSIBLE; }} while (0)

#define TYPE_BLOB_ENSURE()                                                                                         \
    do {if (((flags & RRR_TYPE_CONVERT_F_STRICT_BLOBS) && !RRR_TYPE_IS_BLOB_EXCACT(source->definition->type)) ||   \
        !RRR_TYPE_IS_BLOB(source->definition->type)) { return RRR_TYPE_CONVERSION_NOT_POSSIBLE; }} while (0)

#define TYPE_STR_ENSURE()                                                                                          \
    do {if (((flags & RRR_TYPE_CONVERT_F_STRICT_STRINGS) && !RRR_TYPE_IS_STR_EXCACT(source->definition->type)) ||  \
        !RRR_TYPE_IS_STR(source->definition->type)) { return RRR_TYPE_CONVERSION_NOT_POSSIBLE; }} while (0)

#define TYPE_MSG_ENSURE()                                                                                          \
    (void)(flags);                                                                                                 \
    do {if (!RRR_TYPE_IS_MSG(source->definition->type)) { return RRR_TYPE_CONVERSION_NOT_POSSIBLE; }} while (0)

#define TYPE_VAIN_ENSURE()                                                                                          \
    (void)(flags);                                                                                                 \
    do {if (!RRR_TYPE_IS_VAIN(source->definition->type)) { return RRR_TYPE_CONVERSION_NOT_POSSIBLE; }} while (0)

static int __rrr_type_convert_h2str (RRR_TYPE_CONVERT_ARGS) {
	 TYPE_H_ENSURE();

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

		if ((buf = malloc((size_t) new_size)) == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_type_convert_h2str\n");
			ret = RRR_TYPE_CONVERSION_HARD_ERROR;
			goto out;
		}

		memset (buf, ' ', (size_t) new_size); // Set whole buffer to spaces

		for (size_t i = 0; i < source->element_count; i++) {
			const rrr_biglength rpos = i * sizeof(uint64_t);
			const rrr_biglength wpos = max_out_length * i;

			char tmp[max_out_length + 1];

			const int number_length = (
					RRR_TYPE_FLAG_IS_SIGNED(source->flags)
					// Add parentheses around pointer addition to avoid compiler converting
					// it to array subscripting (multiplying rpos with 8)
					? snprintf(tmp, sizeof(tmp), "%" PRIi64, *((int64_t *) (source->data + rpos)))
					: snprintf(tmp, sizeof(tmp), "%" PRIu64, *((uint64_t *) (source->data + rpos)))
			);

			if (number_length <= 0) {
				RRR_MSG_0("Error from snprintf in __rrr_type_convert_h2str\n");
				ret = RRR_TYPE_CONVERSION_HARD_ERROR;
				goto out;
			}

			// Write right justified in the slot
			const rrr_biglength wpos_with_offset = wpos + max_out_length - (rrr_biglength) number_length;

			memcpy(buf + wpos_with_offset, tmp, (size_t) number_length);
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
	(*target)->element_count = source->element_count;

	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

static int __rrr_type_convert_h2vain (RRR_TYPE_CONVERT_ARGS) {
	TYPE_H_ENSURE();
	int ret = 0;

	if (source->element_count > 1) {
		RRR_DBG_3("  E h2vain refusing to convert multiple values\n");
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	if (*((int64_t*) source->data) != 0) {
		RRR_DBG_3("  E h2vain source value was not zero, not converting\n");
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	ret = rrr_type_new_vain(target, source->tag_length, source->tag);

	out:
	return ret;
}


static int __rrr_type_convert_blob2str (RRR_TYPE_CONVERT_ARGS) {
	TYPE_BLOB_ENSURE();
	return __rrr_type_convert_clone_set_new_definition_with_data(target, source, &rrr_type_definition_str);
}

static int __rrr_type_convert_blob2blob (RRR_TYPE_CONVERT_ARGS) {
	TYPE_BLOB_ENSURE();
	return __rrr_type_convert_clone_set_new_definition_with_data(target, source, &rrr_type_definition_blob);
}

static int __rrr_type_convert_blob2hex (RRR_TYPE_CONVERT_ARGS) {
	TYPE_BLOB_ENSURE();

	int ret = 0;

	char *data_new = NULL;

	rrr_biglength data_length_new = 0;

	if ((ret = rrr_hex_bin_to_hex(&data_new, &data_length_new, source->data, source->total_stored_length)) != 0) {
		goto out;
	}

	if (data_length_new > RRR_LENGTH_MAX) {
		RRR_MSG_0("Resulting data too long in while converting blob tpye of size %" PRIrrrl "to hex\n",
				source->total_stored_length);
		ret = RRR_TYPE_CONVERSION_SOFT_ERROR;
		goto out;
	}

	if ((ret = __rrr_type_convert_clone_set_new_definition_no_data(target, source, &rrr_type_definition_str)) != 0) {
		goto out;
	}

	rrr_type_value_set_data(*target, data_new, (rrr_length) data_length_new);
	data_new = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(data_new);
	return ret;
}

static int __rrr_type_convert_str2str (RRR_TYPE_CONVERT_ARGS) {
	TYPE_STR_ENSURE();
	return __rrr_type_convert_clone_set_new_definition_with_data(target, source, &rrr_type_definition_str);
}

static int __rrr_type_convert_str2blob (RRR_TYPE_CONVERT_ARGS) {
	TYPE_STR_ENSURE();
	if (source->total_stored_length == 0) {
		RRR_DBG_3("  E str2blob not possible for empty string\n");
		return RRR_TYPE_CONVERSION_NOT_POSSIBLE;
	}
	return __rrr_type_convert_clone_set_new_definition_with_data(target, source, &rrr_type_definition_blob);
}

static int __rrr_type_convert_str2h (RRR_TYPE_CONVERT_ARGS) {
	TYPE_STR_ENSURE();

	if (source->element_count == 0) {
		RRR_BUG("BUG: Element count was 0 in __rrr_type_convert_str2h\n");
	}
	if (source->total_stored_length % source->element_count != 0) {
		RRR_BUG("BUG: Stored length not divisible by element count in __rrr_type_convert_str2h\n");
	}

	int ret = 0;

	char *data_new = NULL;
	struct rrr_type_value *value_new = NULL;

	if (source->total_stored_length == 0) {
		RRR_DBG_3("  E str2h not possible for empty string\n");
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	int found_sign = 0;
	for (const char *pos = source->data; pos < source->data + source->total_stored_length; pos++) {
		if ((*pos >= '0' && *pos <= '9') || (*pos == ' ') || (*pos == '+')) {
			// OK
		}
		else if (*pos == '-') {
			// OK, some values are signed
			found_sign = 1;
		}
		else {
			RRR_DBG_3("  E str2h not possible, non numeric character %c encountered\n", *pos);
			ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
			goto out;
		}
	}

	const rrr_biglength size_new = source->element_count * sizeof(uint64_t);

	if (size_new > RRR_LENGTH_MAX) {
		RRR_MSG_0("Size exceeds maximum in __rrr_type_convert_str2h\n");
		ret = 1;
		goto out;
	}

	if ((data_new = malloc((size_t) size_new)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_convert_str2h\n");
		ret = 1;
		goto out;
	}

	// Maximum number size is 20 characters, allow some more
	// in case input data begins with spaces or zeros
	// 2^63 =  9,223,372,036,854,775,808
	// 2^64 = 18,446,744,073,709,551,616

	const rrr_length source_element_size_max = 64;
	const rrr_length source_element_size = source->total_stored_length / source->element_count;
	if (source_element_size > source_element_size_max) {
		RRR_DBG_3("  E str2h refusing to convert input > 64 bytes (is %" PRIrrrl ")\n", source_element_size);
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	char *wpos = data_new;
	const char *end = source->data + source->total_stored_length;
	for (const char *rpos = source->data; rpos < end; rpos += source_element_size) {
		char tmp_buf[source_element_size_max + 1];
		memcpy(tmp_buf, rpos, (size_t) source_element_size);
		tmp_buf[source_element_size] = '\0';

		union {
			long long int i;
			unsigned long long int u;
		} tmp_num;

		if (found_sign) {
			const char *endptr = NULL;
			tmp_num.i = strtoll(tmp_buf, (char **) &endptr, 10);
			if (*endptr != '\0') {
				RRR_DBG_3("  E str2h strtoll failed for input data '%s'\n", tmp_buf);
				ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
				goto out;
			}
		}
		else {
			const char *endptr = NULL;
			tmp_num.u = strtoull(tmp_buf, (char **) &endptr, 10);
			if (*endptr != '\0') {
				RRR_DBG_3("  E str2h strtoull failed for input data '%s'\n", tmp_buf);
				ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
				goto out;
			}
		}

		memcpy(wpos, &tmp_num, sizeof(uint64_t));
		wpos += sizeof(uint64_t);
	}

	if ((ret = rrr_type_value_new_simple (
			&value_new,
			&rrr_type_definition_h,
			(found_sign ? RRR_TYPE_FLAG_SIGNED : 0),
			source->tag_length,
			source->tag
	)) != 0) {
		goto out;
	}

	value_new->element_count = source->element_count;
	rrr_type_value_set_data(value_new, data_new, (rrr_length) size_new);
	data_new = NULL;

	*target = value_new;
	value_new = NULL;

	out:
	rrr_type_value_destroy(value_new);
	RRR_FREE_IF_NOT_NULL(data_new);
	return ret;
}

static int __rrr_type_convert_str2vain (RRR_TYPE_CONVERT_ARGS) {
	TYPE_STR_ENSURE();

	int ret = 0;

	if (source->element_count > 1) {
		RRR_DBG_3("  E str2vain refusing to convert multiple values\n");
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	if (source->total_stored_length != 0) {
		RRR_DBG_3("  E str2vain refusing to convert value with non-zero length\n");
		ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
		goto out;
	}

	ret = rrr_type_new_vain(target, source->tag_length, source->tag);

	out:
	return ret;
}

static int __rrr_type_convert_msg2blob (RRR_TYPE_CONVERT_ARGS) {
	TYPE_MSG_ENSURE();
	return __rrr_type_convert_clone_set_new_definition_with_data(target, source, &rrr_type_definition_blob);
}

static int __rrr_type_convert_vain2h (RRR_TYPE_CONVERT_ARGS) {
	TYPE_VAIN_ENSURE();
	return rrr_type_new_h(target, source->tag_length, source->tag, 1);
}

static int __rrr_type_convert_vain2str (RRR_TYPE_CONVERT_ARGS) {
	TYPE_VAIN_ENSURE();

	return rrr_type_value_new (
		target,
		&rrr_type_definition_str,
		0,
		source->tag_length,
		source->tag,
		0,
		NULL,
		1,
		NULL,
		0
	);
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
	RRR_TYPE_CONVERSION_H2STR,
	RRR_TYPE_CONVERSION_H2VAIN,
	RRR_TYPE_CONVERSION_BLOB2STR,
	RRR_TYPE_CONVERSION_BLOB2BLOB,
	RRR_TYPE_CONVERSION_BLOB2HEX,
	RRR_TYPE_CONVERSION_STR2STR,
	RRR_TYPE_CONVERSION_STR2BLOB,
	RRR_TYPE_CONVERSION_STR2H,
	RRR_TYPE_CONVERSION_STR2VAIN,
	RRR_TYPE_CONVERSION_MSG2BLOB,
	RRR_TYPE_CONVERSION_VAIN2H,
	RRR_TYPE_CONVERSION_VAIN2STR
};

RRR_TYPE_CONVERSION_DEFINE(h2str,H,STR);
RRR_TYPE_CONVERSION_DEFINE(h2vain,H,VAIN);
RRR_TYPE_CONVERSION_DEFINE(blob2str,BLOB,STR);
RRR_TYPE_CONVERSION_DEFINE(blob2blob,BLOB,BLOB);
RRR_TYPE_CONVERSION_DEFINE(blob2hex,BLOB,HEX);
RRR_TYPE_CONVERSION_DEFINE(str2str,STR,STR);
RRR_TYPE_CONVERSION_DEFINE(str2blob,STR,BLOB);
RRR_TYPE_CONVERSION_DEFINE(str2h,STR,H);
RRR_TYPE_CONVERSION_DEFINE(str2vain,STR,VAIN);
RRR_TYPE_CONVERSION_DEFINE(vain2h,VAIN,H);
RRR_TYPE_CONVERSION_DEFINE(vain2str,VAIN,STR);
RRR_TYPE_CONVERSION_DEFINE(msg2blob,MSG,BLOB);

static const struct rrr_type_conversion_definition *rrr_type_conversions[] = {
		&rrr_type_conversion_h2str,
		&rrr_type_conversion_h2vain,
		&rrr_type_conversion_blob2str,
		&rrr_type_conversion_blob2blob,
		&rrr_type_conversion_blob2hex,
		&rrr_type_conversion_str2str,
		&rrr_type_conversion_str2blob,
		&rrr_type_conversion_str2h,
		&rrr_type_conversion_str2vain,
		&rrr_type_conversion_msg2blob,
		&rrr_type_conversion_vain2h,
		&rrr_type_conversion_vain2str

};

static const struct rrr_type_conversion_definition *__rrr_type_convert_definition_get_from_str (
		const char *str
) {
	for (size_t i = 0; i < sizeof(rrr_type_conversions) / sizeof(*rrr_type_conversions); i++) {
		if (strcmp(str, rrr_type_conversions[i]->name) == 0) {
			return rrr_type_conversions[i];
		}
	}
	return NULL;
}

static int __rrr_type_convert (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_conversion_definition *method,
		const int flags
) {
	int ret = 0;

	*target = NULL;

	if (source->definition == method->to) {
		ret = rrr_type_value_clone(target, source, 1);
	}
	else {
		ret = method->convert(target, source, flags);
	}

	return ret;
}

static int __rrr_type_convert_using_list (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_conversion_collection *list,
		const size_t pos,
		const int flags
) {
	if (pos > list->item_count) {
		RRR_BUG("BUG: Position out of bounds in __rrr_type_convert_using_list\n");
	}

	int ret = 0;

	*target = NULL;

	struct rrr_type_value *result_local = NULL;

	if (pos == list->item_count) {
		ret = RRR_TYPE_CONVERSION_DONE;
		goto out;
	}

	const struct rrr_type_conversion_definition *method = list->items[pos];

	const struct rrr_type_value *next_source = NULL;

	RRR_DBG_3(" >> %llu/%llu %s->%s\n",
			(unsigned long long) pos + 1,
			(unsigned long long) list->item_count,
			source->definition->identifier,
			method->name
	);

	if ((ret = __rrr_type_convert(&result_local, source, method, flags)) != 0) {
		RRR_DBG_3("  X type %s\n", source->definition->identifier);
		if (ret == RRR_TYPE_CONVERSION_NOT_POSSIBLE && (flags & RRR_TYPE_CONVERT_F_ON_ERROR_TRY_NEXT)) {
			next_source = source;
		}
		else {
			RRR_DBG_3("Conversion failure in list at position %llu, could not convert value of type '%s' using method '%s'\n",
					(long long unsigned) pos, source->definition->identifier, method->name);
			goto out;
		}
	}
	else {
		RRR_DBG_3("  > type %s\n", result_local->definition->identifier);
		next_source = result_local;
	}

	// The innermost function eventually writes to target
	if ((ret = __rrr_type_convert_using_list (target, next_source, list, pos + 1, flags)) != 0) {
		if (ret == RRR_TYPE_CONVERSION_DONE) {
			if (result_local == NULL) {
				ret = RRR_TYPE_CONVERSION_NOT_POSSIBLE;
				goto out;
			}

			*target = result_local;
			result_local = NULL;
			ret = 0;
		}
	}

	out:
	if (result_local != NULL) {
		rrr_type_value_destroy(result_local);
	}
	return ret;
}

int rrr_type_convert_using_list (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		const struct rrr_type_conversion_collection *list,
		const int flags
) {
	return __rrr_type_convert_using_list (target, source, list, 0, flags);
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

		if ((result->items[wpos++] = __rrr_type_convert_definition_get_from_str(node_tag)) == NULL) {
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
