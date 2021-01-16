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

#include <json-c/json_tokener.h>
#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>

#include <stdlib.h>
#include <inttypes.h>

#include "../log.h"
#include "json.h"
#include "../array.h"
#include "../fixed_point.h"

static int __rrr_json_to_array_recurse (
		struct json_object *object,
		const int max_levels,
		const int cur_level,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
);

static int __rrr_json_to_array_recurse_object (
		struct json_object *object,
		const int max_levels,
		const int cur_level,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	if (cur_level > max_levels) {
		RRR_DBG_3("[%i/%i] JSON MAX LEVEL\n", cur_level, max_levels);
		goto out;
	}

	struct json_object_iterator iterator = json_object_iter_begin(object);
	struct json_object_iterator end = json_object_iter_end(object);

	while (!json_object_iter_equal(&iterator, &end)) {
		const char *key = json_object_iter_peek_name(&iterator);
		json_object *object = json_object_iter_peek_value(&iterator);

		RRR_DBG_3("[%i/%i] JSON OBJECT KEY %s\n", cur_level, max_levels, key);

		const enum json_type type = json_object_get_type(object);

		if (type == json_type_string) {
			const char *value = json_object_get_string(object);

			RRR_DBG_3("        => STRING %s\n", value);

			// Note : Zero length strings not possible in RRR arrays
			if (*value == '\0') {
				if ((ret = rrr_array_push_value_u64_with_tag(&array_tmp, key, 0)) != 0) {
					goto out;
				}
			}
			else {
				if ((ret = rrr_array_push_value_str_with_tag(&array_tmp, key, value)) != 0) {
					goto out;
				}
			}
		}
		else if (type == json_type_int) {
			const int64_t value = json_object_get_int64(object);

			RRR_DBG_3("        => INT %" PRIi64 "\n", value);

			if ((ret = rrr_array_push_value_i64_with_tag(&array_tmp, key, value)) != 0) {
				goto out;
			}
		}
		else if (type == json_type_double) {
			double value_double = json_object_get_double(object);
			rrr_fixp value = 0;

			RRR_DBG_3("        => DOUBLE %lf\n", value_double);

			if (rrr_fixp_ldouble_to_fixp(&value, value_double) != 0) {
				RRR_MSG_0("Conversion of double to fixed point failed while parsing JSON\n");
				ret = RRR_JSON_PARSE_ERROR;
				goto out;
			}

			if ((ret = rrr_array_push_value_fixp_with_tag(&array_tmp, key, value)) != 0) {
				goto out;
			}
		}
		else if (type == json_type_boolean) {
			const json_bool value = json_object_get_boolean(object);

			RRR_DBG_3("        => BOOL %s\n", (value ? "TRUE" : "FALSE"));

			// Note : unsigned is used for bools
			if ((ret = rrr_array_push_value_u64_with_tag(&array_tmp, key, value)) != 0) {
				goto out;
			}
		}
		else if (type == json_type_null) {
			RRR_DBG_3("        => NULL\n", cur_level, max_levels);
			RRR_MSG_0("NULL data type encountered in JSON, this is not supported.\n");
			ret = RRR_JSON_PARSE_ERROR;
			goto out;
		}
		else {
			if ((ret = __rrr_json_to_array_recurse (
					object,
					max_levels,
					cur_level + 1,
					callback,
					callback_arg
			)) != 0) {
				goto out;
			}
		}

		json_object_iter_next(&iterator);
	}

	ret = callback(&array_tmp, callback_arg);

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_json_to_array_recurse (
		struct json_object *object,
		const int max_levels,
		const int cur_level,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if (cur_level > max_levels) {
		RRR_DBG_3("[%i/%i] JSON MAX LEVEL\n", cur_level, max_levels);
		goto out;
	}

	const enum json_type type = json_object_get_type(object);

	if (type == json_type_array) {
		const size_t length = json_object_array_length(object);
		for (size_t i = 0; i <  length; i++) {
			RRR_DBG_3("[%i/%i] JSON ARRAY IDX %llu\n", cur_level, max_levels, (long long unsigned) i);
			if ((ret = __rrr_json_to_array_recurse (
					json_object_array_get_idx(object, i),
					max_levels,
					cur_level + 1,
					callback,
					callback_arg
			)) != 0) {
				goto out;
			}
		}
	}
	else if (type == json_type_object) {
		RRR_DBG_3("[%i/%i] JSON OBJECT\n", cur_level, max_levels);
		if ((ret = __rrr_json_to_array_recurse_object (
				object,
				max_levels,
				cur_level,
				callback,
				callback_arg
		)) != 0) {
			goto out;
		}
	}
	else {
		RRR_MSG_0("Unknown JSON type '%s' at current level, expecting object or array. Loose values outside of objects are not supported.\n",
				json_type_to_name(type));
		ret = RRR_JSON_PARSE_ERROR;
		goto out;
	}

	out:
	return ret;
}

/* For all found objects, an RRR array containing all plain values is
 * created and handed to the callback. If an object contains another object,
 * an array is created for both of them. The array resulting from the parent object
 * will not have any information about it's child or vice versa. */
int rrr_json_to_arrays (
		const char *data,
		size_t data_size,
		const int max_levels,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;

	json_tokener *tokener = NULL;
	json_object *object = NULL;

	if ((tokener = json_tokener_new()) == NULL) {
		RRR_MSG_0("Could not allocate tokener in rrr_json_to_array\n");
		ret = RRR_JSON_HARD_ERROR;
		goto out;
	}

	if ((object = json_tokener_parse_ex(tokener, data, data_size)) == NULL) {
		enum json_tokener_error err = json_tokener_get_error(tokener);
		if (err == json_tokener_continue) {
			ret = RRR_JSON_PARSE_INCOMPLETE;
			goto out;
		}

		RRR_DBG_2("Failed to parse JSON data: %s\n",
				json_tokener_error_desc(err));
		ret = RRR_JSON_PARSE_ERROR;
		goto out;
	}

	ret = __rrr_json_to_array_recurse (
			object,
			max_levels,
			0,
			callback,
			callback_arg
	);

	out:
	if (tokener != NULL) {
		json_tokener_free(tokener);
	}
	if (object != NULL) {
		json_object_put(object);
	}
	return ret;
}
