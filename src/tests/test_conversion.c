/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "test.h"
#include "test_conversion.h"
#include "../lib/array.h"
#include "../lib/type.h"
#include "../lib/type_conversion.h"
#include "../lib/map.h"

static int __rrr_test_conversion_convert (
		struct rrr_array *target,
		const struct rrr_array *source,
		const struct rrr_map *conversion_map
) {
	int ret = 0;

	struct rrr_type_conversion_collection *conversion_list = NULL;
	struct rrr_type_value *value_new_tmp = NULL;

	if ((ret = rrr_type_conversion_collection_new_from_map(&conversion_list, conversion_map)) != 0) {
		TEST_MSG("Creation of conversion list failed in rrr_test_conversion\n");
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_type_value);
		if ((ret = rrr_type_convert_using_list(&value_new_tmp, node, conversion_list, RRR_TYPE_CONVERT_F_ON_ERROR_TRY_NEXT)) != 0) {
			TEST_MSG("Conversion failed in rrr_test_conversion\n");
			goto out;
		}
		RRR_LL_APPEND(target, value_new_tmp);
		value_new_tmp = NULL;
	RRR_LL_ITERATE_END();

	out:
	rrr_type_value_destroy(value_new_tmp);
	if (conversion_list != NULL) {
		rrr_type_conversion_collection_destroy(conversion_list);
	}
	return ret;
}

static int __rrr_test_conversion_push_field_h (
		struct rrr_array *target,
		uint64_t *values,
		rrr_length values_count,
		int is_signed
) {
	int ret = 0;

	struct rrr_type_value *value_new = NULL;

	if ((ret = rrr_type_value_new_simple (
			&value_new,
			&rrr_type_definition_h,
			(is_signed ? RRR_TYPE_FLAG_SIGNED : 0),
			0,
			NULL
	)) != 0) {
		goto out;
	}

	if ((value_new->data = rrr_allocate(sizeof(*values) * values_count)) == NULL) {
		TEST_MSG("Creation of data memory failed in rrr_test_conversion\n");
		goto out;
	}

	memcpy(value_new->data, values, sizeof(*values) * values_count);
	value_new->total_stored_length = sizeof(*values) * values_count;
	value_new->element_count = values_count;

	RRR_LL_APPEND(target, value_new);
	value_new = NULL;

	out:
	rrr_type_value_destroy(value_new);
	return ret;
}

static int __rrr_test_conversion_push_field_str (
		struct rrr_array *target,
		const char *str
) {
	int ret = 0;

	struct rrr_type_value *value_new = NULL;

	if ((ret = rrr_type_value_new (
			&value_new,
			&rrr_type_definition_str,
			0,
			0,
			NULL,
			0,
			NULL,
			1,
			NULL,
			strlen(str)
	)) != 0) {
		goto out;
	}

	memcpy(value_new->data, str, strlen(str));

	RRR_LL_APPEND(target, value_new);
	value_new = NULL;

	out:
	rrr_type_value_destroy(value_new);
	return ret;
}

static int __rrr_test_conversion_validate_str (
		const struct rrr_type_value *value,
		const char *expected_str,
		const rrr_length expected_size
) {
	int ret = 0;

	if (value->total_stored_length != expected_size) {
		TEST_MSG("Result data size mismatch in __rrr_test_conversion_validate_str (%llu<>%llu)\n",
				(unsigned long long) value->total_stored_length,
				(unsigned long long) expected_size
		);
		ret = 1;
		goto out;
	}

	if (memcmp(value->data, expected_str, expected_size) != 0) {
		TEST_MSG("Result data mismatch in __rrr_test_conversion_validate_str\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_test_conversion(void) {
	int ret = 0;

	struct rrr_array array_input = {0};
	struct rrr_array array_converted = {0};
	struct rrr_map conversion_map = {0};

	int64_t values_multi[] = {
		12345,
		-12345
	};
	const char values_multi_as_str[] = "               12345              -12345";

	uint64_t values_single[] = {
		0xffffffffffffffff
	};
	const char values_single_as_str[] = "18446744073709551615";

	uint64_t values_single_zero[] = {
		0
	};
	const char values_single_zero_as_str[] = "0";

	const char value_empty_str[] = "";

	ret |= __rrr_test_conversion_push_field_h(&array_input, (uint64_t *) values_multi, sizeof(values_multi) / sizeof(*values_multi), 1);
	ret |= __rrr_test_conversion_push_field_h(&array_input, values_single, sizeof(values_single) / sizeof(*values_single), 0);
	ret |= __rrr_test_conversion_push_field_h(&array_input, values_single_zero, sizeof(values_single_zero) / sizeof(*values_single_zero), 0);
	ret |= __rrr_test_conversion_push_field_str(&array_input, value_empty_str);

	if (ret != 0) {
		goto out;
	}

	ret |= rrr_map_item_add_new(&conversion_map, "h2str", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "str2blob", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "blob2str", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "str2h", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "h2vain", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "vain2h", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "h2str", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "str2vain", NULL);
	ret |= rrr_map_item_add_new(&conversion_map, "vain2str", NULL);

	if (ret != 0) {
		TEST_MSG("Creation of map elements failed in rrr_test_conversion\n");
		goto out;
	}

	if ((ret = __rrr_test_conversion_convert(&array_converted, &array_input, &conversion_map)) != 0) {
		goto out;
	}

	const char *expected_results[] = {
			values_multi_as_str,
			values_single_as_str,
			values_single_zero_as_str,
			value_empty_str
	};

	int i = 0;
	RRR_LL_ITERATE_BEGIN(&array_converted, const struct rrr_type_value);
		if (i == sizeof(expected_results) / sizeof(*expected_results)) {
			TEST_MSG("Too many elements in converted array in rrr_test_conversion\n");
			ret = 1;
			goto out;
		}

		if ((ret = __rrr_test_conversion_validate_str (
				node,
				expected_results[i],
				strlen(expected_results[i])
		)) != 0) {
			goto out;
		}

		i++;
	RRR_LL_ITERATE_END();

	if (i != sizeof(expected_results) / sizeof(*expected_results)) {
		TEST_MSG("Not enough elements in converted array in rrr_test_conversion\n");
		ret = 1;
		goto out;
	}

	// Return value propagates

	out:
	if (RRR_DEBUGLEVEL_2) {
		rrr_array_dump(&array_converted);
	}
	rrr_map_clear(&conversion_map);
	rrr_array_clear(&array_input);
	rrr_array_clear(&array_converted);
	return ret;
}
