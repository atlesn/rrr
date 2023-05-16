/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <inttypes.h>

struct rrr_msg_msg;
struct rrr_instance_collection;
struct rrr_instance_runtime_data;
struct rrr_map;

struct rrr_test_function_data {
	int do_array_str_to_h_conversion;
	int do_blob_field_divide;
};

#define RRR_TEST_FUNCTION_ARGS                                 \
    const struct rrr_test_function_data *test_function_data,   \
    struct rrr_instance_collection *instances,                 \
    struct rrr_instance_runtime_data *self_thread_data

int test_averager (
		RRR_TEST_FUNCTION_ARGS
);

int test_array (
		RRR_TEST_FUNCTION_ARGS
);

int test_anything (
		RRR_TEST_FUNCTION_ARGS,
		const struct rrr_map *array_check_values
);

int test_type_array_mysql (
		RRR_TEST_FUNCTION_ARGS
);
