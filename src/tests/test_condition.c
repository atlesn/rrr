/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <string.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/condition.h"
#include "../lib/array_tree.h"
#include "../lib/parse.h"
#include "../lib/util/rrr_endian.h"
#include "test.h"
#include "test_condition.h"

#define TREE_CLEANUP				\
do {if (tree != NULL) {				\
	rrr_array_tree_dump(tree);		\
	rrr_array_tree_destroy(tree);	\
}} while(0)

#define TREE_INTERPRET(name)																								\
	do {if (rrr_array_tree_interpret_raw(&tree, name, strlen(name), RRR_QUOTE(name))) {	\
		TEST_MSG("Array tree parsing failed\n");																			\
		ret |= 1;																											\
	}}while(0)

static int __rrr_test_condition_parsing (void) {
	int ret = 0;

	{
		struct rrr_condition condition = {0};

		static const char *condition_a = "(1 & {tag} OR 2 == 2 AND (3 == 3 OR 3 & 0x1))";
		if (rrr_condition_interpret_raw(&condition, condition_a, strlen(condition_a))) {
			TEST_MSG("Condition parse test failed for expression '%s'\n", condition_a);
			ret |= 1;
		}

		rrr_condition_clear(&condition);
	}

	{
		struct rrr_array_tree *tree = NULL;

		static const char *array_tree =
				"be4#my_tag,fixp,sep1,\n"
				"IF ({my_tag}==2)\n"
				"	fixp,sep1,be4#my_tag_two           ,\n,\n"
				"	IF ({my_tag_two}>10)\n"
				"		be4@{my_tag_two}#my_tag_extra\n"
				"		;\n"
				"	ELSIF ({my_tag_two}<6)\n"
				"		be2@{my_tag_two}#my_tag_extra\n"
				"		;\n"
				"	ELSE\n"
				"		be1@{my_tag_two}#my_tag_extra,\n"
				"		be{my_tag_two}s#my_tag_extra_dynamic\n"
				"		;\n"
				"	IF (1==1);\n"
				"	;\n"
				"ELSE\n"
				"	be4#my_tag_not_two;\n"
				";";

		TREE_INTERPRET(array_tree);
		TREE_CLEANUP;

		static const char *array_tree_rpn = "be4#my_tag,IF({my_tag} 2 ==)be4#my_tag_two;ELSEbe4#my_tag_not_two;;";

		TREE_INTERPRET(array_tree_rpn);
		TREE_CLEANUP;
	}

	return ret;
}

static int __rrr_test_condition_misc_values_import (
		struct rrr_array_tree *definition,
		const char *input,
		ssize_t input_length,
		int (*callback)(struct rrr_array *array, void *arg)
) {
	int ret = 0;

	ssize_t parsed_bytes;
	int ret_tmp;
	if ((ret_tmp = rrr_array_tree_import_from_buffer (
			&parsed_bytes,
			input,
			input_length,
			definition,
			callback,
			NULL
	)) != 0) {
		TEST_MSG("Array data import failed, return was %i\n", ret_tmp);
		ret |= 1;
	}

	if (parsed_bytes != (rrr_slength) input_length) {
		TEST_MSG("Not all bytes from input data was parsed %lli vs %lli\n",
				(long long int) parsed_bytes,
				(long long int) input_length
		);
		ret |= 1;
	}

	return ret;
}

static const char array_tree_misc_values[] = "ustr,sep1,istr#istr,IF(1==1&&{istr}==-444)blob1,REWIND1,str,be3,le3,be8,le8;;";
static const char array_tree_misc_values_input[] = "444\r-444\"blablabla\"\r\n\n\n\n\r\n\n\n\n\n\n\n\0\0\n\n\n\n\n\n\n";

static int __rrr_test_condition_array_import_callback_check_str (const struct rrr_type_value *value, const char *str) {
	int ret = 0;

	char *str_tmp = NULL;

	if (value->definition->to_str(&str_tmp, value) == 0) {
		if (strcmp(str_tmp, str) != 0) {
			TEST_MSG("String mismatch '%s'<>'%s'\n",
					str,
					str_tmp
			);
			ret |= 1;
		}
	}
	else {
		ret |= 1;
	}

	RRR_FREE_IF_NOT_NULL(str_tmp);
	return ret;
}

static int __rrr_test_condition_array_import_callback (
		struct rrr_array *array,
		void *arg
) {
	(void)(arg);

	int ret = 0;

	rrr_array_dump(array);

	struct rrr_type_value *u = rrr_array_value_get_by_index(array, 0);
	struct rrr_type_value *s = rrr_array_value_get_by_tag(array, "istr");
	struct rrr_type_value *str = rrr_array_value_get_by_index(array, 3);
	struct rrr_type_value *raw_be = rrr_array_value_get_by_index(array, 4);
	struct rrr_type_value *raw_le = rrr_array_value_get_by_index(array, 5);
	struct rrr_type_value *raw_be_big = rrr_array_value_get_by_index(array, 6);
	struct rrr_type_value *raw_le_big = rrr_array_value_get_by_index(array, 7);

	uint64_t u_value = u->definition->to_64(u);
	if (u_value != 444) {
		TEST_MSG("Mismatch for unsigned test value 444, value was %" PRIu64 "\n", u_value);
		ret |= 1;
	}

	int64_t s_value = (int64_t) s->definition->to_64(s);
	if (s_value != -444) {
		TEST_MSG("Mismatch for signed test value -444, value was %" PRIi64 "\n", s_value);
		ret |= 1;
	}

	ret |= __rrr_test_condition_array_import_callback_check_str(u, "444");
	ret |= __rrr_test_condition_array_import_callback_check_str(s, "-444");
	ret |= __rrr_test_condition_array_import_callback_check_str(str, "blablabla");
	ret |= __rrr_test_condition_array_import_callback_check_str(raw_be, "854538");
	ret |= __rrr_test_condition_array_import_callback_check_str(raw_le, "854538");

	const char *big_in = "\0\n\n\n\n\n\n\n";
	char be_big_str[64];
	sprintf(be_big_str, "%" PRIu64, rrr_le64toh(*((uint64_t *) big_in)));

	ret |= __rrr_test_condition_array_import_callback_check_str(raw_be_big, be_big_str);
	ret |= __rrr_test_condition_array_import_callback_check_str(raw_le_big, be_big_str);

	rrr_array_clear(array);
	return ret;
}

static int __rrr_test_condition_misc_values (void) {
	int ret = 0;

	struct rrr_array_tree *tree = NULL;

	TREE_INTERPRET(array_tree_misc_values);

	if (tree == NULL) {
		goto out;
	}

	if ((ret = __rrr_test_condition_misc_values_import (
			tree,
			array_tree_misc_values_input,
			sizeof(array_tree_misc_values_input) - 1,
			__rrr_test_condition_array_import_callback
	)) != 0) {
		goto out;
	}

	out:
	TREE_CLEANUP;
	return ret;
}

int rrr_test_condition (void) {
	int ret = 0;

	// Don't overwrite ret, or in 1's on failure and let all tests run

	ret |= __rrr_test_condition_parsing();
	ret |= __rrr_test_condition_misc_values();

	return ret;
}
