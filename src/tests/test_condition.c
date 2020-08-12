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
#include "../lib/condition.h"
#include "../lib/array_tree.h"
#include "../lib/parse.h"
#include "test.h"
#include "test_condition.h"

static const char *condition_a = "(1 & {tag} OR 2 == 2 AND (3 == 3 OR 3 & 0x1))";

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

static const char *array_tree_rpn = "be4#my_tag,IF({my_tag} 2 ==)be4#my_tag_two;ELSEbe4#my_tag_not_two;;";


int rrr_test_condition (void) {
	int ret = 0;

	struct rrr_condition condition = {0};
	struct rrr_parse_pos pos = {0};

	rrr_parse_pos_init(&pos, condition_a, strlen(condition_a));

	// Don't overwrite ret, or in 1's on failure and let all tests run

	if (rrr_condition_parse(&condition, &pos)) {
		TEST_MSG("Condition parse test failed for expression '%s'\n", condition_a);
		ret |= 1;
	}
	rrr_condition_clear(&condition);

	struct rrr_array_tree *tree = NULL;

	rrr_parse_pos_init(&pos, array_tree, strlen(array_tree) + 1);

	if (rrr_array_tree_parse(&tree, &pos, "my_tree")) {
		TEST_MSG("Array tree parsing failed\n");
		ret |= 1;
	}
	if (tree != NULL) {
		int ret_tmp;
		if ((ret_tmp = rrr_array_tree_validate(tree)) != 0) {
			TEST_MSG("Array tree was invalid return was %i\n", ret_tmp);
			ret |= 1;
		}
		rrr_array_tree_dump(tree);
		rrr_array_tree_destroy(tree);
	}

	rrr_parse_pos_init(&pos, array_tree_rpn, strlen(array_tree_rpn) + 1);

	if (rrr_array_tree_parse(&tree, &pos, "my_tree")) {
		TEST_MSG("Array tree parsing failed\n");
		ret |= 1;
	}
	if (tree != NULL) {
		int ret_tmp;
		if ((ret_tmp = rrr_array_tree_validate(tree)) != 0) {
			TEST_MSG("Array tree was invalid, return was %i\n", ret_tmp);
			ret |= 1;
		}
		rrr_array_tree_dump(tree);
		rrr_array_tree_destroy(tree);
	}

	return ret;
}
