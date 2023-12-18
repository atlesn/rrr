/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include <assert.h>
#include <string.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "test.h"
#include "test_parse.h"
#include "../lib/parse.h"

static int __rrr_test_parse_make_location_message(const char *str) {
	struct rrr_parse_pos pos;
	char *str_tmp = (char *) 1;

	rrr_parse_pos_init(&pos, str, strlen(str));

	assert(rrr_parse_str_extract_name(&str_tmp, &pos, ')') == 0 && str_tmp == NULL);

	rrr_parse_make_location_message(&str_tmp, &pos);
	TEST_MSG("\n%s\n", str_tmp);
	rrr_free(str_tmp);

	return 0;
}

static int __rrr_test_parse_extract_name(void) {
	struct rrr_parse_pos pos;
	char *str_tmp = NULL;

	int ret = 0;

	{
		rrr_parse_pos_init(&pos, "", 0);
		if (rrr_parse_str_extract_name(&str_tmp, &pos, ')') != 0 || str_tmp != NULL) {
			TEST_MSG("Failed at empty string\n");
			ret = 1;
			goto out;
		}
	}

	{
		rrr_parse_pos_init(&pos, ")", 1);
		if (rrr_parse_str_extract_name(&str_tmp, &pos, ')') != 0 || str_tmp != NULL) {
			TEST_MSG("Failed at empty name with end char\n");
			ret = 1;
			goto out;
		}
	}

	{
		rrr_parse_pos_init(&pos, "a", 1);
		if (rrr_parse_str_extract_name(&str_tmp, &pos, ')') != 1 || str_tmp != NULL) {
			TEST_MSG("Failed at missing end char\n");
			ret = 1;
			goto out;
		}
	}

	{
		rrr_parse_pos_init(&pos, "a)", 2);
		if (rrr_parse_str_extract_name(&str_tmp, &pos, ')') != 0 || str_tmp == NULL) {
			TEST_MSG("Failed at test supposed to succeed\n");
			ret = 1;
			goto out;
		}
		assert(strlen(str_tmp) == 1);
		assert(*str_tmp == 'a');
		assert(*(str_tmp+1) == '\0');
		rrr_free(str_tmp);
	}

	out:
	return ret;
}

int rrr_test_parse(void) {
	int ret = 0;

	TEST_MSG("Testing name extraction\n");
	ret |= __rrr_test_parse_extract_name();

	TEST_MSG("Testing location messages\n");
	ret |= __rrr_test_parse_make_location_message("");
	ret |= __rrr_test_parse_make_location_message("(\n)");
	// NOTE ! Long string with spaces, don't mess up. Must be longer
	//        than truncation limit of location maker.
	ret |= __rrr_test_parse_make_location_message("                                                                " \
                                                      "                                                                " \
                                                      "                                                                ");

	return ret;
}
