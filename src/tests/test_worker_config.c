/*

Read Route Record

Copyright (C) 2025 Atle Solbakken atle@goliathdns.no

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

#include <string.h>

#include "../lib/instance_config.h"
#include "test.h"

#define RESET() rrr_instance_config_collection_destroy(collection); collection = NULL;

int rrr_test_worker_config (void) {
	int ret = 0;

	struct rrr_instance_config_collection *collection = NULL;

	const char *test_multiple_workers_fail =
		"[instance]\n" \
		"param=a\n" \
		"param_x=1\n" \
		"[instanceFAIL[ab]]\n" \
		"param_x=2\n";
		;

	const char *test_multiple_workers =
		"[instance]\n" \
		"param=a\n" \
		"param_x=1\n" \
		"[instance[ab]]\n" \
		"param_x=2\n" \
		"[instance[cd]]\n" \
		"param_x=3\n" \
		;

	TEST_MSG("Test subconfigs main missing\n");

	if (rrr_instance_config_parse_string(&collection, test_multiple_workers_fail, strlen(test_multiple_workers_fail)) != 1) {
		TEST_MSG("Failed\n");
		ret = 1;
	}

	TEST_MSG("Test subconfigs success\n");

	if (rrr_instance_config_parse_string(&collection, test_multiple_workers, strlen(test_multiple_workers)) != 0) {
		TEST_MSG("Failed\n");
		ret = 1;
	}

	TEST_MSG("OK\n");

	ret |= rrr_instance_config_dump(collection);

	if (collection != NULL) {
		rrr_instance_config_collection_destroy(collection);
	}
	return ret;
}
