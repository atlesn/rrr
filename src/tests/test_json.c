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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/log.h"

#include "test.h"
#include "test_fixp.h"
#include "../lib/array.h"
#include "../lib/json/json.h"
#include "../lib/fixed_point.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/linked_list.h"

static int __rrr_test_json_data_a_callback (const struct rrr_array *array, void *arg) {
	int *counter = arg;

	int ret = 0;

	char *str_tmp = NULL;

	if (RRR_DEBUGLEVEL_3) {
		rrr_array_dump(array);
	}

	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (strcmp(node->tag, "keepvalue") == 0) {
			if ((ret = node->definition->to_str(&str_tmp, node)) != 0) {
				goto out;
			}
			if (strcmp(str_tmp, "value") != 0) {
				TEST_MSG("Mismatch '%s'<>'%s'\n", str_tmp, "value");
				ret = 1;
				goto out;
			}
		}
		else if (strcmp(node->tag, "keep1") == 0) {
			uint64_t value = node->definition->to_64(node);
			if (value != 1) {
				TEST_MSG("Mismatch %" PRIu64 "<>1\n", value);
				ret = 1;
				goto out;
			}
		}
		else if (strcmp(node->tag, "keep2.2") == 0) {
			rrr_fixp fixp = 0;
			rrr_fixp_ldouble_to_fixp(&fixp, 2.2);

			if (memcmp(node->data, &fixp, sizeof(rrr_fixp)) != 0) {
				TEST_MSG("Mismatch %" PRIu64 "<>%" PRIu64 "\n", fixp, *((uint64_t *) node->data));
				ret = 1;
				goto out;
			}
		}
		else if (strcmp(node->tag, "keepnull") == 0) {
			if (!RRR_TYPE_IS_VAIN(node->definition->type)) {
				TEST_MSG("Mismatch, null value was not vain\n");
				ret = 1;
				goto out;
			}
		}
		else {
			TEST_MSG("Unknown tag '%s'\n", node->tag);
			ret = 1;
			goto out;
		}

		(*counter)++;
	RRR_LL_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(str_tmp);
	return ret;
}

int rrr_test_json(void) {
	int ret = 0;

	const char *data_a = "[{\"drop\" : {\"keepvalue\" : \"value\"}, \"keep1\" : 1},{\"keep2.2\" : 2.2, \"keepnull\" : null}]";

	RRR_DBG_3("JSON: %s\n", data_a);

	int counter = 0;

	if ((ret = rrr_json_to_arrays(data_a, strlen(data_a), 3, __rrr_test_json_data_a_callback, &counter)) != 0) {
		TEST_MSG("JSON test failed\n");
		goto out;
	}

	if (counter != 4) {
		TEST_MSG("JSON test failed: Values missing or too many values %i<>3\n", counter);
		ret = 1;
		goto out;
	}

	out:
	return (ret != 0);
}
