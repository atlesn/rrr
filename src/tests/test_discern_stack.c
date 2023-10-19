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

#include "test.h"
#include "test_discern_stack.h"
#include "../lib/discern_stack.h"
#include "../lib/parse.h"

static const char *fails[] = {
	// Empty definition
	"",
	// Invalid keyword
	"INVALID",
	// Missing value after keywords
	"T    ",
	"H    ",
	"D    ",
	// Invalid topic filter, array tag and destination name
	"T ##\tPOP",
	"H a-",
	"D a$",
	// Not enough arguments
	"AND",
	"OR",
	"NOT",
	"APPLY",
	"POP",
	"T a\tAND",
	"T a\tOR",
	"D a\tAPPLY",
	// Incorrect argument types
	"D a H b AND",
	"H a D b OR",
	"D a     NOT",
	"H a H b APPLY",
	"D a H b APPLY",
	// Stack not empty
	"H a H a POP",
	// End missing
	"T ##",
	"H a",
	// Stack overflow
	"H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a " \
	"H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a " \
	"H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a " \
	"H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a H a "

};

const enum rrr_discern_stack_fault fail_codes[] = {
	RRR_DISCERN_STACK_FAULT_END_MISSING,

	RRR_DISCERN_STACK_FAULT_SYNTAX_ERROR,

	RRR_DISCERN_STACK_FAULT_VALUE_MISSING,
	RRR_DISCERN_STACK_FAULT_VALUE_MISSING,
	RRR_DISCERN_STACK_FAULT_VALUE_MISSING,

	RRR_DISCERN_STACK_FAULT_INVALID_VALUE,
	RRR_DISCERN_STACK_FAULT_INVALID_VALUE,
	RRR_DISCERN_STACK_FAULT_INVALID_VALUE,

	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_STACK_COUNT,

	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,
	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,
	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,
	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,
	RRR_DISCERN_STACK_FAULT_INVALID_TYPE,

	RRR_DISCERN_STACK_FAULT_STACK_COUNT,
	RRR_DISCERN_STACK_FAULT_END_MISSING,
	RRR_DISCERN_STACK_FAULT_END_MISSING,
	RRR_DISCERN_STACK_FAULT_STACK_OVERFLOW
};

static const char *valids[] = {
	"H a T b\tAND\tPOP",
	"H a T b\tOR\tPOP",
	"H a D c\tAPPLY\tPOP # Comment",
	"H a\tH b D c\tAPPLY\tAND D d\tAPPLY\tPOP",
	"TRUE FALSE POP BAIL"
};

// Test should confirm that
//   - OR operator writes at correct stack location
//   - NOT operator works

static const char bigtest[] = "T AAA\nT YYY\nT BBB\nOR\n" \
                              "D yes APPLY\n" \
                              "T AAA\nT BBB\n" \
                              "D no APPLY\n" \
			      "OR OR OR NOT\n" \
			      "D no APPLY\n" \
			      "NOT\n" \
                              "D yes APPLY\n" \
			      "NOT\n" \
			      "D no APPLY\n" \
			      "POP\n";
//   Correct: -
//            0
//            0 1
//            0 1 0
//            0 1
//            0 1 0
//            0 1 0 0
//            0 1 0
//            0 1
//            1
//            0
//            1
//            0
//            -
// Incorrect: -
//            0
//            0 1
//            0 1 0
//            0 1     (1) <-- OR writes to popped value, but error is obscured
//            0 1 0
//            0 1 0 0
//            0 1 0   (0) <-- OR writes to popped value, but error is obscured
//            0 1     (1) <-- OR writes to popped value, but error is obscured
//            0       (1) <-- OR writes to popped value, and result becomes incorrect
//            1
//            0
//            1
//            -


static int __rrr_test_discern_stack_resolve_topic_filter_cb (RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS) {
	(void)(arg);
	assert(topic_filter_size == 4 && topic_filter[3] == '\0');
	*result = strncmp(topic_filter, "YYY", topic_filter_size) == 0;
	return 0;
}

static int __rrr_test_discern_stack_resolve_array_tag_cb (RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS) {
	(void)(result);
	(void)(new_index);
	(void)(new_index_size);
	(void)(tag);
	(void)(arg);
	// Not reachable
	assert(0);
}

static int __rrr_test_discern_stack_apply_cb_false (RRR_DISCERN_STACK_APPLY_CB_ARGS) {
	(void)(arg);
	assert(strcmp(destination, "no") == 0);
	return 0;
}

static int __rrr_test_discern_stack_apply_cb_true (RRR_DISCERN_STACK_APPLY_CB_ARGS) {
	(void)(arg);
	assert(strcmp(destination, "yes") == 0);
	return 0;
}

int rrr_test_discern_stack(void) {
	int ret = 0;

	struct rrr_discern_stack_collection routes = {0};

	assert(sizeof(fails)/sizeof(*fails) == sizeof(fail_codes)/sizeof(*fail_codes));

	for (unsigned int i = 0; i < sizeof(fails)/sizeof(*fails); i++) {
		const char *fail = fails[i];
		const enum rrr_discern_stack_fault fail_code = fail_codes[i];

		TEST_MSG("%s\n -> ", fail);

		struct rrr_parse_pos pos;

		rrr_parse_pos_init(&pos, fail, rrr_length_from_biglength_bug_const(strlen(fail)));

		enum rrr_discern_stack_fault fault = 0;
		int ret_tmp = 0;
		if ((ret_tmp = rrr_discern_stack_interpret (&routes, &fault, &pos, fail)) != 1) {
			TEST_MSG(" NOT OK - Test '%s' did not fail as expected, result was %i fault was %i\n",
					fail, ret_tmp, fault);
			ret = 1;
		}
		else if (fault != fail_code) {
			TEST_MSG(" -> NOT OK - Test '%s' fault code mismatch %i<>%i\n",
					fail, fault, fail_code);
			ret = 1;
		}
		else {
			TEST_MSG(" -> OK\n");
			assert(RRR_LL_COUNT(&routes) == 0);
		}
	}

	for (unsigned int i = 0; i < sizeof(valids)/sizeof(*valids); i++) {
		const char *valid = valids[i];

		TEST_MSG("%s\n -> ", valid);

		struct rrr_parse_pos pos;

		rrr_parse_pos_init(&pos, valid, rrr_length_from_biglength_bug_const(strlen(valid)));

		enum rrr_discern_stack_fault fault = 0;
		int ret_tmp = 0;
		if ((ret_tmp = rrr_discern_stack_interpret (&routes, &fault, &pos, valid)) != 0) {
			printf("fault %i ret %i\n", fault, ret_tmp);
			assert(fault != 0);
			TEST_MSG(" -> NOT OK - Test did not succeed as expected, result was %i fault was %i\n",
					ret_tmp, fault);
			ret = 1;
		}
		else {
			assert(fault == 0);
			TEST_MSG(" OK\n");
		}
	}

	if (ret == 0) {
		assert(RRR_LL_COUNT(&routes) == sizeof(valids)/sizeof(*valids));
	}

	rrr_discern_stack_collection_clear(&routes);

	{
		enum rrr_discern_stack_fault fault = 0;
		int ret_tmp = 0;
		struct rrr_parse_pos pos;
		rrr_parse_pos_init(&pos, bigtest, rrr_length_from_biglength_bug_const(strlen(bigtest)));

		TEST_MSG("%s\n -> ", bigtest);

		if ((ret_tmp = rrr_discern_stack_interpret (&routes, &fault, &pos, bigtest)) != 0) {
			printf("fault %i ret %i\n", fault, ret_tmp);
			assert(fault != 0);
			TEST_MSG(" -> NOT OK - Bigtest did not succeed as expected, result was %i fault was %i\n",
					ret_tmp, fault);
			ret = 1;
		}
		else {
			assert(fault == 0);
			TEST_MSG(" OK\n");
		}

		struct rrr_discern_stack_callbacks callbacks = {
			__rrr_test_discern_stack_resolve_topic_filter_cb,
			__rrr_test_discern_stack_resolve_array_tag_cb,
			NULL,
			__rrr_test_discern_stack_apply_cb_false,
			__rrr_test_discern_stack_apply_cb_true,
			NULL
		};

		// Test more times to provoke stack re-use
		for (int i = 0; i < 5; i++) {
			TEST_MSG("    (execute %i) -> ", i);

			if ((ret_tmp = rrr_discern_stack_collection_execute (
					&fault,
					&routes,
					&callbacks
			)) != 0) {
				printf("fault %i ret %i\n", fault, ret_tmp);
				assert(fault != 0);
				TEST_MSG(" -> NOT OK - Bigtest did not succeed as expected, result was %i fault was %i\n",
						ret_tmp, fault);
				ret = 1;
			}
			else {
				assert(fault == 0);
				TEST_MSG(" OK\n");
			}
		}
	}

	return ret;
}

