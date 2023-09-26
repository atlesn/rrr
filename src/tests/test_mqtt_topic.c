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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/mqtt/mqtt_topic.h"

#include "test.h"
#include "test_mqtt_topic.h"

struct rrr_test_mqtt_test_case {
	const char *filter;
	const char *topic;
	int result;
};

#define TEST_CASE(a,b,c)   {#a, #b, c}
#define TEST_CASE_OK(a,b)  TEST_CASE(a,b,1)
#define TEST_CASE_NOK(a,b) TEST_CASE(a,b,0)

static const struct rrr_test_mqtt_test_case test_cases_topic_validation[] = {
	TEST_CASE_NOK(   /++,     /  ),
	TEST_CASE_NOK( ++/  ,     /  ),
	TEST_CASE_OK (  +/# ,     /  ),
	TEST_CASE_OK (  #   ,     /  ),
	TEST_CASE_NOK(  #/  ,     /  ),
	TEST_CASE_NOK(  #/+ ,     /  ),
	TEST_CASE_OK (   /# ,     /  ),
	TEST_CASE_NOK(   /+#,     /  ),
	TEST_CASE_NOK( +#/  ,     /  ),
	TEST_CASE_NOK(   /#+,     /  ),
	TEST_CASE_NOK( #+/  ,     /  ),
	TEST_CASE_OK (  a/  ,     /  ),
	TEST_CASE_OK (  a/+ ,     /  ),
	TEST_CASE_OK (   /a ,     /  ),
	TEST_CASE_NOK(   /+a,     /  ),
	TEST_CASE_NOK( +a/  ,     /  ),
	TEST_CASE_NOK(   /a+,     /  ),
	TEST_CASE_NOK( a+/  ,     /  ),
	TEST_CASE_NOK(  #/  ,     /  ),
	TEST_CASE_NOK(  #/a ,     /  ),
	TEST_CASE_NOK(   /a#,     /  ),
	TEST_CASE_NOK( a#/  ,     /  ),
	TEST_CASE_NOK(   /#a,     /  ),
	TEST_CASE_NOK( #a/  ,     /  ),
	TEST_CASE_NOK( \x80             ,     /  ),
	TEST_CASE_NOK( \xC0\xAF         ,     /  ),
	TEST_CASE_NOK( \xF4\x90\x80\x80 ,     /  ),
	TEST_CASE_NOK( \xE0\x80\xAF     ,     /  ),
	TEST_CASE_OK ( \xE2\x98\xBA     ,     /  ),
	TEST_CASE_OK ( \xF0\xA4\xAD\xA2 ,     /  ),
	TEST_CASE_OK ( \xC2\xA9         ,     /  ),
	{NULL, NULL, 0}
};

static const struct rrr_test_mqtt_test_case test_cases_matching[] = {
	TEST_CASE_OK (   / ,      /  ),
	TEST_CASE_NOK(   / ,      /a ),
	TEST_CASE_NOK(   / ,     a/  ),
	TEST_CASE_NOK(   / ,     a/a ),

	TEST_CASE_OK (  +/+,      /  ),
	TEST_CASE_OK (  +/+,     a/  ),
	TEST_CASE_OK (  +/+,      /a ),
	TEST_CASE_OK (  +/+,     a/a ),

	TEST_CASE_OK (   /+,      /  ),
	TEST_CASE_OK (   /+,      /a ),
	TEST_CASE_NOK(   /+,     a/  ),
	TEST_CASE_NOK(   /+,     a/a ),

	TEST_CASE_OK (  +/ ,      /  ),
	TEST_CASE_NOK(  +/ ,      /a ),
	TEST_CASE_OK (  +/ ,     a/  ),
	TEST_CASE_NOK(  +/ ,     a/a ),

	TEST_CASE_NOK(  a/+,      /  ),
	TEST_CASE_NOK(  a/+,      /a ),
	TEST_CASE_OK (  a/+,     a/  ),
	TEST_CASE_OK (  a/+,     a/a ),

	TEST_CASE_NOK(  b/b,      /  ),
	TEST_CASE_NOK(  b/b,     a/  ),
	TEST_CASE_NOK(  b/b,      /a ),
	TEST_CASE_NOK(  b/b,     a/a ),

	TEST_CASE_NOK(   /b,      /  ),
	TEST_CASE_NOK(   /b,      /a ),
	TEST_CASE_NOK(   /b,     a/  ),
	TEST_CASE_NOK(   /b,     a/a ),

	TEST_CASE_NOK(  b/ ,      /  ),
	TEST_CASE_NOK(  b/ ,      /a ),
	TEST_CASE_NOK(  b/ ,     a/  ),
	TEST_CASE_NOK(  b/ ,     a/a ),

	TEST_CASE_NOK(  a/b,      /  ),
	TEST_CASE_NOK(  a/b,      /a ),
	TEST_CASE_NOK(  a/b,     a/  ),
	TEST_CASE_NOK(  a/b,     a/a ),

	TEST_CASE_NOK(  b/b,      /  ),
	TEST_CASE_NOK(  b/b,     b/  ),
	TEST_CASE_NOK(  b/b,      /b ),
	TEST_CASE_OK (  b/b,     b/b ),

	TEST_CASE_NOK(   /b,      /  ),
	TEST_CASE_OK (   /b,      /b ),
	TEST_CASE_NOK(   /b,     b/  ),
	TEST_CASE_NOK(   /b,     b/b ),

	TEST_CASE_NOK(  b/ ,      /  ),
	TEST_CASE_NOK(  b/ ,      /b ),
	TEST_CASE_OK (  b/ ,     b/  ),
	TEST_CASE_NOK(  b/ ,     b/b ),

	TEST_CASE_NOK(  a/#,      /  ),
	TEST_CASE_NOK(  a/#,      /a ),
	TEST_CASE_OK (  a/#,     a/  ),
	TEST_CASE_OK (  a/#,     a/a ),

	TEST_CASE_OK (   /#,      /  ),
	TEST_CASE_OK (   /#,      /a ),
	TEST_CASE_NOK(   /#,     a/  ),
	TEST_CASE_NOK(   /#,     a/a ),

	TEST_CASE_NOK(   /#,      /$ ),
	TEST_CASE_NOK(  #,       $/  ),
	TEST_CASE_NOK(  #,       $/$ ),

	TEST_CASE_OK (   /#,      /a$),
	TEST_CASE_OK (  #,      a$/  ),
	TEST_CASE_OK (  #,      a$/a$),

	TEST_CASE_NOK(   a/b,    a   ),
	TEST_CASE_NOK(   a,      a/b ),

	TEST_CASE_NOK(   +/a,     a   ),
	TEST_CASE_NOK(   a/+,     a   ),
	TEST_CASE_NOK(   +/+,     a   ),
	TEST_CASE_NOK(   +/#,     a   ),

	TEST_CASE_OK (   #,       a/a ),
	TEST_CASE_NOK(   +,       a/a ),
	TEST_CASE_OK (   #,       a   ),
	TEST_CASE_OK (   +,       a   ),

	TEST_CASE_NOK(   /+,      /$ ),
	TEST_CASE_NOK(  +/ ,     $/  ),
	TEST_CASE_NOK(  +/+,     $/$ ),

	TEST_CASE_OK (   /+,      /a$),
	TEST_CASE_OK (  +/ ,    a$/  ),
	TEST_CASE_OK (  +/+,    a$/a$),

	{NULL, NULL, 0}
};

static int __rrr_test_mqtt_topic_verify_match (int ret, int expected_result) {
	switch (ret) {
		case RRR_MQTT_TOKEN_MATCH:
			if (!expected_result) {
				TEST_MSG("- Matched but should not match\n");
				return 1;
			}
			break;
		case RRR_MQTT_TOKEN_MISMATCH:
			if (expected_result) {
				TEST_MSG("- Did not match but should\n");
				return 1;
			}
			break;
		case RRR_MQTT_TOKEN_INTERNAL_ERROR:
		default:
			TEST_MSG("- Internal error from matcher\n");
			return 1;
	};

	return 0;
}

int rrr_test_mqtt_topic(void) {
	int ret = 0;
	int ret_tmp;

	const struct rrr_test_mqtt_test_case *test_case;

	TEST_MSG("\n=== INVALID FILTERS\n");
	TEST_MSG("\n+ %10s %5s\n", "FILTER", "VALID");
	for (test_case = test_cases_topic_validation; test_case->filter != NULL; test_case++) {
		TEST_MSG("+ %10s %5s\n", test_case->filter, test_case->result ? "YES" : "NO");

		// Note : Funtion returns 1 on error while expected result 1 is OK hence the == for fail
		if (rrr_mqtt_topic_filter_validate_name(test_case->filter) == test_case->result) {
			TEST_MSG("= FAIL\n");
			ret = 1;
		}
		else {
			TEST_MSG("= SUCCESS\n");
		}
	}

	// Note : Testing both tokenizing then match as well as matching strings directly.
	// TODO : Remove tokenizer function, only keep one.

	TEST_MSG("\n=== TOPIC<>FILTER MATCING\n");
	TEST_MSG("\n+ %10s %10s %5s\n", "FILTER", "TOPIC", "MATCH");
	for (test_case = test_cases_matching; test_case->filter != NULL; test_case++) {
		ret_tmp = 0;

		TEST_MSG("+ %10s %10s %5s\n", test_case->filter, test_case->topic, test_case->result ? "YES" : "NO");

		if (rrr_mqtt_topic_filter_validate_name(test_case->filter) != 0) {
			TEST_MSG("- Filter validation failed\n");
			goto fail;
		}

		if (rrr_mqtt_topic_validate_name(test_case->topic) != 0) {
			TEST_MSG("- Topic validation failed\n");
			goto fail;
		}

		if (__rrr_test_mqtt_topic_verify_match (rrr_mqtt_topic_match_str(test_case->filter, test_case->topic), test_case->result) != 0) {
			TEST_MSG("- Tokenized verification failed\n");
			ret_tmp = 1;
		}

		if (__rrr_test_mqtt_topic_verify_match(rrr_mqtt_topic_match_topic_and_linear_with_end (
				test_case->topic,
				test_case->topic + strlen(test_case->topic),
				test_case->filter,
				test_case->filter + strlen(test_case->filter)
		), test_case->result) != 0) {
			TEST_MSG("- Non-tokenized linear verification failed\n");
			ret_tmp = 1;
		};

		if (ret_tmp)
			goto fail;

		TEST_MSG("= SUCCESS\n");

		continue;
		fail:
			TEST_MSG("= FAIL\n");
			ret = 1;
	}

	return (ret != 0);
}
