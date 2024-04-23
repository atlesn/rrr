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
#include "test_http.h"
#include "../lib/log.h"
#include "../lib/http/http_util.c"

struct rrr_test_http_endpoint_and_query_string_split_callback_data {
	const char *expect_endpoint;
	const char *expect_query_string;
};

static int __rrr_test_http_endpoint_and_query_string_split_callback (
		const void *endpoint_decoded,
		rrr_nullsafe_len endpoint_decoded_length,
		const void *query_string_raw,
		rrr_nullsafe_len query_string_raw_length,
		void *arg
) {
	struct rrr_test_http_endpoint_and_query_string_split_callback_data *callback_data = arg;

	// printf("Endpoint: '%.*s'<>'%s'\n", (int) endpoint_decoded_length, (const char *) endpoint_decoded, callback_data->expect_endpoint);
	// printf("Query string: '%.*s'<>'%s'\n", (int) query_string_raw_length, (const char *) query_string_raw, callback_data->expect_query_string);

	if (callback_data->expect_endpoint != NULL) {
		if (endpoint_decoded_length != strlen(callback_data->expect_endpoint)) {
			TEST_MSG("Endpoint length mismatch\n");
			return 1;
		}
		if (query_string_raw_length != strlen(callback_data->expect_query_string)) {
			TEST_MSG("Query string length mismatch\n");
			return 1;
		}
		if (strncmp(callback_data->expect_endpoint, endpoint_decoded, rrr_size_from_biglength_bug_const(endpoint_decoded_length)) != 0) {
			TEST_MSG("Endpoint mismatch '%.*s'<>'%s'\n",
				(int) endpoint_decoded_length, (const char *) endpoint_decoded, callback_data->expect_endpoint);
			return 1;
		}
		if (strncmp(callback_data->expect_query_string, query_string_raw, rrr_size_from_biglength_bug_const(query_string_raw_length)) != 0) {
			TEST_MSG("Query string mismatch '%.*s'<>'%s'\n",
				(int) query_string_raw_length, (const char *) query_string_raw, callback_data->expect_query_string);
			return 1;
		}
	}
	else {
		if (endpoint_decoded_length != 0) {
			TEST_MSG("Endpoint decode succeeded unexpectedly\n");
			return 1;
		}
		if (query_string_raw_length != 0) {
			TEST_MSG("Query string decode succeeded unexpectedly\n");
			return 1;
		}
	}

	return 0;
}

static int __rrr_test_http_endpoint_and_query_string_split_step (
		struct rrr_nullsafe_str **tmp,
		const char *test,
		const char *endpoint,
		const char *query_string
) {
	int ret = 0;

	if ((ret = rrr_nullsafe_str_new_or_replace_raw (
			tmp,
			test,
			strlen(test)
	)) != 0) {
		TEST_MSG("Failed to create nullsafe tmp string in %s\n", __func__);
		goto out;
	}

	struct rrr_test_http_endpoint_and_query_string_split_callback_data callback_data = {
		endpoint,
		query_string
	};

	if ((ret = rrr_http_util_uri_endpoint_and_query_string_split (
			*tmp,
			__rrr_test_http_endpoint_and_query_string_split_callback,
			&callback_data
	)) != 0) {
		if (endpoint != NULL) {
			TEST_MSG("Decoding failed unexpectedly\n");
			goto out;
		}
		ret = 0;
	}
	else {
		if (endpoint == NULL) {
			TEST_MSG("Decoding succeeded unexpectedly\n");
			ret = 1;
			goto out;
		}
	}

	TEST_MSG("OK\n");

	out:
	return ret;
}

static int __rrr_test_http_endpoint_and_query_string_split (void) {
	int ret = 0;

	static const char rrr_http_test_endpoint_and_query_string_fail_a[] = "a%2/b%";
	static const char rrr_http_test_endpoint_and_query_string_fail_b[] = "a%20/b%";

	static const char rrr_http_test_endpoint_and_query_string_ok_a[] = "a%20/b%20/c?a=b%20&c=+";
	static const char rrr_http_test_endpoint_and_query_string_ok_a_endpoint[] = "a /b /c";
	static const char rrr_http_test_endpoint_and_query_string_ok_a_query_string[] = "a=b%20&c=+";

	static const char rrr_http_test_endpoint_and_query_string_ok_b[] = "a%20/b%20/c";
	static const char rrr_http_test_endpoint_and_query_string_ok_b_endpoint[] = "a /b /c";
	static const char rrr_http_test_endpoint_and_query_string_ok_b_query_string[] = "";

	static const char rrr_http_test_endpoint_and_query_string_ok_c[] = "?b=c%20";
	static const char rrr_http_test_endpoint_and_query_string_ok_c_endpoint[] = "";
	static const char rrr_http_test_endpoint_and_query_string_ok_c_query_string[] = "b=c%20";

	static const char rrr_http_test_endpoint_and_query_string_ok_d[] = "a/b?";
	static const char rrr_http_test_endpoint_and_query_string_ok_d_endpoint[] = "a/b";
	static const char rrr_http_test_endpoint_and_query_string_ok_d_query_string[] = "";

	struct rrr_nullsafe_str *tmp = NULL;

	TEST_MSG("HTTP endpoint/query string split fail A...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_fail_a,
			NULL,
			NULL
	);

	TEST_MSG("HTTP endpoint/query string split fail B...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_fail_b,
			NULL,
			NULL
	);

	TEST_MSG("HTTP endpoint/query string split succeed A...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_ok_a,
			rrr_http_test_endpoint_and_query_string_ok_a_endpoint,
			rrr_http_test_endpoint_and_query_string_ok_a_query_string
	);

	TEST_MSG("HTTP endpoint/query string split succeed B...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_ok_b,
			rrr_http_test_endpoint_and_query_string_ok_b_endpoint,
			rrr_http_test_endpoint_and_query_string_ok_b_query_string
	);

	TEST_MSG("HTTP endpoint/query string split succeed C...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_ok_c,
			rrr_http_test_endpoint_and_query_string_ok_c_endpoint,
			rrr_http_test_endpoint_and_query_string_ok_c_query_string
	);

	TEST_MSG("HTTP endpoint/query string split succeed D...");
	ret |= __rrr_test_http_endpoint_and_query_string_split_step (
			&tmp,
			rrr_http_test_endpoint_and_query_string_ok_d,
			rrr_http_test_endpoint_and_query_string_ok_d_endpoint,
			rrr_http_test_endpoint_and_query_string_ok_d_query_string
	);

	rrr_nullsafe_str_destroy_if_not_null(&tmp);
	return ret;
}

int rrr_test_http (void) {
	int ret = 0;

	if ((ret = __rrr_test_http_endpoint_and_query_string_split()) != 0) {
		goto out;
	}

	out:
	return ret;
}
