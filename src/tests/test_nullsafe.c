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
#include "test_nullsafe.h"
#include "../lib/helpers/nullsafe_str.h"
#include "../lib/util/macro_utils.h"

static int __rrr_test_nullsafe_split_callback (
		const void *start,
		rrr_nullsafe_len chunk_len,
		int is_last,
		void *arg
) {
	int *counter = arg;

	(void)(start);

	if (is_last && chunk_len == 5) {
		// OK
	}
	else if (chunk_len != 0 && chunk_len != 3) {
		TEST_MSG("Wrong size failure in split result %llu<>0 AND %llu<>3\n",
		(long long unsigned) chunk_len, (long long unsigned) chunk_len);
		return 1;
	}

	(*counter)++;

	return 0;
}

#define SPLIT()                                                                                                      \
	do { if ((ret = rrr_nullsafe_str_split_raw(str, '/', __rrr_test_nullsafe_split_callback, &counter)) != 0) {  \
		TEST_MSG("Failure from nullsafe split\n"); goto out;                                                 \
	}} while (0)

#define CHECK_AND_RESET_COUNTER(target,error_msg)                                        \
	if (counter != target) {                                                         \
		TEST_MSG("Counter failure for " error_msg " %i<>%i\n", target, counter); \
		ret = 1;                                                                 \
		goto out;                                                                \
	} counter = 0

#define SPLIT_CHECK_AND_RESET_COUNTER(target,error_msg)  \
	SPLIT();                                         \
	CHECK_AND_RESET_COUNTER(target,error_msg)

#define APPEND(string)                                                                    \
	do {if ((ret = rrr_nullsafe_str_append_raw(str, string, strlen(string))) != 0) {  \
		TEST_MSG("Failed to append to string\n"); goto out;                       \
	}} while(0)

#define PREPEND(string)                                                                    \
	do {if ((ret = rrr_nullsafe_str_prepend_raw(str, string, strlen(string))) != 0) {  \
		TEST_MSG("Failed to prepend to string\n"); goto out;                       \
	}} while(0)

int rrr_test_nullsafe(void) {
	int ret = 0;

	struct rrr_nullsafe_str *str = NULL;

	if ((ret = rrr_nullsafe_str_new_or_replace_empty(&str)) != 0) {
		goto out;
	}

	int counter = 0;

	SPLIT_CHECK_AND_RESET_COUNTER(0, "empty split");
	APPEND("/");
	SPLIT_CHECK_AND_RESET_COUNTER(2, "separator only split");
	PREPEND("aaa/");
	SPLIT_CHECK_AND_RESET_COUNTER(3, "single value split with two separators at the end");
	APPEND("aaa");
	SPLIT_CHECK_AND_RESET_COUNTER(3, "two value split with two separators in the middle");
	APPEND("aa");
	SPLIT_CHECK_AND_RESET_COUNTER(3, "two value split with two separators in the middle, last value is longer");

	out:
	rrr_nullsafe_str_destroy_if_not_null(&str);
	return (ret != 0);
}
