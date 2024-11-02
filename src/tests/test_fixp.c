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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "test.h"
#include "test_fixp.h"
#include "../lib/fixed_point.h"
#include "../lib/util/macro_utils.h"

int rrr_test_fixp(void) {
	int ret = 0;

	rrr_fixp fixp_a = 0;
	rrr_fixp fixp_b = 0;
	rrr_fixp fixp_c = 0;

	const char *endptr;

	const char *a_str = "+1.5yuiyuiyuiyu";
	const char *b_str = "-1.5##%%¤#";
	const char *c_str = "15.671875";

	char *tmp = NULL;
	char buf[512];
	rrr_fixp test = 0;
	long double dbl = 0;

	ret |= rrr_fixp_str_to_fixp(&fixp_a, a_str, (rrr_length) strlen(a_str), &endptr);
	if (endptr - a_str != 4) {
		TEST_MSG("End pointer position was incorrect for A\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_b, b_str, (rrr_length) strlen(b_str), &endptr);
	if (endptr - b_str != 4) {
		TEST_MSG("End pointer position was incorrect for B\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_c, c_str, (rrr_length) strlen(c_str), &endptr);
	if (endptr - c_str != 9) {
		TEST_MSG("End pointer position was incorrect for C\n");
		ret = 1;
		goto out;
	}

	if (ret != 0) {
		TEST_MSG("Conversion from string to fixed point failed\n");
		goto out;
	}


	if (fixp_a == 0) {
		TEST_MSG("Zero returned while converting string to fixed point\n");
		ret = 1;
		goto out;
	}

	test = fixp_a + fixp_b;
	if (test != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5, got %" PRIu64 "\n", test);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_to_str_double(buf, 511, fixp_a)) != 0) {
		TEST_MSG("Conversion from fixed point to string failed\n");
		goto out;
	}
	if (strncmp(buf, "1.5", 3) != 0) {
		TEST_MSG("Wrong output while converting fixed point to string, expected '1.5' but got '%s'\n", buf);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_to_str_double(buf, 511, fixp_c)) != 0) {
		TEST_MSG("Conversion from fixed point to string failed\n");
		goto out;
	}
	if (strncmp(buf, "15.671875", 8) != 0) {
		TEST_MSG("Wrong output while converting fixed point to string, expected '5.671875' but got '%s'\n", buf);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_to_new_str_double (&tmp, fixp_c)) != 0) {
		TEST_MSG("Conversion from fixed point to new string failed\n");
		goto out;
	}
	if (strcmp(buf, tmp) != 0) {
		TEST_MSG("Mismatch from static and dynamic fixp to string functions: '%s'<>'%s'\n", buf, tmp);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_to_ldouble(&dbl, fixp_a)) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed\n");
		goto out;
	}

	if (dbl != 1.5) {
		TEST_MSG("Wrong output while converting fixed point to double, expected 1.5 but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_ldouble_to_fixp(&fixp_a, dbl)) != 0) {
		TEST_MSG("Conversion from double to fixed point failed\n");
		goto out;
	}

	test = fixp_a + fixp_b;
	if (test != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5 after conversion from double, got %" PRIu64 "\n", test);
		ret = 1;
		goto out;
	}

	const char *a_hex = "16#+1.8/¤#";
	if (rrr_fixp_str_to_fixp(&fixp_a, a_hex, (rrr_length) strlen(a_hex), &endptr) != 0) {
		TEST_MSG("Hexadecimal conversion A failed\n");
		ret = 1;
		goto out;
	}

	if (endptr - a_hex != 7) {
		TEST_MSG("End pointer position was incorrect for hex A\n");
		ret = 1;
		goto out;
	}

	if (rrr_fixp_to_ldouble(&dbl, fixp_a) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed for hex A\n");
		ret = 1;
		goto out;
	}

	if (dbl != 1.5) {
		TEST_MSG("Wrong output while converting fixed point to double (hex test), expected 1.5 but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	const char *b_hex = "16#-0.000001";
	if (rrr_fixp_str_to_fixp(&fixp_b, b_hex, (rrr_length) strlen(b_hex), &endptr) != 0) {
		TEST_MSG("Hexadecimal conversion B failed\n");
		ret = 1;
		goto out;
	}

	if (endptr - b_hex != 12) {
		TEST_MSG("End pointer position was incorrect for hex B\n");
		ret = 1;
		goto out;
	}

	if ((uint64_t) fixp_b != 0xffffffffffffffff) {
		TEST_MSG("Wrong output while converting fixed point to double (hex B), expected 0xffffffffffffffff but got 0x%llx\n", (unsigned long long) fixp_b);
		ret = 1;
		goto out;
	}

	if (rrr_fixp_to_ldouble(&dbl, fixp_b) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed for hex B\n");
		ret = 1;
		goto out;
	}

	if (dbl != -0.00000005960464477539f) {
		TEST_MSG("Wrong output while converting fixed point to double (hex B), expected -0.00000005960464477539f but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	if (rrr_fixp_from_ldouble(&test, dbl) != 0) {
		TEST_MSG("Conversion from ldouble to fixed point failed for hex B\n");
		ret = 1;
		goto out;
	}

	if (test != fixp_b) {
		TEST_MSG("Wrong output while converting ldouble to fixed point (hex B), expected 0xffffffffffffffff but got 0x%llx\n", (unsigned long long) test);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return (ret != 0);
}
