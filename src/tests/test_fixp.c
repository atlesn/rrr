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

#include "test.h"
#include "test_fixp.h"
#include "../lib/fixed_point.h"

int rrr_test_fixp(void) {
	int ret = 0;

	rrr_fixp fixp_a = 0;
	rrr_fixp fixp_b = 0;
	rrr_fixp fixp_c = 0;

	const char *endptr;

	const char *a_str = "+1.5yuiyuiyuiyu";
	const char *b_str = "-1.5##%%¤#";
	const char *c_str = "15.671875";

	ret |= rrr_fixp_str_to_fixp(&fixp_a, a_str, strlen(a_str), &endptr);
	if (endptr - a_str != 4) {
		TEST_MSG("End pointer position was incorrect for A\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_b, b_str, strlen(b_str), &endptr);
	if (endptr - b_str != 4) {
		TEST_MSG("End pointer position was incorrect for B\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_c, c_str, strlen(c_str), &endptr);

	if (ret != 0) {
		TEST_MSG("Conversion from string to fixed point failed\n");
		goto out;
	}

	if (fixp_a == 0) {
		TEST_MSG("Zero returned while converting string to fixed point\n");
		ret = 1;
		goto out;
	}

	ret = fixp_a + fixp_b;
	if (ret != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5, got %i\n", ret);
		ret = 1;
		goto out;
	}

	char buf[512];
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

	long double dbl = 0;
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

	ret = fixp_a + fixp_b;
	if (ret != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5 after conversion from double, got %i\n", ret);
		ret = 1;
		goto out;
	}

	const char *a_hex = "16#+1.8/¤#";
	if (rrr_fixp_str_to_fixp(&fixp_a, a_hex, strlen(a_hex), &endptr) != 0) {
		TEST_MSG("Hexadecimal conversion failed\n");
		ret = 1;
		goto out;
	}

	if (endptr - a_hex != 7) {
		TEST_MSG("End pointer position was incorrect for hex\n");
		ret = 1;
		goto out;
	}

	if (rrr_fixp_to_ldouble(&dbl, fixp_a) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed (hex)\n");
		ret = 1;
		goto out;
	}

	if (dbl != 1.5) {
		TEST_MSG("Wrong output while converting fixed point to double (hex test), expected 1.5 but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	out:
	return (ret != 0);
}
