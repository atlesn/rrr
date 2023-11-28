/*

Read Route Record

Copyright (C) 2021-2023 Atle Solbakken atle@goliathdns.no

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
#include "../lib/util/increment.h"
#include "../lib/util/macro_utils.h"
#include "test.h"
#include "test_increment.h"

#define FAIL_IF_NE(exp_i) \
	do {if (i != exp_i) { TEST_MSG("Incrementer: i was not " RRR_QUOTE(exp_i) "\n"); return 1; }} while (0)

static int __test_increment_bits_to_max (void) {
	int ret = 0;

	uint64_t acc = 0;
	for (int i = 0; i <= 64; i++) {
		uint64_t max = rrr_increment_bits_to_max(i);
		if (max != acc) {
			RRR_MSG_1("rrr_increment_bits_to_max(%d) returned %llu, expected %llu\n", i, max, acc);
			ret = 1;
		}
		acc = (acc << 1) | 1;
	}

	return ret;
}
/*
int rrr_increment_verify_value_prefix (
		uint64_t value,
		uint32_t max,
		uint64_t prefix
);
 
* */

static int __test_increment_verify_value_prefix (void) {
	int ret = 0;

	uint64_t value;
	uint32_t max;
	uint64_t prefix;

	value =  0x0000dead0000beef;
	max =    0x00000000ffffffff;
	prefix = 0xdead;

	if (rrr_increment_verify_value_prefix (value, max, prefix) != 0) {
		RRR_MSG_0("rrr_increment_verify_value_prefix failed unexpectedly\n");
		ret = 1;
	}

	prefix = 0x1dead;

	if (rrr_increment_verify_value_prefix (value, max, prefix) != 1) {
		RRR_MSG_0("rrr_increment_verify_value_prefix did not fail as expected A\n");
		ret = 1;
	}

	prefix = 0xead;

	if (rrr_increment_verify_value_prefix (value, max, prefix) != 1) {
		RRR_MSG_0("rrr_increment_verify_value_prefix did not fail as expected B\n");
		ret = 1;
	}

	value =  0x00000ead0000beef;
	prefix = 0xdead;

	if (rrr_increment_verify_value_prefix (value, max, prefix) != 1) {
		RRR_MSG_0("rrr_increment_verify_value_prefix did not fail as expected C\n");
		ret = 1;
	}

	value =  0x0001dead0000beef;

	if (rrr_increment_verify_value_prefix (value, max, prefix) != 1) {
		RRR_MSG_0("rrr_increment_verify_value_prefix did not fail as expected D\n");
		ret = 1;
	}

	return ret;
}

static int __test_increment_verify (void) {
	int ret = 0;
	// Step or mod too high
	if (rrr_increment_verify(0x100, 1, 100, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on step_or_mod > 0xff\n");
		ret = 1;
	}
	// Min too high
	if (rrr_increment_verify(1, 0x100000000, 100, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on min > 0xffffffff\n");
		ret = 1;
	}
	// Max too high
	if (rrr_increment_verify(1, 1, 0x100000000, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on max > 0xffffffff\n");
		ret = 1;
	}
	// Position too high
	if (rrr_increment_verify(1, 1, 100, 0x100000000, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on position > 0xffffffff\n");
		ret = 1;
	}
	// Min > max
	if (rrr_increment_verify(1, 100, 1, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on min > max\n");
		ret = 1;
	}
	// Mod is 0
	if (rrr_increment_verify(0, 1, 100, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on mod == 0\n");
		ret = 1;
	}
	// Max - min + 1 < mod
	if (rrr_increment_verify(100, 1, 10, 0, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on max - min + 1 < mod\n");
		ret = 1;
	}
	// Position > mod - 1
	if (rrr_increment_verify(100, 1, 100, 100, 0) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on position > mod - 1\n");
		ret = 1;
	}
	// Prefix overlaps max
	if (rrr_increment_verify(1, 1, 0xffffffff, 0, 0x100000000) != 1) {
		RRR_MSG_0("rrr_increment_verify did not fail on prefix overlaps max\n");
		ret = 1;
	}
	// Valid
	if (rrr_increment_verify(1, 1, 0xffffffff, 0, 0xffffffff) != 0) {
		RRR_MSG_0("rrr_increment_verify failed on valid input\n");
		ret = 1;
	}

	return ret;
}

static int __test_increment_prefix_apply (void) {
	int ret = 0;

	uint32_t value;
	uint32_t max;
	uint64_t prefix;
	uint64_t res;

	value = 0xdeadbeef;
	max = 0xffffffff; 
	prefix = 0x12345678;

	if ((res = rrr_increment_apply_prefix(value, max, prefix)) != 0x12345678deadbeef) {
		RRR_MSG_0("rrr_increment_prefix_apply returned %" PRIx64 " while %" PRIx64 " was expected A\n",
			res, 0x12345678deadbeef);
		ret = 1;
	}

	value = 0xeadbeef;
	max = 0xfffffff;
	prefix = 0x123456789;

	if ((res = rrr_increment_apply_prefix(value, max, prefix)) != 0x123456789eadbeef) {
		RRR_MSG_0("rrr_increment_apply_prefix returned %" PRIx64 " while %" PRIx64 " was expected B\n",
			res, 0x123456789eadbeef);
		ret = 1;
	}

	value = 0xdeadbeef;
	max = 0xffffffff;
	prefix = 0x123456;

	if ((res = rrr_increment_apply_prefix(value, max, prefix)) != 0x00123456deadbeef) {
		RRR_MSG_0("rrr_increment_apply_prefix returned %" PRIx64 " while %" PRIx64 " was expected C\n",
			res, 0x123456deadbeef);
		ret = 1;
	}

	value = 0xbeef;
	max = 0xffff;
	prefix = 0xdead;

	if ((res = rrr_increment_apply_prefix(value, max, prefix)) != 0x00000000deadbeef) {
		RRR_MSG_0("rrr_increment_apply_prefix returned %" PRIx64 " while %" PRIx64 " was expected D\n",
			res, (uint64_t) 0x00000000deadbeef);
		ret = 1;
	}

	value = 0xbeef;
	max = 0xffffffff; 
	prefix = 0x12345678;

	if ((res = rrr_increment_apply_prefix(value, max, prefix)) != 0x123456780000beef) {
		RRR_MSG_0("rrr_increment_apply_prefix returned %" PRIx64 " while %" PRIx64 " was expected E\n",
			res, 0x123456780000beef);
		ret = 1;
	}

	if ((value = rrr_increment_strip_prefix(&prefix, res, max)) != 0xbeef || prefix != 0x12345678) {
		RRR_MSG_0("rrr_increment_strip prefix returned %" PRIx32 " and %" PRIx64 " while " \
			"%" PRIx32 " and %" PRIx64 " was expected\n",
			value, res,
			0xbeef, 0x12345678);
		ret = 1;
	}

	return ret;
}

static int __test_increment_max_to_prefix_mask (void) {
	int ret = 0;

	uint32_t max = 0xffff;
	uint64_t res = 0xdeadbeef1234;
	uint64_t mask = rrr_increment_max_to_prefix_mask(max);

	if ((res &= mask) != 0xdeadbeef0000) {
		RRR_MSG_0("rrr_increment_max_to_prefix_mask returned %" PRIx64 " while %" PRIx64 " was expected\n",
			res, 0xdeadbeef0000);
		ret = 1;
	}

	return ret;
}

int rrr_test_increment (void) {
	int ret = 0;

	if (__test_increment_bits_to_max() != 0) {
		return 1;
	}

	if (__test_increment_verify_value_prefix() != 0) {
		return 1;
	}

	if (__test_increment_verify() != 0) {
		return 1;
	}

	if (__test_increment_prefix_apply() != 0) {
		return 1;
	}

	if (__test_increment_max_to_prefix_mask() != 0) {
		return 1;
	}

	uint32_t i = 1;

	i = rrr_increment_basic(i, 1, 1, 2);
	FAIL_IF_NE(2);

	i = rrr_increment_basic(i, 1, 1, 2);
	FAIL_IF_NE(1);

	i = rrr_increment_mod(i, 1, 3, 4, 0);
	FAIL_IF_NE(3);

	i = rrr_increment_mod(i, 1, 3, 4, 0);
	FAIL_IF_NE(4);

	i = rrr_increment_mod(i, 1, 3, 4, 0);
	FAIL_IF_NE(3);

	i = rrr_increment_mod(i, 2, 3, 10, 0);
	FAIL_IF_NE(4);

	i = rrr_increment_mod(i, 2, 3, 10, 0);
	FAIL_IF_NE(6);

	i = rrr_increment_mod(i, 2, 3, 6, 0);
	FAIL_IF_NE(4);

	i = rrr_increment_mod(i, 2, 3, 6, 1);
	FAIL_IF_NE(3);

	i = rrr_increment_basic(i, 0xffffffff - 3 - 1, 1, 0xffffffff);
	FAIL_IF_NE(0xfffffffe);

	i = rrr_increment_mod(i, 200, 1, 0xffffffff, 1);
	FAIL_IF_NE(1);

	return ret;
}
