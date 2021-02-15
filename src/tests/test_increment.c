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

#include <stdio.h>
#include <string.h>

#include "../lib/log.h"
#include "../lib/util/increment.h"
#include "../lib/util/macro_utils.h"
#include "test.h"
#include "test_increment.h"

#define FAIL_IF_NE(exp_i) \
	do {if (i != exp_i) { TEST_MSG("Incrementer: i was not " RRR_QUOTE(exp_i) "\n"); return 1; }} while (0)

int rrr_test_increment (void) {
	int ret = 0;

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
