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
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "test.h"
#include "test_hdlc.h"
#include "../lib/route.h"
#include "../lib/parse.h"
#include "../lib/rrr_strerror.h"

static const char *TEST_DATA_FILE = "test_hdlc_data.bin";

int rrr_test_hdlc(void) {
	int ret = 0;

	int fd = open(TEST_DATA_FILE, 0);

	if (fd == -1) {
		TEST_MSG("Failed to open %s: %s\n", TEST_DATA_FILE, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	ret = 1;

	out:
	return ret;
}

