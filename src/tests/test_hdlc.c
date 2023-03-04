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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "test.h"
#include "test_hdlc.h"
#include "../lib/route.h"
#include "../lib/parse.h"
#include "../lib/rrr_strerror.h"
#include "../lib/hdlc/hdlc.h"

static const char *TEST_DATA_FILE = "test_hdlc_data.bin";

static int __rrr_test_hdlc_read (void) {
	int ret = 0;

	const int offset = 16;
	char buf[65535 + offset];
	struct rrr_parse_pos pos;
	struct rrr_hdlc_parse_state state;
	ssize_t bytes;
	int fd;

	if ((fd = open(TEST_DATA_FILE, 0)) == -1) {
		TEST_MSG("Failed to open %s: %s\n", TEST_DATA_FILE, rrr_strerror(errno));
		ret = 1;
		goto out_final;
	}

	assert(sizeof(buf) > RRR_HDLC_MAX(&state));

	memset(buf, '\0', sizeof(buf));

	TEST_MSG("Raw HDLC overflow...\n");
	buf[offset] = 0x7e;
	rrr_parse_pos_init(&pos, buf, rrr_length_from_size_t_bug_const(sizeof(buf)));
	rrr_hdlc_parse_state_init(&state, &pos);

	if ((ret = rrr_hdlc_parse_frame(&state)) != RRR_HDLC_SOFT_ERROR) {
		TEST_MSG("Parsing did not return soft error as expected, return was %i\n", ret);
		ret = 1;
		goto out;
	}

	TEST_MSG("Raw HDLC frames...\n");

	memset(buf, '\0', sizeof(buf));

	// Offset write position to include junk data before first frame
	if ((bytes = read(fd, buf + offset, sizeof(buf) - offset)) <= 0) {
		TEST_MSG("Failed to read %s: %s\n", TEST_DATA_FILE, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	TEST_MSG("Raw HDLC input data size is %lli\n", (long long int) bytes);

	rrr_parse_pos_init(&pos, buf + offset, rrr_length_from_slength_bug_const(bytes));

	for (int i = 0; i < 2; i++) {
		rrr_hdlc_parse_state_init(&state, &pos);

		if ((ret = rrr_hdlc_parse_frame (&state)) != RRR_HDLC_OK) {
			TEST_MSG("Failed to parse HDLC frame index %i, return was %i\n", i, ret);
			ret = 1;
			goto out;
		}

		TEST_MSG("- Parsed frame of size %" PRIrrrl "\n", RRR_HDLC_DATA_SIZE(&state));
	}

	TEST_MSG("Raw HDLC incomplete parsing...\n");
	rrr_hdlc_parse_state_init(&state, &pos);
	if (rrr_hdlc_parse_frame (&state) != RRR_HDLC_INCOMPLETE) {
		TEST_MSG("Parsing did not return incomplete as expected\n");
		ret = 1;
		goto out;
	}

	if (!RRR_PARSE_CHECK_EOF(&pos)) {
		TEST_MSG("Parse input data not exhausted after parsing two frames\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Raw HDLC escape sequence...\n");
	buf[0] = 0x7e;
	buf[1] = 0x7d;
	buf[2] = 0x7e ^ 0x20;
	buf[3] = 0x7d;
	buf[4] = 0x10 ^ 0x20;
	buf[5] = 0x7e;
	rrr_parse_pos_init(&pos, buf, rrr_length_from_size_t_bug_const(sizeof(buf)));
	rrr_hdlc_parse_state_init(&state, &pos);

	if ((ret = rrr_hdlc_parse_frame (&state)) != RRR_HDLC_OK) {
		TEST_MSG("Failed to parse escape sequence, return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if (RRR_HDLC_DATA_SIZE(&state) != 2) {
		TEST_MSG("Data size of escape sequence was not 2 bytes but %" PRIrrrl "\n", RRR_HDLC_DATA_SIZE(&state));
		ret = 1;
		goto out;
	}

	if (RRR_HDLC_DATA(&state)[0] != 0x7e || RRR_HDLC_DATA(&state)[1] != 0x10) {
		TEST_MSG("Incorrect data after resolving escape sequence\n");
		ret = 1;
		goto out;
	}

	

	out:
		close(fd);
	out_final:
		return ret;
}

static int __rrr_test_hdlc_array_import (char target[64]) {
	(void)(target);
	return 1;
}

static int __rrr_test_hdlc_array_export (const char source[64]) {
	(void)(source);
	return 1;
}

int rrr_test_hdlc(void) {
	int ret = 0;

	char frame[64];

	ret |= __rrr_test_hdlc_read();
	ret |= __rrr_test_hdlc_array_import(frame);
	ret |= __rrr_test_hdlc_array_export(frame);

	return ret;
}

