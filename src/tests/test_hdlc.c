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
#include "../lib/parse.h"
#include "../lib/allocator.h"
#include "../lib/rrr_strerror.h"
#include "../lib/hdlc/hdlc.h"
#include "../lib/array_tree.h"
#include "../lib/util/rrr_time.h"

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

	assert(sizeof(buf) > RRR_HDLC_MAX);

	TEST_MSG("Raw HDLC zero byte frame...\n");
	buf[0] = 0x7e;
	buf[1] = 0x7e;
	rrr_parse_pos_init(&pos, buf, 2);
	rrr_hdlc_parse_state_init(&state, &pos);
	if ((ret = rrr_hdlc_parse_frame(&state)) != RRR_HDLC_INCOMPLETE) {
		TEST_MSG("Parsing zero byte frame did not return incomplete as expected, return was %i\n", ret);
		ret = 1;
		goto out;
	}

	TEST_MSG("Raw HDLC overflow...\n");
	memset(buf, '\0', sizeof(buf));
	buf[offset] = 0x7e;
	rrr_parse_pos_init(&pos, buf, rrr_length_from_size_t_bug_const(sizeof(buf)));
	rrr_hdlc_parse_state_init(&state, &pos);

	if ((ret = rrr_hdlc_parse_frame(&state)) != RRR_HDLC_SOFT_ERROR) {
		TEST_MSG("Parsing overflow test did not return soft error as expected, return was %i\n", ret);
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
	buf[0] = 0x7e; // Double 0x7e at beginning should be ignored
	buf[1] = 0x7e;
	buf[2] = 0x7d;
	buf[3] = 0x7e ^ 0x20;
	buf[4] = 0x7d;
	buf[5] = 0x10 ^ 0x20;
	buf[6] = 0x7e;
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

static const char rrr_test_hdlc_array_definition[] = "hdlc#my_hdlc;";
static const char rrr_test_hdlc_array_tag[] = "my_hdlc";

struct rrr_test_hdlc_array_import_callback_data {
	char *target;
	rrr_length *target_size;
};

static int __rrr_test_hdlc_array_import_callback (struct rrr_array *array, void *arg) {
	struct rrr_test_hdlc_array_import_callback_data *callback_data = arg;

	int ret = 0;

	const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(array, rrr_test_hdlc_array_tag);
	struct rrr_msg_msg *msg = NULL;

	if (value == NULL) {
		TEST_MSG("Value was NULL in %s\n", __func__);
		ret = 1;
		goto out;
	}

	assert(RRR_TYPE_IS_BLOB(value->definition->type));
	assert(RRR_TYPE_IS_HDLC(value->definition->type));
	assert(rrr_type_value_is_tag(value, rrr_test_hdlc_array_tag));
	assert (value->element_count == 1);
	assert(*callback_data->target_size > value->total_stored_length);

	memcpy(callback_data->target, value->data, value->total_stored_length);
	*callback_data->target_size = value->total_stored_length;

	// Pack to message
	if ((ret = rrr_array_new_message_from_array (
			&msg,
			array,
			rrr_time_get_64(),
			NULL,
			0
	)) != 0) {
		TEST_MSG("Failed to create message in %s\n", __func__);
		goto out;
	}

	// Unpack
	uint16_t version;
	if ((ret = rrr_array_message_append_to_array (
			&version,
			array,
			msg
	)) != 0) {
		TEST_MSG("Failed to create message in %s\n", __func__);
		goto out;
	}

	assert(rrr_array_count(array) == 2);

	const struct rrr_type_value *value_unpacked = rrr_array_value_get_by_index(array, 1);

	if (value->total_stored_length != value_unpacked->total_stored_length) {
		TEST_MSG("Length mismatch after unpacking in %s\n", __func__);
		ret = 1;
		goto out;
	}

	assert(value->element_count == value_unpacked->element_count);
	assert(memcmp(value->data, value_unpacked->data, value->total_stored_length) == 0);
	assert(value->definition->type == value_unpacked->definition->type);

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_hdlc_array_import (void) {
	int ret = 0;

	char target[64];
	rrr_length target_size = rrr_length_from_size_t_bug_const(sizeof(target));
	char source[65535];
	struct rrr_array_tree *tree;
	rrr_length parsed_bytes = 0;

	if ((ret = rrr_array_tree_interpret_raw (
			&tree,
			rrr_test_hdlc_array_definition,
			rrr_length_from_size_t_bug_const(sizeof(rrr_test_hdlc_array_definition) - 1),
			"my_definition"
	)) != 0) {
		TEST_MSG("Failed to interpret array tree definition in %s\n", __func__);
		goto out_final;
	}

	TEST_MSG("Array tree import of HDLC frame...\n");

	source[0] = 0x7e;
	source[1] = 0x7d;
	source[2] = 0x7e ^ 0x20;
	source[3] = 0x7d;
	source[4] = 0x10 ^ 0x20;
	source[5] = 0x7e;

	struct rrr_test_hdlc_array_import_callback_data callback_data = {
		target,
		&target_size
	};

	// Parse half the frame
	if ((ret = rrr_array_tree_import_from_buffer (
			&parsed_bytes,
			source,
			3,
			tree,
			__rrr_test_hdlc_array_import_callback,
			&callback_data
	)) == RRR_ARRAY_TREE_PARSE_INCOMPLETE) {
		// OK, expected result
	}
	else {
		TEST_MSG("Unexpected result %i from array tree import in %s\n", ret, __func__);
		ret = 1;
		goto out;
	}

	assert(parsed_bytes == 0);

	// Parse the whole frame
	if ((ret = rrr_array_tree_import_from_buffer (
			&parsed_bytes,
			source,
			6,
			tree,
			__rrr_test_hdlc_array_import_callback,
			&callback_data
	)) == RRR_ARRAY_TREE_OK) {
		// OK, expected result
	}
	else {
		TEST_MSG("Unexpected result %i from array tree import in %s\n", ret, __func__);
		ret = 1;
		goto out;
	}

	assert(parsed_bytes == 6);

	if (*callback_data.target_size != 2) {
		TEST_MSG("Incorrect frame size of %" PRIrrrl " after array import\n", *callback_data.target_size);
		ret = 1;
		goto out;
	}

	if (target[0] != 0x7e || target[1] != 0x10) {
		TEST_MSG("Incorrect frame data after array import\n");
		ret = 1;
		goto out;
	}

	out:
		rrr_array_tree_destroy(tree);
	out_final:
		return ret;
}

static int __rrr_test_hdlc_array_export (void) {
	int ret = 0;

	char *target = NULL;
	rrr_biglength target_size;
	struct rrr_array array = {0};

	TEST_MSG("Array tree export of HDLC frame...\n");

	// assert rrr_type_value_get_export_length
	//r rrr_type_vaoue_allocate_and_export

	{
		struct rrr_type_value *value;
		if ((ret = rrr_type_value_new (
				&value,
				rrr_type_get_from_id(RRR_TYPE_HDLC),
				0,
				0,
				NULL,
				0,
				NULL,
				1,
				NULL,
				3
		)) != 0) {
			TEST_MSG("Failed to create value in %s\n", __func__);
			goto out;
		}
		RRR_LL_APPEND(&array, value);

		// Use values which will be escaped
		value->data[0] = 0x7e;
		value->data[1] = 0x7d;
		value->data[2] = 0x10;
	}

	int found_tags = 0;
	if ((ret = rrr_array_selected_tags_export (
			&target,
			&target_size,
			&found_tags,
			&array,
			NULL
	)) != 0) {
		TEST_MSG("Failed to pack array in %s\n", __func__);
		goto out;
	}

	assert(found_tags == 1);

	if (target_size != 7) {
		TEST_MSG("Unexpected exported size of %" PRIrrrbl " in %s\n", target_size, __func__);
		ret = 1;
		goto out;
	}

	if (target[0] != 0x7e ||
	    target[1] != 0x7d ||
	    target[2] != (0x7e ^ 0x20) ||
	    target[3] != 0x7d ||
	    target[4] != (0x7d ^ 0x20) ||
	    target[5] != 0x10 ||
	    target[6] != 0x7e
	) {
		TEST_MSG("Invalid exported data in %s\n", __func__);
		ret = 1;
		return ret;
	}

	out:
	rrr_array_clear(&array);
	RRR_FREE_IF_NOT_NULL(target);
	return ret;
}

int rrr_test_hdlc(void) {
	int ret = 0;

	ret |= __rrr_test_hdlc_read();
	ret |= __rrr_test_hdlc_array_import();
	ret |= __rrr_test_hdlc_array_export();

	return ret;
}

