/*

Block Device Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdint.h>

#include "../include/bdl.h"
#include "update.h"
#include "blocks.h"
#include "write.h"

struct update_block_loop_data {
	uint64_t timestamp_gteq;
	uint64_t application_data_and;
	unsigned long int result_count;
	struct bdl_update_callback_data *update_data;
	struct bdl_update_info (*test)(void *arg, struct bdl_update_callback_data *update_data);
	void *test_arg;
};

int update_block_loop_callback(struct bdl_block_loop_callback_data *data, int *result) {
	struct update_block_loop_data *loop_data = (struct update_block_loop_data *) data->argument_ptr;
	const struct bdl_block_header *block_header = data->block;

	*result = BDL_BLOCK_LOOP_OK;

	if (	(block_header->timestamp < loop_data->timestamp_gteq) ||
			(block_header->application_data & loop_data->application_data_and) == 0
	) {
		return 0;
	}

	struct bdl_update_callback_data callback_data = {
			block_header->timestamp,
			block_header->application_data,
			block_header->data_length,
			data->block_data
	};

	struct bdl_update_info update_info = loop_data->test (
		loop_data->test_arg,
		&callback_data
	);

	if (update_info.do_update == 1) {
		struct bdl_block_header new_header = *block_header;
		new_header.application_data = update_info.new_appdata;
		if (write_checksum_and_put_block(
			&new_header,
			block_header->data_length, data->block_data,
			data->master_header,
			data->block_position,
			data->file
		) != 0) {
			*result =  BDL_BLOCK_LOOP_ERR;
			return 1;
		}

		loop_data->result_count++;
	}

	if (update_info.do_break == 1) {
		*result = BDL_BLOCK_LOOP_BREAK;
	}

	return 0;
}

int update_hintblock_loop_callback(
		struct bdl_hintblock_loop_callback_data *data,
		int *result
) {
	struct update_block_loop_data *loop_data = (struct update_block_loop_data *) data->argument_ptr;
	const struct bdl_hintblock_state *hintblock_state = &data->location->hintblock_state;
	const struct bdl_header *master_header = data->master_header;

	if (hintblock_state->valid != 1) {
		*result = BDL_BLOCK_LOOP_BREAK;
		return 0;
	}

	if (hintblock_state->highest_timestamp < loop_data->timestamp_gteq) {
		*result = BDL_BLOCK_LOOP_OK;
		return 0;
	}

	*result = BDL_BLOCK_LOOP_OK;

	char block_buf[master_header->block_size];
	struct bdl_block_header *block_header;
	char *block_data;

	struct bdl_block_loop_callback_data callback_data;
	unsigned long int block_position;

	callback_data.argument_int = 0;
	callback_data.argument_ptr = (void *) loop_data;

	if (block_loop_blocks(
			data->file, master_header, hintblock_state,
			update_block_loop_callback,
			block_buf, master_header->block_size,
			&block_header, &block_data,
			&callback_data,
			result
	) != 0) {
		fprintf (stderr, "Error while looping blocks in hintblock loop\n");
		return 1;
	}

	return 0;
}

int update_application_data (
	struct bdl_io_file *session_file,
	uint64_t timestamp_min,
	uint64_t application_data_and,
	struct bdl_update_info (*test)(void *arg, struct bdl_update_callback_data *update_data),
	void *arg,
	int *result_final
) {
	struct bdl_header header;
	int result;
	*result_final = 0;

	// Read master header
	if (block_get_validate_master_header(session_file, &header, &result) != 0) {
		fprintf (stderr, "Could not get header from device while writing new data block\n");
		return BDL_WRITE_ERR_IO;
	}

	if (result != 0) {
		fprintf (stderr, "Invalid header of device while writing new data block\n");
		return BDL_WRITE_ERR_CORRUPT;
	}

	// Find oldest hint block
	struct bdl_block_location oldest_location;
	if (block_find_oldest_hintblock(session_file, &header, timestamp_min, &oldest_location, &result) != 0) {
		fprintf (stderr, "Error while finding oldest hint block\n");
		return 1;
	}

	// Check if no blocks were found
	if (oldest_location.hintblock_state.valid != 1) {
		return 0;
	}

	// Loop and update data
	struct update_block_loop_data loop_data;
	loop_data.timestamp_gteq = timestamp_min;
	loop_data.application_data_and = application_data_and;
	loop_data.result_count = 0;
	loop_data.test = test;
	loop_data.test_arg = arg;

	struct bdl_hintblock_loop_callback_data callback_data;
	callback_data.argument_int = 0;
	callback_data.argument_ptr = (void *) &loop_data;

	struct bdl_block_location location;

	if (block_loop_hintblocks_large_device (
			session_file, &header,
			&oldest_location,
			update_hintblock_loop_callback, &callback_data,
			&location,
			&result
	) != 0) {
		fprintf (stderr, "Error while looping hintblocks while updating blocks\n");
		return 1;
	}

	*result_final = loop_data.result_count;

	return 0;
}
