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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "io.h"
#include "read.h"
#include "blocks.h"
#include "../include/bdl.h"

struct read_block_loop_data {
	uint64_t timestamp_gteq;
	unsigned long int limit;
	unsigned long int result_count;
};

//#define BDL_READ_DEBUG

int read_block_loop_callback(struct bdl_block_loop_callback_data *data, int *result) {
	struct read_block_loop_data *loop_data = (struct read_block_loop_data *) data->argument_ptr;
	const struct bdl_block_header *block_header = data->block;

#ifdef BDL_READ_DEBUG
	printf ("Check block at %lu\n", data->block_position);
#endif

	if (block_header->timestamp >= loop_data->timestamp_gteq) {
		block_dump(block_header, data->block_position, data->block_data);
		loop_data->result_count++;
	}

	if (loop_data->limit != 0 && loop_data->result_count == loop_data->limit) {
		*result = BDL_BLOCK_LOOP_BREAK;
	}

	return 0;
}

int read_hintblock_loop_callback(
		struct bdl_hintblock_loop_callback_data *data,
		int *result
) {
	struct read_block_loop_data *loop_data = (struct read_block_loop_data *) data->argument_ptr;
	const struct bdl_hintblock_state *hintblock_state = &data->location->hintblock_state;
	const struct bdl_header *master_header = data->master_header;

#ifdef BDL_READ_DEBUG
	printf ("Checking if hintblock highest timestamp %" PRIx64 " is >= %" PRIx64 "\n",
				hintblock_state->highest_timestamp,
				loop_data->timestamp_gteq
	);
#endif

	if (hintblock_state->valid != 1) {
		#ifdef BDL_READ_DEBUG
			printf ("- Hint block was not valid, ending here\n");
		#endif
		*result = BDL_BLOCK_LOOP_BREAK;
		return 0;
	}

	if (hintblock_state->highest_timestamp < loop_data->timestamp_gteq) {
		#ifdef BDL_READ_DEBUG
			printf ("- Timestamp outside range\n");
		#endif
		*result = BDL_BLOCK_LOOP_OK;
		return 0;
	}

	*result = BDL_BLOCK_LOOP_OK;

#ifdef BDL_READ_DEBUG
	printf ("- Hintblock matched\n");
#endif

	char block_buf[master_header->block_size];
	struct bdl_block_header *block_header;
	char *block_data;

	struct bdl_block_loop_callback_data callback_data;
	unsigned long int block_position;

	callback_data.argument_int = 0;
	callback_data.argument_ptr = (void *) loop_data;

	if (block_loop_blocks(
			data->file, master_header, hintblock_state,
			read_block_loop_callback,
			block_buf, master_header->block_size,
			&block_header, &block_data,
			&callback_data,
			result
	) != 0) {
		fprintf (stderr, "Error while looping blocks in hintblock loop\n");
		return 1;
	}

	if (loop_data->limit != 0 && loop_data->result_count >= loop_data->limit) {
		if (loop_data->result_count > loop_data->limit) {
			fprintf (stderr, "Bug: Result limit exceeded\n");
			exit (EXIT_FAILURE);
		}
#ifdef BDL_READ_DEBUG
		printf ("- Limit reached, breaking out\n");
#endif
		*result = BDL_BLOCK_LOOP_BREAK;
	}

	return 0;
}

int read_blocks (struct bdl_io_file *device, uint64_t timestamp_gteq, unsigned long int limit) {
	struct bdl_header master_header;
	int result;

	if (block_get_validate_master_header(device, &master_header, &result) != 0) {
		fprintf (stderr, "Error while getting master header before reading\n");
		return 1;

	}
	if (result != 0) {
		fprintf (stderr, "Master header of device was not valid before reading\n");
		return 1;
	}

	// Find oldest hint block
	struct bdl_block_location oldest_location;
	if (block_find_oldest_hintblock(device, &master_header, timestamp_gteq, &oldest_location, &result) != 0) {
		fprintf (stderr, "Error while finding oldest hint block\n");
		return 1;
	}

#ifdef BDL_READ_DEBUG
	if (oldest_location.hintblock_state.valid == 1) {
		printf ("Found oldest hintblock at %lu highest timestamp %" PRIu64 "\n",
				oldest_location.hintblock_state.location, oldest_location.hintblock_state.highest_timestamp
		);
		if (oldest_location.hintblock_state.highest_timestamp == 0) {
			fprintf (stderr, "Bug: Smallest timestamp found was zero\n");
			exit (EXIT_FAILURE);

		}
	}
	else {
		printf ("No hintblocks found\n");
	}
#endif

	// Check if no blocks were found
	if (oldest_location.hintblock_state.valid != 1) {
		return 0;
	}

	// Read data
	struct read_block_loop_data loop_data;
	loop_data.timestamp_gteq = timestamp_gteq;
	loop_data.limit = limit;
	loop_data.result_count = 0;

	struct bdl_hintblock_loop_callback_data callback_data;
	callback_data.argument_int = 0;
	callback_data.argument_ptr = (void *) &loop_data;

	struct bdl_block_location location;

	if (block_loop_hintblocks_large_device (
			device, &master_header,
			&oldest_location,
			read_hintblock_loop_callback, &callback_data,
			&location,
			&result
	) != 0) {
		fprintf (stderr, "Error while looping hintblocks while reading blocks\n");
		return 1;
	}

	return 0;
}
