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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include "../include/bdl.h"
#include "blocks.h"
#include "defaults.h"
#include "crypt.h"
#include "io.h"
#include "validate.h"
#include "write.h"

//#define BDL_DEBUG_BLOCKS

int block_hintblock_get_last_block (
		struct bdl_io_file *file,
		const struct bdl_hintblock_state *state,
		const struct bdl_header *master_header,
		struct bdl_block_header *block,
		int *result
) {
	char temp_block_data[master_header->block_size];
	struct bdl_block_header *block_tmp = (struct bdl_block_header *) temp_block_data;

	*result = 1;
	if (io_read_block (file, state->hintblock.previous_block_pos, temp_block_data, master_header->block_size) != 0) {
		fprintf (stderr, "Could not read block at %i\n", (int)state->hintblock.previous_block_pos);
		return 1;
	}

	if (validate_block(temp_block_data, master_header, result) != 0) {
		*result = 1;
		return 0;
	}

	memcpy (block, temp_block_data, sizeof(*block));

	return 0;
}

int block_get_validate_block (
		struct bdl_io_file *file,
		unsigned long int pos,
		const struct bdl_header *master_header,

		char *buf,
		unsigned long int data_length,
		struct bdl_block_header **block_header,
		char **data,

		int *result
) {
	*result = 0;

	if (data_length < master_header->block_size) {
		fprintf (stderr, "block_get_validate_block called with too small read buffer\n");
		exit (EXIT_FAILURE);
	}

	if (io_read_block (file, pos, buf, master_header->block_size) != 0) {
		fprintf (stderr, "Error while reading block area at %lu\n", pos);
		*result = 1;
		return 1;
	}

	*block_header = (struct bdl_block_header *) buf;
	*data = buf + sizeof(struct bdl_block_header);

	if (validate_block (buf, master_header, result) != 0) {
		fprintf (stderr, "Error while checking hash for hint block at %lu\n", pos);
		*result = 1;
		return 1;
	}

	return 0;
}

int block_get_valid_hintblock (
		struct bdl_io_file *file,
		unsigned long int pos,
		const struct bdl_header *master_header,
		struct bdl_hint_block *hintblock,
		int *result
) {
	*result = 0;

	if (io_read_block (file, pos, (char *) hintblock, sizeof(*hintblock)) != 0) {
		fprintf (stderr, "Error while reading hint block area at %lu\n", pos);
		return 1;
	}

	int hash_return;
	if (validate_hintblock (hintblock, pos, master_header, result) != 0) {
		fprintf (stderr, "Error while checking hash for hint block at %lu\n", pos);
		return 1;
	}

	return 0;
}

int block_hintblock_recover_backup (
		struct bdl_io_file *file,
		const struct bdl_header *master_header,
		struct bdl_hintblock_state *state,
		int *result
) {
	if (block_get_valid_hintblock(file, state->backup_location, master_header, &state->hintblock, result) != 0) {
		fprintf (stderr, "Error while reading backup hint block area at %lu\n", state->backup_location);
		return 1;
	}

	if (*result != 0) {
		return 0;
	}

#ifdef BDL_DEBUG_BLOCKS
	printf ("Recovering backup from position %lu to %lu\n", state->backup_location, state->location);
#endif

	if (write_update_hintblock (
			file,
			state->hintblock.previous_block_pos,
			state->hintblock.previous_tagged_block_pos,
			state->location,
			state->location - BDL_HINTBLOCK_BACKUP_POSITION,
			master_header
	) != 0) {
		*result = 1;
		fprintf(stderr, "Error while recovering backup hintblock\n");
		return 1;
	}

	io_sync(file);

	return 0;
}

int block_get_hintblock_state (
		struct bdl_io_file *file,
		unsigned long int pos,
		const struct bdl_header *master_header,
		unsigned long int blockstart_min,
		unsigned long int blockstart_max,
		struct bdl_hintblock_state *state
) {
	state->valid = 0;
	state->backup_location = pos + BDL_HINTBLOCK_BACKUP_POSITION;
	state->blockstart_min = blockstart_min;
	state->blockstart_max = blockstart_max;
	state->highest_timestamp = 0;
	state->location = pos;

	int result;
	if (block_get_valid_hintblock(file, pos, master_header, &state->hintblock, &result) != 0) {
		fprintf (stderr, "Error while reading hint block area at %lu\n", pos);
		return 1;
	}

	if (result != 0) {
		if (block_hintblock_recover_backup(file, master_header, state, &result) != 0) {
			fprintf (stderr, "Error while recovering hintblock backup while getting hintblock state\n");
			return 1;
		}

		if (result == 0) {
			if (block_get_valid_hintblock(file, pos, master_header, &state->hintblock, &result) != 0) {
				fprintf (stderr, "Error while reading hint block area at %lu after recovering from backup\n", pos);
				return 1;
			}
		}
		else {
			return 0;
		}
	}
	else if (state->hintblock.previous_block_pos > blockstart_max || state->hintblock.previous_block_pos < blockstart_min) {
		return 0;
	}


	int block_result;
	struct bdl_block_header block;
	if (block_hintblock_get_last_block (file, state, master_header, &block, &block_result) != 0) {
		fprintf (stderr, "Error while getting last block before hintblock\n");
		return 1;
	}

	if (block_result != 0) {
		return 0;
	}

	state->valid = 1;
	state->highest_timestamp = block.timestamp;

#ifdef BDL_DBG_BLOCKS
		printf ("Highest timestamp of hint block was %" PRIu64 "\n", state->highest_timestamp);
#endif

	return 0;
}

int block_loop_hintblocks_worker (
		struct bdl_io_file *file,
		const struct bdl_header *header,
		unsigned long int loop_begin,
		unsigned long int loop_end,
		unsigned long int loop_spacing,
		struct bdl_block_location *location,
		int (*callback)(struct bdl_hintblock_loop_callback_data *, int *result),
		struct bdl_hintblock_loop_callback_data *callback_data,
		int *result
) {
	if (loop_end > file->size) {
		fprintf (stderr, "Bug: Attempted to loop hintblocks beyond file scope\n");
		exit (EXIT_FAILURE);
	}

	// First block of a region (just after header or previous hint block)
	unsigned long int blockstart_min = loop_begin - loop_spacing + header->block_size;

	for (unsigned long int i = loop_begin; i < loop_end; i += loop_spacing) {
		// Last block of this region (right before hint block)
		unsigned long int blockstart_max = i - header->block_size;

		if (blockstart_min < header->header_size) {
			fprintf (stderr, "Bug: blockstart_min was less than header size int hintblock loop worker\n");
			exit (EXIT_FAILURE);
		}

		if (block_get_hintblock_state (
				file, i, header,
				blockstart_min,
				blockstart_max,
				&location->hintblock_state
				) != 0
		) {
			fprintf (stderr, "Error while reading hint block at %lu while looping\n", i);
			return 1;
		}

		callback_data->hintblock_position = i;
		callback_data->blockstart_min = blockstart_min;
		callback_data->blockstart_max = blockstart_max;

		if (callback(callback_data, result) != 0) {
			fprintf (stderr, "Error in callback function for hint block loop\n");
			return 1;
		}

		if (*result == BDL_BLOCK_LOOP_BREAK) {
			return 0;
		}
		else if (*result == BDL_BLOCK_LOOP_ERR) {
			return 1;
		}

		blockstart_min = i + header->block_size;
	}

	return 0;
}

int block_loop_hintblocks_large_device (
		struct bdl_io_file *file,
		const struct bdl_header *header,
		const struct bdl_block_location *first_location,
		int (*callback)(struct bdl_hintblock_loop_callback_data *, int *result),
		struct bdl_hintblock_loop_callback_data *callback_data,
		struct bdl_block_location *location,
		int *result
) {
	*result = BDL_BLOCK_LOOP_OK;

	memset (location, '\0', sizeof(*location));

	// Search for hint blocks
	callback_data->file = file;
	callback_data->master_header = header;
	callback_data->location = location;
	callback_data->hintblock_position = 0;
	callback_data->blockstart_min = 0;
	callback_data->blockstart_max = 0;

	unsigned long int device_size = file->size;
	unsigned long int header_size = header->header_size;

	unsigned long int loop_begin_orig = header_size + BDL_DEFAULT_HINTBLOCK_SPACING;
	unsigned long int loop_begin = loop_begin_orig;
	unsigned long int loop_spacing = BDL_DEFAULT_HINTBLOCK_SPACING;
	unsigned long int loop_end = device_size;

	// Override where we begin to search?
	if (first_location != NULL) {
		if (first_location->hintblock_state.valid != 1) {
			fprintf (stderr, "Bug: Called block_loop_hintblocks_large_device with invalid first block set\n");
			exit (EXIT_FAILURE);
		}
		loop_begin = first_location->hintblock_state.location;
	}

	if (block_loop_hintblocks_worker (
			file, header,
			loop_begin, loop_end, loop_spacing,
			location,
			callback, callback_data,
			result
	) != 0) {
		fprintf (stderr, "Error while looping hint blocks 1st round\n");
		return 1;
	}

	// Check if we skipped the beginning initially and need to loop again
	if (loop_begin != loop_begin_orig && *result != BDL_BLOCK_LOOP_BREAK) {
		loop_end = loop_begin;
		loop_begin = loop_begin_orig;

		if (block_loop_hintblocks_worker (
				file, header,
				loop_begin, loop_end, loop_spacing,
				location,
				callback, callback_data,
				result
		) != 0) {
			fprintf (stderr, "Error while looping hint blocks 2nd round\n");
			return 1;
		}
	}

	// TODO: Code for hint block at the very end

	return 0;
}

int block_loop_blocks (
	struct bdl_io_file *file,
	const struct bdl_header *header,
	const struct bdl_hintblock_state *hintblock_state,
	int (*callback)(struct bdl_block_loop_callback_data *, int *result),

	char *block_data_buf,
	unsigned long int block_data_length,
	struct bdl_block_header **block_header,
	char **block_data,

	struct bdl_block_loop_callback_data *callback_data,
	int *result
) {
	*result = BDL_BLOCK_LOOP_OK;

	if (block_data_length < header->block_size) {
		fprintf (stderr, "Bug: Too little data allocated for block in block loop\n");
		exit (EXIT_FAILURE);
	}

	callback_data->file = file;
	callback_data->master_header = header;
	callback_data->hintblock_state = hintblock_state;
	callback_data->block_position = 0;
	callback_data->block = NULL;
	callback_data->block_data = NULL;

	for (unsigned long int i = hintblock_state->blockstart_min;
			i <= hintblock_state->blockstart_max &&
			i <= hintblock_state->hintblock.previous_block_pos;
			i += header->block_size
	) {
		if (i == hintblock_state->backup_location) {
			continue;
		}

		if (block_get_validate_block (
				file, i, header,
				block_data_buf, block_data_length,
				block_header, block_data,
				result
		) != 0) {
			fprintf (stderr, "Error while getting and validating block at %lu\n", i);
			return 1;
		}

		if (*result == 1) {
			*result = BDL_BLOCK_LOOP_BREAK;
			return 0;
		}

		callback_data->block_position = i;
		callback_data->block = *block_header;
		callback_data->block_data = *block_data;

		if (callback (callback_data, result) != 0) {
			fprintf (stderr, "Error in callback function while looping blocks, at pos %lu\n", i);
			return 1;
		}

		if (*result == BDL_BLOCK_LOOP_BREAK) {
			break;
		}
		else if (*result == BDL_BLOCK_LOOP_ERR) {
			return 1;
		}
	}

	return 0;
}

int block_get_validate_master_header(struct bdl_io_file *file, struct bdl_header *header, int *result) {
	if (io_read_block(file, 0, (char *) header, sizeof(*header)) != 0) {
		fprintf (stderr, "Error while reading header from file\n");
		return 1;
	}

	if (validate_header(header, file->size, result) != 0) {
		fprintf (stderr, "Error while validating header\n");
		return 1;
	}

	return 0;
}

void block_dump (const struct bdl_block_header *header, unsigned long int position, const char *data) {
	char buf[1024 + header->data_length];

	int bytes = snprintf (buf, 1024,
			"BLOCK:%lu:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu32 ":%" PRIu32 ":",
			position,
			header->timestamp,
			header->application_data,
			header->data_length,
			header->pad,
			header->hash
	);
	if (bytes >= 1024 - 1) {
		fprintf (stderr, "Bug: Block dump buffer got full\n");
		exit (EXIT_FAILURE);
	}

	memcpy(buf + bytes, data, header->data_length);

	/* TODO this writing stuff is probably slow (if it matters) */
	if (fflush(stdout) != 0) {
		fprintf (stderr, "Error while flushing stdout buffer: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	buf[bytes + header->data_length] = '\n';
	bytes++;

	int res = write (fileno(stdout), buf, bytes + header->data_length);

	if (res == -1) {
		fprintf (stderr, "Error while write block data to stdout: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (res != bytes + header->data_length) {
		fprintf (stderr, "Did not write all block data bytes for some reason\n");
		exit(EXIT_FAILURE);
	}
}

struct block_find_smallest_hintblock_loop_data {
	uint64_t timestamp_gteq;
	uint64_t smallest_timestamp;
	struct bdl_hintblock_state smallest_state;
};

int block_find_oldest_hintblock_loop_callback (
	struct bdl_hintblock_loop_callback_data *data,
	int *result
) {
	struct block_find_smallest_hintblock_loop_data *loop_data = (struct block_find_smallest_hintblock_loop_data *) data->argument_ptr;
	const struct bdl_hintblock_state *state = &data->location->hintblock_state;

	if (state->valid != 1) {
		*result = BDL_BLOCK_LOOP_BREAK;
		return 0;
	}

	if (state->highest_timestamp < loop_data->timestamp_gteq) {
		*result = BDL_BLOCK_LOOP_OK;
		return 0;
	}

	if (state->highest_timestamp < loop_data->smallest_timestamp) {
		loop_data->smallest_timestamp = state->highest_timestamp;
		loop_data->smallest_state = *state;
	}

	return 0;
}

int block_find_oldest_hintblock (
	struct bdl_io_file *device,
	const struct bdl_header *master_header,
	uint64_t timestamp_gteq,
	struct bdl_block_location *location,
	int *result
) {
	struct block_find_smallest_hintblock_loop_data loop_data;

	loop_data.timestamp_gteq = timestamp_gteq;
	memset (&loop_data.smallest_state, '\0', sizeof(loop_data.smallest_state));
	loop_data.smallest_timestamp = 0xffffffffffffffff;

	struct bdl_hintblock_loop_callback_data callback_data;
	callback_data.argument_int = 0;
	callback_data.argument_ptr = (void*) &loop_data;

	if (block_loop_hintblocks_large_device (
			device, master_header, NULL,
			block_find_oldest_hintblock_loop_callback, &callback_data,
			location,
			result
	) != 0) {
		fprintf (stderr, "Error while looping hintblocks while reading blocks\n");
		return 1;
	}

	location->hintblock_state = loop_data.smallest_state;

	return 0;
}
