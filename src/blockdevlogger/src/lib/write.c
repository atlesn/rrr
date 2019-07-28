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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>

#include "write.h"
#include "blocks.h"
#include "defaults.h"
#include "io.h"
#include "crypt.h"
#include "validate.h"
#include "bdltime.h"
#include "../include/bdl.h"

//#define BDL_DBG_WRITE

int write_find_location_small(struct bdl_io_file *file, const struct bdl_header *header, struct bdl_block_location *location) {
	location->block_location = 0;

	// TODO : Implement

	fprintf (stderr, "Error: Small devices are not yet supported\n");
	exit (EXIT_FAILURE);
}

int write_check_free_hintblock (
		const struct bdl_header *master_header,
		struct bdl_block_location *location,
		int *result
) {
	*result = 1;

	struct bdl_hintblock_state *state = &location->hintblock_state;

	// We write here if we find an invalid/unused hint block
	if (state->valid == 0) {

#ifdef BDL_DBG_WRITE
		printf ("Hint block was unused\n");
#endif

		location->block_location = state->blockstart_min;

		*result = 0;
	}
	else {
		if (state->hintblock.previous_block_pos + master_header->block_size <= state->blockstart_max) {

#ifdef BDL_DBG_WRITE
			printf ("Hint block has free room\n");
#endif

			location->block_location = state->hintblock.previous_block_pos + master_header->block_size;

			if (location->block_location == state->backup_location) {
				location->block_location += master_header->block_size;
			}

			*result = 0;
		}
		else {

#ifdef BDL_DBG_WRITE
			printf ("Hint block is full\n");
#endif

			location->block_location = state->blockstart_min;

			*result = 1;
		}
	}

	return 0;
}

struct hintblock_timestamp {
	struct bdl_hintblock_state state;
	int initialized;
	uint64_t min_timestamp;
};

int write_hintblock_check_timestamps (struct bdl_hintblock_loop_callback_data *data, int *result) {
	struct hintblock_timestamp *timestamp = (struct hintblock_timestamp *) data->argument_ptr;
	const struct bdl_hintblock_state *state = &data->location->hintblock_state;

	if (state->highest_timestamp < timestamp->min_timestamp) {
		timestamp->min_timestamp = state->highest_timestamp;
		timestamp->state = *state;
		timestamp->initialized = 1;
	}

	*result = BDL_BLOCK_LOOP_OK;

	return 0;
}

int write_hintblock_check_free_callback (struct bdl_hintblock_loop_callback_data *data, int *result) {
	*result = BDL_BLOCK_LOOP_ERR;

	if (write_check_free_hintblock (
			data->master_header,
			data->location,
			result
			) != 0
	) {
		fprintf (stderr, "Error while checking for free hintblock\n");
		return 1;
	}

	if (*result == 0) {
		// Hint block has free room
		*result = BDL_BLOCK_LOOP_BREAK;
		data->argument_int = 0;
	}
	else if (*result == 1) {
		// Hint block is full
		*result = BDL_BLOCK_LOOP_OK;
		data->argument_int = 1;
	}

	return 0;
}

int write_find_location(struct bdl_io_file *file, const struct bdl_header *header, struct bdl_block_location *location) {
	if (file->size < BDL_SMALL_SIZE_THRESHOLD) {
#ifdef BDL_DBG_WRITE
		printf ("Finding new write location for small device\n");
#endif
		return write_find_location_small(file, header, location);
	}

	// Search for hint blocks
	struct bdl_hintblock_loop_callback_data callback_data;
	memset (&callback_data, '\0', sizeof(callback_data));

	// Attempt to find a hint block with free room
	int result;
	if (block_loop_hintblocks_large_device (
			file, header,
			NULL,
			write_hintblock_check_free_callback, &callback_data,
			location,
			&result
	) != 0) {
		fprintf (stderr, "Error while looping hint blocks in write operation\n");
		return 1;
	}

	if (callback_data.argument_int == 0) {
		// Hint block with free room found
		return 0;
	}

	// Find hint block with lowest time stamp and invalidate
	struct hintblock_timestamp timestamp;
	timestamp.initialized = 0;
	timestamp.min_timestamp = 0xffffffffffffffff;

	memset (&callback_data, '\0', sizeof(callback_data));
	callback_data.argument_ptr = &timestamp;

	if (block_loop_hintblocks_large_device (
			file, header,
			NULL,
			write_hintblock_check_timestamps, &callback_data,
			location,
			&result
	) != 0) {
		fprintf (stderr, "Error while looping hint blocks in write operation to find timestamps\n");
		return 1;
	}

	if (timestamp.initialized == 1) {
		location->block_location = timestamp.state.blockstart_min;
		location->hintblock_state = timestamp.state;
		return 0;
	}

	fprintf (stderr, "Bug: Reached end of write_find_location()\n");
	exit(EXIT_FAILURE);
}

int write_put_and_pad_block (struct bdl_io_file *file, int pos, const char *data, int data_length, char pad, int total_size) {
	int padding_length = total_size - data_length;

	char padding[padding_length];
	memset (padding, pad, padding_length);

	if (io_write_block(file, pos, data, data_length, padding, padding_length, 1) != 0) {
		fprintf (stderr, "Error while writing data and padding to location %i\n", pos);
		return 1;
	}

	return 0;
}

int write_update_hintblock (
		struct bdl_io_file *file,
		unsigned long int block_position,
		uint64_t previous_tagged_block_pos,
		unsigned long int hintblock_position,
		unsigned long int hintblock_backup_position,
		const struct bdl_header *header

) {
	// Work on hint block
	struct bdl_hint_block hint_block;
	int result;

	// Preserve information from exisiting hint block
	if (block_get_valid_hintblock(file, hintblock_position, header, &hint_block, &result)) {
		fprintf (stderr, "Error while getting hint block at %lu\n", hintblock_position);
		return 1;
	}

	if (result != 0) {
		memset (&hint_block, '\0', sizeof(hint_block));
	}

	hint_block.previous_block_pos = block_position;
	hint_block.hash = 0;

	if (previous_tagged_block_pos != 0) {
		hint_block.previous_tagged_block_pos = previous_tagged_block_pos;
	}

	if (crypt_hash_data(
			(const char *) &hint_block,
			sizeof(hint_block),
			header->default_hash_algorithm,
			&hint_block.hash) != 0
	) {
		fprintf (stderr, "Error while hashing hint block\n");
		return 1;
	}

	if (write_put_and_pad_block(
			file,
			hintblock_position,
			(const char *) &hint_block, sizeof(hint_block),
			header->pad_character,
			header->block_size) != 0
	) {
		fprintf (stderr, "Error while putting hint block\n");
		return 1;
	}

	// Write a backup?
	if (hintblock_backup_position != hintblock_position) {
		if (write_update_hintblock(
				file,
				block_position, previous_tagged_block_pos,
				hintblock_backup_position, hintblock_backup_position,
				header
		) != 0) {
			fprintf (stderr, "Error while writing backup hint block\n");
			return 1;
		}
	}

	return 0;
}

int write_checksum_and_put_block(
	const struct bdl_block_header* block_header,
	unsigned long int data_length, const char* data,
	const struct bdl_header* header,
	unsigned int block_position,
	struct bdl_io_file* session_file
) {
	// Checksum and write the block
	unsigned long int block_total_size = sizeof(*block_header) + data_length;
	char hash_data[block_total_size];
	memcpy(hash_data, block_header, sizeof(*block_header));
	memcpy(hash_data + sizeof(*block_header), data, data_length);

	struct bdl_block_header *new_header = (struct bdl_block_header *) hash_data;
	new_header->hash = 0;

	if (crypt_hash_data(
			hash_data,
			block_total_size,
			header->default_hash_algorithm,
			&new_header->hash
	) != 0) {
		fprintf(stderr, "Error while hashing block\n");
		return 1;
	}

	if (write_put_and_pad_block(
			session_file,
			block_position,
			hash_data,
			block_total_size,
			header->pad_character,
			header->block_size
	) != 0) {
		fprintf(stderr, "Error while putting block\n");
		return 1;
	}

	return 0;
}

int write_put_block (
		struct bdl_io_file *session_file,
		const char *data, unsigned long int data_length,
		uint64_t appdata,
		uint64_t timestamp,
		unsigned long int faketimestamp
) {
	struct bdl_header header;
	int result;

	// Read master header
	if (block_get_validate_master_header(session_file, &header, &result) != 0) {
		fprintf (stderr, "Could not get header from device while writing new data block\n");
		return BDL_WRITE_ERR_IO;
	}

	if (result != 0) {
		fprintf (stderr, "Invalid header of device while writing new data block\n");
		return BDL_WRITE_ERR_CORRUPT;
	}

	// Find write location
	struct bdl_block_location location;
	if (write_find_location (session_file, &header, &location) != 0) {
		fprintf (stderr, "Error while finding write location for device\n");
		return 1;
	}

	// Work on data block
	struct bdl_block_header block_header;
	memset (&block_header, '\0', sizeof(block_header));
	block_header.data_length = data_length;
	block_header.timestamp = (timestamp == 0 ? time_get_64() : timestamp);
	block_header.application_data = appdata;

#ifdef BDL_DBG_WRITE
	printf ("Writing new block at location %lu with hintblock at %lu timestamp %" PRIu64 "\n",
			location.block_location, location.hintblock_state.location, block_header.timestamp
	);
#endif

	// Check timestamp
	if (location.hintblock_state.highest_timestamp >= block_header.timestamp) {
		if (faketimestamp == 0) {
			fprintf (stderr, "Cannot insert element with earlier or equal timestamp than the latest block already in place. Check your clock or consider using faketimestamp.\n");
			return 1;
		}
		else if (location.hintblock_state.highest_timestamp - block_header.timestamp > faketimestamp) {
			fprintf (stderr, "Faketimestamp limit exceeded, check your clock or consider increasing it.\n");
			return BDL_WRITE_ERR_TIMESTAMP;
		}
		block_header.timestamp = location.hintblock_state.highest_timestamp + 1;
#ifdef BDL_DBG_WRITE
		printf ("Timestamp corrected to %" PRIu64 "\n",
				block_header.timestamp
		);
#endif
	}

	// Check data length
	if (data_length > header.block_size - sizeof(block_header)) {
		fprintf(stderr, "Length of data was to large to fit inside a block, length was %lu while maximum size is %" PRIu64 "\n",
			data_length, (header.block_size - sizeof(block_header))
		);
		return BDL_WRITE_ERR_SIZE;
	}

	// Check for funny write locations
	if (location.block_location < header.header_size) {
		fprintf (stderr, "Bug: Block location was inside header on write\n");
		exit (EXIT_FAILURE);
	}

	if (location.hintblock_state.location < header.header_size + header.block_size) {
		fprintf (stderr, "Bug: Hint block location was too early on write\n");
		exit (EXIT_FAILURE);
	}

	if (location.block_location == location.hintblock_state.backup_location) {
		fprintf (stderr, "Bug: Attempted to place block on hintblock backup location\n");
		exit (EXIT_FAILURE);
	}

	// Checksum and write the block
	if (write_checksum_and_put_block(
			&block_header,
			data_length, data,
			&header, location.block_location,
			session_file
	) != 0) {
		return 1;
	}

	// Update hintblock
	if (write_update_hintblock(
			session_file,
			location.block_location, 0,
			location.hintblock_state.location, location.hintblock_state.backup_location,
			&header
	) != 0) {
		fprintf (stderr, "Error while updating hintblock while writing new block\n");
		return 1;
	}

	return 0;
}

