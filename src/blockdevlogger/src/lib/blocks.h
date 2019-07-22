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

#ifndef BDL_BLOCKS_H
#define BDL_BLOCKS_H

#include <stdint.h>

#include "io.h"

#define BDL_BLOCK_LOOP_OK		0
#define BDL_BLOCK_LOOP_ERR		1
#define BDL_BLOCK_LOOP_BREAK	2

struct bdl_io_file;

struct bdl_header {
	uint8_t header_begin_message[32];

	/* Version number to detect incompatibilities */
	int16_t blocksystem_version;

	/* Usually 0xff or 0x00 */
	uint8_t pad_character;

	/* For future use, currently 0=CRC32 */
	uint8_t default_hash_algorithm;

	/* Size of a block in bytes */
	uint64_t block_size;

	/* Total size to write after the header before we wrap */
	uint64_t total_size;

	/* Size of header including padding */
	uint32_t header_size;

	/* Hash of all parameters with hash being zero */
	uint32_t hash;
};

struct bdl_block_header {
	uint64_t timestamp;

	/* Usable for applications */
	uint64_t application_data;

	/* Length of actual data, the rest up to the block size defined in the header is padded */
	uint64_t data_length;

	/* Future use? */
	uint32_t pad;

	/* Hash of header and data with hash itself being zero */
	uint32_t hash;
};

struct bdl_hint_block {
	uint64_t previous_block_pos;

	/* The application may tag blocks for instance marking which have been processed */
	uint64_t previous_tagged_block_pos;

	/* Future use? */
	uint32_t pad;

	/* Hash of header and data with hash itself being zero. Do not place hash at same location in struct as block header. */
	uint32_t hash;
};

struct bdl_header_pad {
	uint8_t pad;
};

struct bdl_hintblock_state {
	int valid;
	unsigned long int blockstart_min;
	unsigned long int blockstart_max;
	unsigned long int location;
	unsigned long int backup_location;
	uint64_t highest_timestamp;
	struct bdl_hint_block hintblock;
};

struct bdl_block_location {
	unsigned long int block_location;
	struct bdl_hintblock_state hintblock_state;
};

struct bdl_hintblock_loop_callback_data {
	// May be initialized before looping, not used by the loop
	int argument_int;
	void *argument_ptr;

	// Initialized by the loop itself
	struct bdl_io_file *file;
	const struct bdl_header *master_header;
	struct bdl_block_location *location;
	unsigned long int hintblock_position;
	unsigned long int blockstart_min;
	unsigned long int blockstart_max;
};

struct bdl_block_loop_callback_data {
	// May be initialized before looping, not used by the loop
	int argument_int;
	void *argument_ptr;

	// Initialized by the loop itself
	struct bdl_io_file *file;
	const struct bdl_header *master_header;
	const struct bdl_hintblock_state *hintblock_state;

	unsigned long int block_position;
	const struct bdl_block_header *block;
	const char *block_data;
};

int block_get_valid_hintblock (
	struct bdl_io_file *file,
	unsigned long int pos,
	const struct bdl_header *master_header,
	struct bdl_hint_block *hintblock,
	int *result
);
int block_loop_hintblocks_large_device (
	struct bdl_io_file *file,
	const struct bdl_header *header,
	const struct bdl_block_location *first_location,
	int (*callback)(struct bdl_hintblock_loop_callback_data *, int *result),
	struct bdl_hintblock_loop_callback_data *callback_data,
	struct bdl_block_location *location,
	int *result
);
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
);
int block_find_oldest_hintblock (
	struct bdl_io_file *device,
	const struct bdl_header *master_header,
	uint64_t timestamp_gteq,
	struct bdl_block_location *location,
	int *result
);

int block_get_validate_master_header(struct bdl_io_file *file, struct bdl_header *header, int *result);
void block_dump (const struct bdl_block_header *header, unsigned long int position, const char *data);

#endif
