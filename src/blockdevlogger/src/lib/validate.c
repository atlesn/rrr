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

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "validate.h"
#include "defaults.h"
#include "io.h"
#include "blocks.h"
#include "crypt.h"
#include "../include/bdl.h"

int validate_block(const char *all_data, const struct bdl_header *master_header, int *result) {
	const struct bdl_block_header *header = (struct bdl_block_header *) all_data;

	unsigned long int total_size = sizeof(*header) + header->data_length;

	if (total_size > master_header->block_size) {
		*result = 1;
		return 0;
	}

	uint32_t hash_orig = header->hash;

	char buf[total_size];
	memcpy (buf, all_data, total_size);
	struct bdl_block_header *header_copy = (struct bdl_block_header *) buf;
	header_copy->hash = 0;

	if (crypt_check_hash(
			buf,
			total_size,
			master_header->default_hash_algorithm,
			hash_orig,
			result) != 0
	) {
		fprintf (stderr, "Error while checking hash for block\n");
		return 1;
	}

	return 0;
}

int validate_hintblock (
		const struct bdl_hint_block *header_orig,
		unsigned long int position,
		const struct bdl_header *master_header,
		int *result
) {
	struct bdl_hint_block header = *header_orig;

	header.hash = 0;

	if (crypt_check_hash(
			(const char *) &header,
			sizeof(header),
			master_header->default_hash_algorithm,
			header_orig->hash,
			result) != 0
	) {
		fprintf (stderr, "Error while validating hash for hint block\n");
		return 1;
	}

	if (header_orig->pad != 0) {
		*result = 1;
		return 0;
	}

	return 0;
}


int validate_header (const struct bdl_header *header, int file_size, int *result) {
	struct bdl_header header_copy = *header;
	header_copy.hash = 0; // Needs to be zero for hash to be valid

	*result = 1;

	if (crypt_check_hash(
			(const char *) &header_copy,
			sizeof(header_copy),
			header->default_hash_algorithm,
			header->hash,
			result) != 0
	) {
		fprintf (stderr, "Error while validating hash for hint block\n");
		return 1;
	}

	if (*result != 0) {
		/* Stop further checks if checksum is not valid */
		fprintf (stderr, "Header checksum of device was not valid, possible data corruption. Please re-initialize device.\n");
		*result = 1;
		return 0;
	}

	if (header->total_size < header->block_size * 2) {
		fprintf (stderr, "The total size specified in the header was too small. Please re-initialize device.\n");
		*result = 1;
	}

	if (header->total_size > file_size) {
		fprintf (stderr, "The file size specified in the header is larger than the file size. Please re-initialize device.\n");
		*result = 1;
	}

	if (header->total_size % header->block_size != 0) {
		fprintf (stderr, "The header total size was not dividable by block size. Please re-initialize device.\n");
		*result = 1;
	}

	if (header->blocksystem_version != BDL_BLOCKSYSTEM_VERSION) {
		fprintf (stderr, "Incompatible blocksystem version. Header has version is V %u, and we require V %u\n",
				header->blocksystem_version,
				BDL_BLOCKSYSTEM_VERSION
		);
		*result = 1;
	}
	else if (header->block_size < BDL_MINIMUM_BLOCKSIZE) {
		fprintf (stderr, "The block size defined in the header was %" PRIu64 " but minimum size is %d\n", header->block_size, BDL_MINIMUM_BLOCKSIZE);
		*result = 1;
	}
	else if (header->block_size > BDL_MAXIMUM_BLOCKSIZE) {
		fprintf (stderr, "The block size defined in the header was %" PRIu64 " but maximum size is %d\n", header->block_size, BDL_MAXIMUM_BLOCKSIZE);
		*result = 1;
	}
	else if (header->block_size % BDL_BLOCKSIZE_DIVISOR) {
		fprintf (stderr, "The block size defined in the header (%" PRIu64 ") was not dividable with %d\n", header->block_size, BDL_BLOCKSIZE_DIVISOR);
		*result = 1;
	}

	return 0;
}

int validate_dev (struct bdl_io_file *session_file, int *result) {
	struct bdl_header header;

	if (block_get_validate_master_header(session_file, &header, result) != 0) {
		fprintf (stderr, "Could not get header from device while writing new data block\n");
		return 1;
	}

	return 0;
}
