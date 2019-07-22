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

#ifndef BDL_WRITE_H
#define BDL_WRITE_H

#include <stdint.h>

#include "io.h"
#include "blocks.h"
#include "../include/bdl.h"

int write_put_block (
		struct bdl_io_file *session_file,
		const char *data, unsigned long int data_length,
		uint64_t appdata,
		uint64_t timestamp,
		unsigned long int faketimestamp
);

int write_update_hintblock (
		struct bdl_io_file *file,
		unsigned long int block_position,
		uint64_t previous_tagged_block_pos,
		unsigned long int hintblock_position,
		unsigned long int hintblock_backup_position,
		const struct bdl_header *header
);

int write_put_and_pad_block (
		struct bdl_io_file *file,
		int pos,
		const char *data, int data_length,
		char pad, int total_size
);

int write_checksum_and_put_block(
	const struct bdl_block_header* block_header,
	unsigned long int data_length, const char* data,
	const struct bdl_header* header,
	unsigned int block_position,
	struct bdl_io_file* session_file
);

#endif
