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
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "init.h"
#include "defaults.h"
#include "blocks.h"
#include "crypt.h"
#include "io.h"
#include "../include/bdl.h"

int check_blank_device (struct bdl_io_file *file) {
	int item_count = BDL_NEW_DEVICE_BLANK_START_SIZE / sizeof(int);
	int buf[item_count];
	size_t items = fread (buf, sizeof(buf[0]), item_count, file->file);

	if (items < item_count) {
		if (feof(file->file)) {
			fprintf (stderr, "Device was too small\n");
			goto error_close;
		}
		int error = ferror(file->file);
		fprintf (stderr, "Error while reading from device: %s\n", strerror(error));
		goto error_close;
	}

	for (int i = 0; i < item_count; i++) {
		if (buf[i] != 0) {
			fprintf (stderr,
					"Device needs to be pre-initialized with %i bytes of zeros. Try running 'dd if=/dev/zero of=DEVICE count=%i'\n",
					BDL_NEW_DEVICE_BLANK_START_SIZE, BDL_NEW_DEVICE_BLANK_START_SIZE
			);
			goto error_close;
		}
	}

	success:
	return 0;

	error_close:
	return 1;
}

int init_dev(struct bdl_io_file *session_file, long int blocksize, long int header_pad, char padchar) {
	// These are redudant checks, but keep them for now
	if (header_pad < BDL_MINIMUM_HEADER_PAD) {
		fprintf (stderr, "Bug: init_dev called with too small header pad\n");
		exit (EXIT_FAILURE);
	}
	if (header_pad % BDL_HEADER_PAD_DIVISOR != 0) {
		fprintf (stderr, "Bug: init_dev called with header pad not dividable by divisor\n");
		exit (EXIT_FAILURE);
	}
	if (blocksize > BDL_MAXIMUM_BLOCKSIZE) {
		fprintf(stderr, "Bug: init_dev blocksize was too large, maximum is %i\n", BDL_MAXIMUM_BLOCKSIZE);
		exit (EXIT_FAILURE);
	}
	if (blocksize < BDL_MINIMUM_BLOCKSIZE) {
		fprintf(stderr, "Bug: init_dev blocksize was too small, minimum is %i\n", BDL_MINIMUM_BLOCKSIZE);
		exit (EXIT_FAILURE);
	}
	if (blocksize % BDL_BLOCKSIZE_DIVISOR != 0) {
		fprintf(stderr, "Bug: init_dev blocksize needs to be dividable by %i\n", BDL_BLOCKSIZE_DIVISOR);
		exit (EXIT_FAILURE);
	}

	struct bdl_header header;
	memset (&header, '\0', sizeof(header));

	int pad_size = header_pad - sizeof(header);
	char header_pad_string[pad_size];
	memset (header_pad_string, padchar, pad_size);

	strncpy(header.header_begin_message, BDL_CONFIG_HEADER_START, 32);
	header.blocksystem_version = BDL_BLOCKSYSTEM_VERSION;
	header.block_size = blocksize;
	header.pad_character = padchar;
	header.hash = 0;
	header.default_hash_algorithm = BDL_DEFAULT_HASH_ALGORITHM;
	header.total_size = 0;
	header.header_size = header_pad;

	if (check_blank_device(session_file)) {
		return 1;
	}

	if (session_file->size < (header_pad + blocksize * 2)) {
		fprintf(stderr, "The total size will be too small, minimum size is %ld\n", (header_pad + blocksize * 2));
		return 1;
	}

	header.total_size = (session_file->size - header_pad - ((session_file->size - header_pad) % blocksize));

	uint32_t hash;
	if (crypt_hash_data((const char *) &header, sizeof(header), header.default_hash_algorithm, &hash)) {
		fprintf (stderr, "Hashing of header failed\n");
		return 1;
	}

	header.hash = hash;

	int write_result = io_write_block(session_file, 0, (const char *) &header, sizeof(header), header_pad_string, pad_size, 1);

	if (write_result != 0) {
		fprintf (stderr, "Failed to write header to device\n");
		return 1;
	}

	return 0;
}
