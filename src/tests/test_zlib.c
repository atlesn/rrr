/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <errno.h>

#include "test.h"
#include "../lib/allocator.h"
#include "../lib/rrr_strerror.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/zlib/rrr_zlib.h"

static const char *data_uncompressed_file = "./test_zlib_data";
static const char *data_compressed_file = "./test_zlib_data.gz";

int rrr_test_zlib (void) {
	int ret = 0;

	char *data_uncompressed = NULL;
	char *data_compressed = NULL;
	char *data_test_uncompressed = NULL;
	char *data_test_compressed = NULL;

	rrr_biglength data_uncompressed_size;
	rrr_biglength data_compressed_size;
	rrr_biglength data_test_uncompressed_size;
	rrr_biglength data_test_compressed_size;

	TEST_MSG("Loading input files...\n");

	if ((ret = rrr_socket_open_and_read_file (
			&data_uncompressed,
			&data_uncompressed_size,
			data_uncompressed_file,
			0,
			0
	)) != 0) {
		TEST_MSG("Failed to load file %s: %s\n", data_uncompressed_file, rrr_strerror(errno));
		goto out;
	}

	if ((ret = rrr_socket_open_and_read_file (
			&data_compressed,
			&data_compressed_size,
			data_compressed_file,
			0,
			0
	)) != 0) {
		TEST_MSG("Failed to load file %s: %s\n", data_compressed_file, rrr_strerror(errno));
		goto out;
	}

	/////////////////////
	// A DECOMPRESS
	/////////////////////

	TEST_MSG("A Decompressing...\n");

	if ((ret = rrr_zlib_gzip_decompress_with_outsize (
			&data_test_uncompressed,
			&data_test_uncompressed_size,
			data_compressed,
			rrr_length_from_biglength_bug_const(data_compressed_size),
			8 // Do small increments in out buffer size to enforce multiple loops during decompression
	)) != 0) {
		TEST_MSG("A Failed with status %i\n", ret);
		goto out;
	}

	TEST_MSG("%.*s\n", rrr_length_from_biglength_bug_const(data_test_uncompressed_size), data_test_uncompressed);

	if (data_uncompressed_size != data_test_uncompressed_size || memcmp(data_uncompressed, data_test_uncompressed, data_test_uncompressed_size) != 0) {
		RRR_MSG_0("A Test data mismatch in %s\n", __func__);
		ret = 1;
		goto out;
	}

	/////////////////////
	// B COMPRESS
	/////////////////////

	TEST_MSG("B Compressing...\n");

	if ((ret = rrr_zlib_gzip_compress_with_outsize (
			&data_test_compressed,
			&data_test_compressed_size,
			data_uncompressed,
			rrr_length_from_biglength_bug_const(data_uncompressed_size),
			8 // Do small increments in out buffer size to enforce multiple loops during compression
	)) != 0) {
		TEST_MSG("B Failed with status %i\n", ret);
		goto out;
	}

	/////////////////////
	// C DECOMPRESS
	/////////////////////

	TEST_MSG("C Decompressing...\n");

	RRR_FREE_IF_NOT_NULL(data_test_uncompressed);

	if ((ret = rrr_zlib_gzip_decompress_with_outsize (
			&data_test_uncompressed,
			&data_test_uncompressed_size,
			data_test_compressed,
			rrr_length_from_biglength_bug_const(data_test_compressed_size),
			8 // Do small increments in out buffer size to enforce multiple loops during decompression
	)) != 0) {
		TEST_MSG("C Failed with status %i\n", ret);
		goto out;
	}

	TEST_MSG("%.*s\n", rrr_length_from_biglength_bug_const(data_test_uncompressed_size), data_test_uncompressed);

	if (data_uncompressed_size != data_test_uncompressed_size || memcmp(data_uncompressed, data_test_uncompressed, data_test_uncompressed_size) != 0) {
		RRR_MSG_0("C Test data mismatch in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(data_uncompressed);
	RRR_FREE_IF_NOT_NULL(data_compressed);
	RRR_FREE_IF_NOT_NULL(data_test_uncompressed);
	RRR_FREE_IF_NOT_NULL(data_test_compressed);
	return ret;
}
