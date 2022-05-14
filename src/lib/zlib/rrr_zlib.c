/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#include <zlib.h>

#include "rrr_zlib.h"
#include "../util/macro_utils.h"
#include "../allocator.h"

static void *__rrr_zlib_allocate (void *arg, unsigned int items, unsigned int size) {
	(void)(arg);
	rrr_biglength size_final = size;
	if (rrr_biglength_mul_err(&size_final, items) != 0) {
		RRR_MSG_0("Maximum allocation size exceeded in %s (attempted to allocate %u * %u bytes)\n", items, size);
		return NULL;
	}
	return rrr_allocate(size_final);
}

static void __rrr_zlib_free (void *ptr, void *arg) {
	(void)(arg);
	rrr_free(ptr);
}

static void __rrr_zlib_stream_init(z_streamp stream) {
	memset(stream, '\0', sizeof(*stream));
	stream->zfree = __rrr_zlib_free;
	stream->zalloc = __rrr_zlib_allocate;
	stream->opaque = NULL;
}

int rrr_zlib_gzip_decompress_with_outsize (char **result, char *data, rrr_length size, rrr_length outsize) {
	int ret = 0;

	*result = NULL;

	rrr_length buf_size = 0;
	char *buf = NULL;

	z_stream stream;
	__rrr_zlib_stream_init(&stream);

	RRR_ASSERT(sizeof(stream.avail_in) >= sizeof(size),zstream_unsigned_cannot_hold_size);
	RRR_ASSERT(sizeof(buf_size) >= sizeof(stream.avail_out),zstream_unsigned_cannot_hold_outsize);

	if (inflateInit(&stream) != Z_OK) {
		RRR_MSG_0("Failed to initialize stream in %s\n", __func__);
		ret = 1;
		goto out;
	}

	stream.next_in = (Bytef *) data;
	stream.avail_in = size;

	while (ret == 0) {
		if (rrr_length_add_err (&rrr_length *a, rrr_length b) {
		buf_size += outsize;
		if ((ret = inflate(&stream, 0)) != Z_OK) {
			if (ret == Z_BUF_ERROR) {
				// Try again with bigger buffer
				continue;
			}
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

int rrr_zlib_gzip_decompress (char **result, char *data, rrr_length size) {
	return rrr_zlib_gzip_decompress_with_outsize(result, data, size, 512 * 1024); // 512 kB
}
