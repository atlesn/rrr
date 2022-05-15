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
#include "../helpers/nullsafe_str.h"
#include "../allocator.h"
#include "../read_constants.h"

// Test with this parameter after working on the algorithm loops
// #define RRR_ZLIB_NO_REALLOC 1

#define RRR_ZLIB_OK          RRR_READ_OK
#define RRR_ZLIB_INCOMPLETE  RRR_READ_INCOMPLETE
#define RRR_ZLIB_ERR         RRR_READ_HARD_ERROR

static void *__rrr_zlib_allocate (void *arg, unsigned int items, unsigned int size) {
	(void)(arg);
	rrr_biglength size_final = size;
	if (rrr_biglength_mul_err(&size_final, items) != 0) {
		RRR_MSG_0("Maximum allocation size exceeded in %s (attempted to allocate %u * %u bytes)\n", items, size);
		return NULL;
	}
	return rrr_allocate(size_final);
}

static void __rrr_zlib_free (void *arg, void *ptr) {
	(void)(arg);
	rrr_free(ptr);
}

static int __rrr_zlib_stream_init(z_streamp stream) {
	memset(stream, '\0', sizeof(*stream));
	stream->zfree = __rrr_zlib_free;
	stream->zalloc = __rrr_zlib_allocate;
	stream->opaque = NULL;
	return 0;
}

static int __rrr_zlib_loop (
		char **result,
		rrr_biglength *result_length,
		z_streamp stream,
		rrr_length outsize,
		int (*func)(z_streamp strm, int *flush)
) {
	int ret = RRR_ZLIB_OK;

	*result = NULL;
	*result_length = 0;

	char *buf = NULL;
	char *buf_new = NULL;

	rrr_length buf_size = 0;
	rrr_length buf_size_old = 0;

	int flush = Z_NO_FLUSH;

	RRR_ASSERT(sizeof(stream->avail_in) >= sizeof(buf_size),zstream_unsigned_cannot_hold_size_avail_in);
	RRR_ASSERT(sizeof(buf_size) >= sizeof(stream->avail_out),zstream_unsigned_cannot_hold_outsize);

	while (1) {
		buf_size_old = buf_size;

		if (rrr_length_add_err (&buf_size, outsize)) {
			RRR_MSG_0("Buffer size addition overflow in %s (%" PRIrrrl "+%" PRIrrrl ")\n",
				__func__, buf_size, outsize);
			ret = RRR_ZLIB_ERR;
			goto out;
		}

#ifdef RRR_ZLIB_NO_REALLOC
		if ((buf_new = rrr_allocate(buf_size)) == NULL) {
			RRR_MSG_0("Buffer allocation failed in %s (%" PRIrrrl ")\n",
				__func__, buf_size);
			ret = RRR_ZLIB_ERR;
			goto out;
		}
		if (buf != NULL) {
			memcpy(buf_new, buf, buf_size_old);
			rrr_free(buf);
		}
#else
		if ((buf_new = rrr_reallocate(buf, buf_size_old, buf_size)) == NULL) {
			RRR_MSG_0("Buffer (re)allocation failed in %s (%" PRIrrrl ")\n",
				__func__, buf_size);
			ret = RRR_ZLIB_ERR;
			goto out;
		}
#endif

		buf = buf_new;
		stream->next_out = (Bytef *) buf + stream->total_out;
		stream->avail_out += outsize;

		switch (func(stream, &flush)) {
			case RRR_ZLIB_OK:
				goto done;
			case RRR_ZLIB_INCOMPLETE:
				continue;
			default:
				goto out;
		}
	}

	done:
	*result = buf;
	*result_length = rrr_length_from_biglength_bug_const(stream->total_out);
	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

static int __rrr_zlib_decompress (z_streamp stream, int *flush) {
	switch (inflate(stream, *flush)) {
		case Z_OK:
			if (stream->avail_out != 0) {
				RRR_MSG_0("inflate returned Z_OK with non-zero avail_out in %s\n", __func__);
				return RRR_ZLIB_ERR;
			}
			/* Fallthrough */
		case Z_BUF_ERROR:
			/* Try again with bigger buffer */
			return RRR_ZLIB_INCOMPLETE;
		case Z_STREAM_END:
			return RRR_ZLIB_OK;
		default:
			break;
	};
	return RRR_ZLIB_ERR;
}

int rrr_zlib_gzip_decompress_with_outsize (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size,
		rrr_length outsize
) {
	int ret = RRR_ZLIB_OK;

	*result = NULL;
	*result_length = 0;

	z_stream stream;

	RRR_ASSERT(sizeof(stream.avail_out) >= sizeof(size),zstream_unsigned_cannot_hold_size_avail_out);
	RRR_ASSERT(sizeof(*result_length) >= sizeof(stream.total_out),biglength_cannot_hold_total_out);

	if ((ret = __rrr_zlib_stream_init(&stream)) != 0) {
		goto out;
	}

	if (inflateInit2(&stream, 32 /* Enable auto gzip decompress */) != Z_OK) {
		RRR_MSG_0("Failed to initialize stream in %s\n", __func__);
		goto out;
	}

	stream.next_in = (z_const Bytef *) data;
	stream.avail_in = size;

	if ((ret = __rrr_zlib_loop (result, result_length, &stream, outsize, __rrr_zlib_decompress)) != RRR_ZLIB_OK) {
		goto out_stream_end;
	}

	out_stream_end:
		inflateEnd(&stream);
	out:
	return ret ? RRR_ZLIB_ERR : RRR_ZLIB_OK;
}

int rrr_zlib_gzip_decompress (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size
) {
	return rrr_zlib_gzip_decompress_with_outsize (
			result,
			result_length,
			data,
			size,
			512 * 1024 // 512 kB
	);
}

static int __rrr_zlib_gzip_decompress_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_nullsafe_str *output = arg;

	int ret = 0;

	char *buf = NULL;
	rrr_biglength buf_size = 0;
	rrr_length len_checked = 0;

	if ((ret = rrr_length_from_biglength_err(&len_checked, len)) != 0) {
		RRR_MSG_0("Maximum size exceeded in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_zlib_gzip_decompress (&buf, &buf_size, str, len_checked)) != 0) {
		goto out;
	}

	rrr_nullsafe_str_set_allocated(output, (void **) &buf, buf_size);

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

int rrr_zlib_gzip_decompress_nullsafe (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input
) {
	return rrr_nullsafe_str_with_raw_do_const (input, __rrr_zlib_gzip_decompress_nullsafe_callback, output);
}

static int __rrr_zlib_compress (z_streamp stream, int *flush) {
	*flush = Z_FINISH;

	switch (deflate(stream, *flush)) {
		case Z_OK:
		case Z_BUF_ERROR:
			/* Try again with bigger buffer */
			return RRR_ZLIB_INCOMPLETE;
		case Z_STREAM_END:
			return RRR_ZLIB_OK;
		default:
			break;
	};

	return RRR_ZLIB_ERR;
}

int rrr_zlib_gzip_compress_with_outsize (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size,
		rrr_length outsize
) {
	int ret = RRR_ZLIB_OK;

	*result = NULL;
	*result_length = 0;

	z_stream stream;

	RRR_ASSERT(sizeof(stream.avail_out) >= sizeof(size),zstream_unsigned_cannot_hold_size_avail_out);
	RRR_ASSERT(sizeof(*result_length) >= sizeof(stream.total_out),biglength_cannot_hold_total_out);

	if ((ret = __rrr_zlib_stream_init(&stream)) != 0) {
		goto out;
	}

	if (deflateInit2 (
			&stream,
			Z_DEFAULT_COMPRESSION,
			Z_DEFLATED,
			15 + 16, /* Enable gzip compress (16) */
			8,
			Z_DEFAULT_STRATEGY
	) != Z_OK) {
		RRR_MSG_0("Failed to initialize stream in %s\n", __func__);
		goto out;
	}

	stream.next_in = (z_const Bytef *) data;
	stream.avail_in = size;

	if ((ret = __rrr_zlib_loop (result, result_length, &stream, outsize, __rrr_zlib_compress)) != RRR_ZLIB_OK) {
		goto out_stream_end;
	}

	out_stream_end:
		deflateEnd(&stream);
	out:
	return ret ? RRR_ZLIB_ERR : RRR_ZLIB_OK;
}

int rrr_zlib_gzip_compress (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size
) {
	return rrr_zlib_gzip_compress_with_outsize (
			result,
			result_length,
			data,
			size,
			512 * 1024 // 512 kB
	);
}

static int __rrr_zlib_gzip_compress_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct rrr_nullsafe_str *output = arg;

	int ret = 0;

	char *buf = NULL;
	rrr_biglength buf_size = 0;
	rrr_length len_checked = 0;

	if ((ret = rrr_length_from_biglength_err(&len_checked, len)) != 0) {
		RRR_MSG_0("Maximum size exceeded in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_zlib_gzip_compress (&buf, &buf_size, str, len_checked)) != 0) {
		goto out;
	}

	rrr_nullsafe_str_set_allocated(output, (void **) &buf, buf_size);

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

int rrr_zlib_gzip_compress_nullsafe (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input
) {
	return rrr_nullsafe_str_with_raw_do_const (input, __rrr_zlib_gzip_compress_nullsafe_callback, output);
}
