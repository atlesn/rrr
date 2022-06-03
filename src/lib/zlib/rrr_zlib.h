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

#ifndef RRR_ZLIB_H
#define RRR_ZLIB_H

#include "../rrr_types.h"

struct rrr_nullsafe_str;

int rrr_zlib_gzip_decompress_with_outsize (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size,
		rrr_length outsize
);
int rrr_zlib_gzip_decompress (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size
);
int rrr_zlib_gzip_decompress_nullsafe (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input
);
int rrr_zlib_gzip_compress_with_outsize (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size,
		rrr_length outsize
);
int rrr_zlib_gzip_compress (
		char **result,
		rrr_biglength *result_length,
		const char *data,
		rrr_length size
);
int rrr_zlib_gzip_compress_nullsafe (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input
);

#endif /* RRR_ZLIB_H */
