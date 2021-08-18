/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <stdio.h>

#include "../log.h"
#include "../allocator.h"
#include "hex.h"
#include "../rrr_types.h"

int rrr_hex_bin_to_hex (
		char **target,
		rrr_biglength *target_length,
		const void *source,
		rrr_length source_size
) {
	int ret = 0;

	*target = NULL;
	*target_length = 0;

	const rrr_biglength output_size = source_size * 2 + 1;

	// Valgrind complains about invalid writes for some reason, allocate at least 32 bytes
	char *result = rrr_allocate(output_size < 32 ? 32 : output_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_hex_bin_to_\n");
		return 1;
	}

	char *wpos = result;
	for (rrr_length i = 0; i < source_size; i++) {
		// Must pass in unsigned to sprintf or else extra FFFF might
		// be printed if value char is negative
		snprintf(wpos, 3, "%02x", *((const unsigned char *) source + i));
		wpos += 2;
	}
	result[output_size - 1] = '\0';

	*target = result;
	*target_length = output_size - 1;

	return ret;
}
