/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"
#include "readfile.h"
#include "../rrr_types.h"
#include "../rrr_strerror.h"

/*
 * Function for reading files without the rrr_socket framework. If a
 * file is to be read in normal circumstances after the program has started,
 * the read file function in rrr_socket framework should be used instead.
 */
int rrr_readfile_read (
		char **target,
		rrr_biglength *target_size,
		const char *filename,
		size_t max_size,
		int enoent_ok
) {
	*target_size = 0;
	*target = NULL;

	int ret = 0;

	char *file_data = NULL;

	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		if (errno == ENOENT && enoent_ok) {
			goto out;
		}

		RRR_MSG_0("Could not open file %s: %s\n", filename, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (fseek(file, 0L, SEEK_END) != 0) {
		RRR_MSG_0("Could not fseek to the end in file %s: %s\n", filename, rrr_strerror(errno));
		ret = 1;
		goto out_close;
	}

	rrr_slength size_signed = ftell(file);
	if (size_signed < 0) {
		RRR_MSG_0("Could not get size of file %s: %s\n", filename, rrr_strerror(errno));
		ret = 1;
		goto out_close;
	}

	rrr_biglength size = size_signed;
	if (max_size != 0 && size > max_size) {
		RRR_MSG_0("File %s was too big (%" PRIrrrsl " > %" PRIrrrbl ")\n", filename, size, max_size);
		ret = 1;
		goto out_close;
	}

	if (fseek(file, 0L, 0) != 0) {
		RRR_MSG_0("Could not fseek to the beginning in file %s: %s\n", filename, rrr_strerror(errno));
		ret = 1;
		goto out_close;
	}

	file_data = malloc(size);
	if (file_data == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_readfile_read\n");
		ret = 1;
		goto out_close;
	}

	size_t bytes = fread(file_data, 1, size, file);
	if (bytes != size) {
		RRR_MSG_0("The whole file %s was not read (result %lu): %s\n",
				filename, bytes, rrr_strerror(ferror(file)));
		ret = 1;
		goto out_free;
	}

	*target = file_data;
	*target_size = bytes;

	goto out_close;
	out_free:
		free(file_data);
	out_close:
		fclose(file);
	out:
		return ret;
}
