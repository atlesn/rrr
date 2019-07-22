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
#include <string.h>

#include "../include/bdl.h"
#include "io.h"
#include "clear.h"
#include "blocks.h"
#include "write.h"

int clear_hintblocks_loop_callback (
		struct bdl_hintblock_loop_callback_data *data,
		int *result
) {
	struct bdl_hint_block new_hintblock;
	memset (&new_hintblock, '\0', sizeof(new_hintblock));

	if (write_put_and_pad_block (
			data->file,
			data->hintblock_position,
			(const char *) &new_hintblock, sizeof(new_hintblock),
			data->master_header->pad_character, data->master_header->block_size
	) != 0)  {
		fprintf (stderr, "Error while putting blank hint block\n");
		*result = BDL_BLOCK_LOOP_ERR;
		return 1;
	}
	return BDL_BLOCK_LOOP_OK;
}

int clear_dev(struct bdl_io_file *file, int *result) {
	struct bdl_header master_header;

	if (block_get_validate_master_header(file, &master_header, result) != 0) {
		fprintf (stderr, "Could not validate master header while reading it for clearing\n");
		return 1;
	}

	if (*result != 0) {
		fprintf (stderr, "Header was not valid, device must be initialized.\n");
		return 0;
	}

	struct bdl_hintblock_loop_callback_data callback_data;
	struct bdl_block_location location;
	callback_data.argument_int = 0;
	callback_data.argument_ptr = NULL;

	if (block_loop_hintblocks_large_device (
			file, &master_header, NULL,
			clear_hintblocks_loop_callback, &callback_data,
			&location,
			result
	) != 0) {
		fprintf (stderr, "Error while looping hintblocks while reading blocks\n");
		return 1;
	}

	return 0;
}
