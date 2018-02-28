/*

Voltage Logger

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

#include "measurement.h"
#include "threads.h"
#include "messages.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

struct vl_message *reading_new (
		uint64_t reading_millis,
		uint64_t time
) {
	struct vl_message *res = malloc(sizeof(*res));

	char buf[64];
	sprintf (buf, "%" PRIu64, reading_millis);

	if (init_message (
			MSG_TYPE_MSG,
			MSG_CLASS_POINT,
			time,
			time,
			reading_millis,
			buf,
			strlen(buf) + 1,
			res
	) != 0) {
		free(res);
		fprintf (stderr, "Bug: Could not initialize message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}

struct vl_message *reading_new_info (
		uint64_t time,
		const char *msg_terminated
) {
	struct vl_message *res = malloc(sizeof(*res));

	if (init_message (
			MSG_TYPE_MSG,
			MSG_CLASS_INFO,
			time,
			time,
			0,
			msg_terminated,
			strlen(msg_terminated)+1,
			res
	) != 0) {
		free(res);
		fprintf (stderr, "Bug: Could not initialize info message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}


