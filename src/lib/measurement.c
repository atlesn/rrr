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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct vl_reading *reading_new(
		uint64_t reading_millis,
		uint64_t time,
		const char *msg,
		unsigned long int msg_size
) {
	struct vl_reading *res = malloc(sizeof(*res));
	res->reading_millis = reading_millis;

	if (init_message (
			MSG_TYPE_MSG,
			MSG_CLASS_POINT,
			time,
			time,
			msg,
			msg_size,
			&res->message
	) != 0) {
		free(res);
		fprintf (stderr, "Bug: Could not initialize message\n");
		exit (EXIT_FAILURE);
	}

	return res;
}
