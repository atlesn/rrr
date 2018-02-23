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

#ifndef VL_MEASUREMENT_H
#define VL_MEASUREMENT_H

#include <stdlib.h>
#include <stdint.h>

#define VL_READING_MSG_SIZE 128

struct reading {
	uint64_t reading_millis;
	char msg[128];
	unsigned long int msg_size;
};

struct average {

};

static inline struct reading *reading_new(uint64_t reading_millis, const char *msg, unsigned long int msg_size) {
	if (msg_size > VL_READING_MSG_SIZE) {
		fprintf (stderr, "Bug: Too long message for measurement\n");
		exit (EXIT_FAILURE);
	}

	struct reading *res = malloc(sizeof(*res));
	res->reading_millis = reading_millis;
	res->msg[0] = '\0';

	if (msg_size > 0) {
		memcpy(res->msg, msg, msg_size);
		res->msg_size = msg_size;
	}

	return res;
}

static inline void reading_free(struct reading *reading) {
	free(reading);
}

#endif
