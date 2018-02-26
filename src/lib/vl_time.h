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

#ifndef VL_TIME_H
#define VL_TIME_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

static inline uint64_t time_get_64() {
	struct timeval tv;
	double time_tmp;

	if (gettimeofday(&tv, NULL) != 0) {
		fprintf (stderr, "Error while getting time, cannot recover from this: %s\n", strerror(errno));
		exit (EXIT_FAILURE);
	}

	time_tmp = (tv.tv_sec * 1000000.0) + (tv.tv_usec);

	return time_tmp;
}

#endif
