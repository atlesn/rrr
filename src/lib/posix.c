/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#define _POSIX_C_SOURCE 200809L

// Allow MAP_ANONYMOUS and strcasecmp
#define _DEFAULT_SOURCE

#include <sys/mman.h>
#include <time.h>
#include <string.h>

#include "posix.h"

int rrr_posix_usleep(int useconds) {
	long part_useconds = (useconds % 1000000);
	long part_seconds =  (useconds - part_useconds) / 1000000;

	struct timespec req = {
		part_seconds,
		part_useconds * 1000
	};

	struct timespec rem = {0};

	return nanosleep(&req, &rem);
}

void *rrr_posix_mmap (size_t size) {
    return mmap (
    		NULL,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS,
			-1,
			0
	);
}

int rrr_posix_strcasecmp (const char *a, const char *b) {
	return strcasecmp(a, b);
}

int rrr_posix_strncasecmp (const char *a, const char *b, size_t n) {
	return strncasecmp(a, b, n);
}
