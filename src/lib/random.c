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

#include <pthread.h>
#include <stdlib.h>

#include "log.h"
#include "random.h"
#include "util/rrr_time.h"

static volatile int rrr_rand_initialized = 0;
static pthread_mutex_t rrr_rand_lock = PTHREAD_MUTEX_INITIALIZER;

int rrr_rand(void) {
	int result = 0;

	pthread_mutex_lock(&rrr_rand_lock);

	if (rrr_rand_initialized != 1) {
		srand((unsigned int) (rrr_time_get_64() & 0xffffffff));
		rrr_rand_initialized = 1;
	}

	result = rand();

	pthread_mutex_unlock(&rrr_rand_lock);

	return result;
}

void rrr_random_string(char *target, size_t target_size) {
	if (target_size == 0) {
		RRR_BUG("BUG: Size was 0 in rrr_random_string\n");
	}

	size_t pos = 0;
	while (pos < target_size) {
		unsigned char rand = (unsigned char) (rrr_rand() % 0xff);
		if ( (rand >= 'A' && rand <= 'Z') ||
		     (rand >= 'a' && rand <= 'z') ||
		     (rand >= '0' && rand <= '9')
		) {
			target[pos++] = (char) rand;
		}
	}
	target[target_size - 1] = '\0';
}

void rrr_random_bytes(void *target, size_t bytes) {
	unsigned char *dataptr = target;

	for (size_t i = 0; i < bytes; i++) {
		*dataptr = (unsigned char) rrr_rand() % 0xff;
		dataptr++;
	}
}
