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

#include "random.h"
#include "vl_time.h"

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
