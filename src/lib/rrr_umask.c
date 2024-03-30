/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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
#include <sys/stat.h>
#include <sys/types.h>

#include "rrr_umask.h"
#include "log.h"

static pthread_mutex_t rrr_umask_lock = PTHREAD_MUTEX_INITIALIZER;
static int rrr_umask_global_was_set = 0;
static mode_t rrr_umask_global = 0;

mode_t rrr_umask_get_global (void) {
	mode_t umask_ret = 0;

	pthread_mutex_lock(&rrr_umask_lock);

	if (rrr_umask_global_was_set != 1) {
		RRR_BUG("BUG: rrr_umask_get_global was called but rrr_umask_onetime_set_global has not yet been called\n");
	}

	umask_ret = rrr_umask_global;

	pthread_mutex_unlock(&rrr_umask_lock);

	return umask_ret;
}

void rrr_umask_onetime_set_global (
		mode_t umask_new
) {
	pthread_mutex_lock(&rrr_umask_lock);

	if (rrr_umask_global_was_set != 0) {
		RRR_BUG("BUG: rrr_umask_onetime_set_global called for a second time\n");
	}

	mode_t umask_old = umask(umask_new);

	RRR_DBG_7("global umask set to %i, old umask was %i\n",
			umask_new, umask_old);

	rrr_umask_global_was_set = 1;
	rrr_umask_global = umask_new;

	pthread_mutex_unlock(&rrr_umask_lock);
}

int rrr_umask_with_umask_lock_do (
		mode_t umask_new,
		int (*callback)(void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	mode_t umask_orig;

	pthread_mutex_lock(&rrr_umask_lock);

	umask_orig = umask(umask_new);

	RRR_DBG_7("umask wrapper set umask to %i, old umask was %i. Revert after callback returns.\n",
			umask_new, umask_orig);

	ret = callback(callback_arg);

	umask(umask_orig);

	pthread_mutex_unlock(&rrr_umask_lock);

	return ret;
}

int rrr_umask_with_umask_lock_and_mode_do (
		mode_t mode,
		int (*callback)(mode_t mode, void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	mode_t umask_orig;

	pthread_mutex_lock(&rrr_umask_lock);

	umask_orig = umask(0);
	umask(umask_orig);

	RRR_DBG_7("umask wrapper mode is %i.\n",
			mode);

	ret = callback(mode & ~umask_orig, callback_arg);

	pthread_mutex_unlock(&rrr_umask_lock);

	return ret;
}
