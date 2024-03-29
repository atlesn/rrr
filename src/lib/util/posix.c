/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

// Allow functions on BSD
#define __BSD_VISIBLE 1

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <poll.h>
#include <unistd.h>

#include "../log.h"
#include "../rrr_strerror.h"
#include "../rrr_types.h"
#include "posix.h"

void rrr_posix_msleep_signal_safe (int mseconds) {
	int pipefd[2] = {0};

	if (pipe(pipefd) != 0) {
		pipefd[0] = STDIN_FILENO;
	}

	struct pollfd pollfd = {0};

	pollfd.fd = pipefd[0];
	pollfd.events = POLLIN;

	poll(&pollfd, 1, mseconds);

	if (pipefd[0] > 0 && pipefd[0] != STDIN_FILENO) {
		close(pipefd[0]);
	}
	if (pipefd[1] > 0) {
		close(pipefd[1]);
	}
}

int rrr_posix_usleep(size_t useconds) {
	size_t part_useconds = (useconds % 1000000);
	size_t part_seconds =  (useconds - part_useconds) / 1000000;

	struct timespec req = {
		(long) part_seconds,
		(long) part_useconds * 1000
	};

	struct timespec rem = {0};

	return nanosleep(&req, &rem);
}

int rrr_posix_sleep_us(rrr_time_us_t t) {
	assert(t.us <= SIZE_MAX);
	return rrr_posix_usleep((size_t) t.us);
}

void *rrr_posix_mmap (size_t size, int is_shared) {
	return mmap (
			NULL,
			size,
			PROT_READ | PROT_WRITE,
			(is_shared ? MAP_SHARED : MAP_PRIVATE) | MAP_ANONYMOUS,
			-1,
			0
	);
}

void *rrr_posix_mmap_with_fd (int fd, size_t size) {
	return mmap (
			NULL,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED,
			fd,
			0
	);
}

int rrr_posix_strcasecmp (const char *a, const char *b) {
	return strcasecmp(a, b);
}

int rrr_posix_strncasecmp (const char *a, const char *b, size_t n) {
	return strncasecmp(a, b, n);
}

int rrr_posix_mutex_init (pthread_mutex_t *mutex, int flags) {
	int ret = 0;

	int is_recursive = (flags & RRR_POSIX_MUTEX_IS_RECURSIVE);
	int is_pshared = (flags & RRR_POSIX_MUTEX_IS_PSHARED);
	int is_errorcheck = (flags & RRR_POSIX_MUTEX_IS_ERRORCHECK);
	int is_robust = (flags & RRR_POSIX_MUTEX_IS_ROBUST);

	flags &= ~(RRR_POSIX_MUTEX_IS_RECURSIVE|RRR_POSIX_MUTEX_IS_PSHARED|RRR_POSIX_MUTEX_IS_ERRORCHECK|RRR_POSIX_MUTEX_IS_ROBUST);

	if (flags != 0) {
		RRR_BUG("BUG: Unsupported flags %i to rrr_posix_mutex_init\n", flags);
	}

	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0)  {
		RRR_MSG_0("Could not initialize mutexattr in rrr_posix_mutex_init\n");
		ret = 1;
		goto out;
	}

	if (is_errorcheck) {
		if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0){
			RRR_MSG_0("settype(ERRORCHECK) failed in rrr_posix_mutex_init, not supported on this platform: %s\n",
					rrr_strerror(errno));
			ret = 1;
			goto out_destroy_mutexattr;
		}
	}

	if (is_pshared) {
		if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
			RRR_MSG_0("setpshared() failed in rrr_posix_mutex_init, not supported on this platform: %s\n",
					rrr_strerror(errno));
			ret = 1;
			goto out_destroy_mutexattr;
		}
	}

	if (is_robust) {
		if (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0) {
			RRR_MSG_0("setrobust() failed in rrr_posix_mutex_init, not supported on this platform: %s\n",
					rrr_strerror(errno));
			ret = 1;
			goto out_destroy_mutexattr;
		}
	}

	if (pthread_mutexattr_settype(&attr, (is_recursive ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_NORMAL)) != 0) {
		RRR_MSG_0("settype() failed in rrr_posix_mutex_init: %s\n",
				rrr_strerror(errno));
		ret = 1;
		goto out_destroy_mutexattr;
	}

	if (pthread_mutex_init(mutex, &attr) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_posix_mutex_init: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_mutexattr;
	}

	goto out_destroy_mutexattr;

	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}

int rrr_posix_rwlock_init (pthread_rwlock_t *mutex, int flags) {
	int ret = 0;

	int is_pshared = (flags & RRR_POSIX_MUTEX_IS_PSHARED);

	flags &= ~(RRR_POSIX_MUTEX_IS_PSHARED);

	if (flags != 0) {
		RRR_BUG("BUG: Unsupported flags %i to rrr_posix_rwlock_init\n", flags);
	}

	pthread_rwlockattr_t attr;

	if (pthread_rwlockattr_init(&attr) != 0)  {
		RRR_MSG_0("Could not initialize mutexattr in rrr_posix_rwlock_init\n");
		ret = 1;
		goto out;
	}

	if (is_pshared) {
		if (pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
			RRR_MSG_0("setpshared() failed in rrr_posix_rwlock_init, not supported on this platform: %s\n",
					rrr_strerror(errno));
			ret = 1;
			goto out_destroy_rwlockattr;
		}
	}

	if (pthread_rwlock_init(mutex, &attr) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_posix_rwlock_init: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_rwlockattr;
	}

	goto out_destroy_rwlockattr;

	out_destroy_rwlockattr:
		pthread_rwlockattr_destroy(&attr);
	out:
		return ret;
}

int rrr_posix_cond_init (pthread_cond_t *mutex, int flags) {
	int ret = 0;

	int is_pshared = (flags & RRR_POSIX_MUTEX_IS_PSHARED);

	flags &= ~(RRR_POSIX_MUTEX_IS_PSHARED);

	if (flags != 0) {
		RRR_BUG("BUG: Unsupported flags %i to rrr_posix_cond_init\n", flags);
	}

	pthread_condattr_t attr;

	if (pthread_condattr_init(&attr) != 0)  {
		RRR_MSG_0("Could not initialize mutexattr in rrr_posix_cond_init\n");
		ret = 1;
		goto out;
	}

	if (is_pshared) {
		if (pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
			RRR_MSG_0("setpshared() failed in rrr_posix_cond_init, not supported on this platform: %s\n",
					rrr_strerror(errno));
			ret = 1;
			goto out_destroy_condattr;
		}
	}

	if (pthread_cond_init(mutex, &attr) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_posix_cond_init: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_condattr;
	}

	goto out_destroy_condattr;

	out_destroy_condattr:
		pthread_condattr_destroy(&attr);
	out:
		return ret;
}

static void __rrr_posix_mutex_robust_consistent (pthread_mutex_t *mutex) {
	int ret_tmp = 0;

	RRR_MSG_0("Mutex was inconsitent in %s while locking, the holder has died.\n",
			__func__);
	if ((ret_tmp = pthread_mutex_consistent(mutex)) != 0) {
		RRR_BUG("Failed to make mutex consistent in %s, cannot recover from this: %s\n",
				__func__, rrr_strerror(ret_tmp));
	}
}

int rrr_posix_mutex_robust_lock (pthread_mutex_t *mutex) {
	int ret = RRR_POSIX_MUTEX_ROBUST_OK;

	if ((ret = pthread_mutex_lock (mutex)) != 0) {
		if (ret == EOWNERDEAD) {
			__rrr_posix_mutex_robust_consistent(mutex);
			pthread_mutex_unlock(mutex);
			ret = RRR_POSIX_MUTEX_ROBUST_ERROR;
		}
		else {
			RRR_BUG("Error returned from pthread_mutex_lock in %s, cannot recover from this: %s\n",
				__func__, rrr_strerror(ret));
		}
	}

	return ret;
}

int rrr_posix_mutex_robust_trylock (pthread_mutex_t *mutex) {
	int ret = RRR_POSIX_MUTEX_ROBUST_OK;

	if ((ret = pthread_mutex_trylock (mutex)) != 0) {
		if (ret == EOWNERDEAD) {
			__rrr_posix_mutex_robust_consistent(mutex);
			ret = RRR_POSIX_MUTEX_ROBUST_ERROR;
		}
		else if (ret == EBUSY) {
			ret = RRR_POSIX_MUTEX_ROBUST_BUSY;
		}
		else {
			RRR_BUG("Error returned from pthread_mutex_lock in %s, cannot recover from this: %s\n",
				__func__, rrr_strerror(ret));
		}
	}

	return ret;
}

void rrr_posix_mutex_robust_destroy (pthread_mutex_t *mutex) {
	// Ensure lock is consisten before destroy
	rrr_posix_mutex_robust_lock(mutex);
	pthread_mutex_unlock(mutex);
	pthread_mutex_destroy(mutex);
}
