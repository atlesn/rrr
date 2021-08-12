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

#ifndef RRR_POSIX_H
#define RRR_POSIX_H

#include <sys/types.h>
#include <limits.h>
#include <string.h>
#include "../log.h"
#include "../rrr_types.h"

#define RRR_POSIX_MUTEX_IS_RECURSIVE    (1<<0)
#define RRR_POSIX_MUTEX_IS_PSHARED      (1<<1)
#define RRR_POSIX_MUTEX_IS_ERRORCHECK   (1<<2)

int rrr_posix_usleep(size_t useconds);
void *rrr_posix_mmap (size_t size, int is_shared);
void *rrr_posix_mmap_with_fd (int fd, size_t size);
int rrr_posix_strcasecmp (const char *a, const char *b);
int rrr_posix_strncasecmp (const char *a, const char *b, size_t n);
int rrr_posix_mutex_init (pthread_mutex_t *mutex, int flags);
int rrr_posix_rwlock_init (pthread_rwlock_t *mutex, int flags);
int rrr_posix_cond_init (pthread_cond_t *mutex, int flags);

#if RRR_BIGLENGTH_MAX > SIZE_MAX

static inline void *rrr_memcpy(void *dest, const void *src, rrr_biglength n) {
	if (n > SIZE_MAX) {
		RRR_BUG("Bug: Overflow in rrr_memcpy, caller should check for this\n");
	}
	return memcpy(dest, src, (size_t) n);
}

static inline void *rrr_memset(void *s, int c, rrr_biglength n) {
	if (n > SIZE_MAX) {
		RRR_BUG("Bug: Overflow in rrr_memset, caller should check for this\n");
	}
	return memset(s, c, (size_t) n);
}

static inline int rrr_memcmp(const void *s1, const void *s2, rrr_biglength n) {
	if (n > SIZE_MAX) {
		RRR_BUG("Bug: Overflow in rrr_memcmp, caller should check for this\n");
	}
	return memcmp(s1, s2, (size_t) n);
}

#else

static inline void *rrr_memcpy(void *dest, const void *src, rrr_biglength n) {
	return memcpy(dest, src, (size_t) n);
}

static inline void *rrr_memset(void *dest, const void *src, rrr_biglength n) {
	return memset(dest, src, (size_t) n);
}

static inline int rrr_memcmp(const void *s1, const void *s2, rrr_biglength n) {
	return memcmp(s1, s2, n);
}

#endif /* RRR_BIGLENGTH_MAX > SIZE_MAX */

#endif /* RRR_POSIX_H */
