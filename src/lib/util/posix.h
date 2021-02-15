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

#define RRR_POSIX_MUTEX_IS_RECURSIVE    (1<<0)
#define RRR_POSIX_MUTEX_IS_PSHARED      (1<<1)
#define RRR_POSIX_MUTEX_IS_ERRORCHECK   (1<<2)

int rrr_posix_usleep(int useconds);
void *rrr_posix_mmap (size_t size);
int rrr_posix_strcasecmp (const char *a, const char *b);
int rrr_posix_strncasecmp (const char *a, const char *b, size_t n);
int rrr_posix_mutex_init (pthread_mutex_t *mutex, int flags);
int rrr_posix_rwlock_init (pthread_rwlock_t *mutex, int flags);
int rrr_posix_cond_init (pthread_cond_t *mutex, int flags);

#endif /* RRR_POSIX_H */
