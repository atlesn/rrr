/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_UTIL_THREADS_H
#define RRR_UTIL_THREADS_H

struct rrr_thread_double_pointer {
	void **ptr;
};

#define RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER_CUSTOM(name,free_function,pointer) \
	struct rrr_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(free_function, &__##name##_double_pointer)

#define RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(name,pointer) \
	struct rrr_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(rrr_thread_free_double_pointer, &__##name##_double_pointer)

#define RRR_THREAD_CLEANUP_PUSH_FREE_SINGLE_POINTER(name) \
	pthread_cleanup_push(rrr_thread_free_single_pointer, name)

#endif /* RRR_UTIL_THREADS_H */
