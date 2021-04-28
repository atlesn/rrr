/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

// Override possibly dangerous library functions, create intentional compile errors

#ifndef RRR_INTERCEPT_H
#define RRR_INTERCEPT_H

// Blocks a lot of stuff
#define _POSIX_C_SOURCE 200809L

#ifndef RRR_INTERCEPT_ALLOW_READDIR
	// Not guaranteed thread-safety in current POSIX specification, rrr wrapper with
	// locking must be used
#	define readdir(x) RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_READDIR
#endif

#ifndef RRR_INTERCEPT_ALLOW_STRERROR
#	define strerror(x) RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_STRERROR
#endif

// Only main() is allowed to do this, others through access functions
#ifndef RRR_INTERCEPT_ALLOW_FORK
#	define waitpid(x,y,z)	RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_WAITPID
#	define wait(x)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_WAIT
#	define fork(x)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_FORK
#endif

// All logging must be done through wrappers
#ifndef RRR_INTERCEPT_ALLOW_PRINTF
//#	define printf(x,...)	RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PRINTF
#endif

// to prevent bugs, all mutex initialization must use helper functions
#ifndef RRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT
#	define pthread_mutex_init(x,y)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_MUTEX_INIT
#	define pthread_mutexattr_init(x)		RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_MUTEX_INIT
#	define pthread_rwlock_init(x,y)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_RWLOCK_INIT
#	define pthread_rwlockattr_init(x)		RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_RWLOCKATTR_INIT
#	define pthread_condattr_init(x)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_CONDATTR_INIT
#	define pthread_cond_init(x,y)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_PTHREAD_COND_INIT
#endif

// umask calls must be wrapped in global umask lock
#ifndef RRR_INTERCEPT_ALLOW_UMASK
#	define umask(x)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_UMASK
#endif

#ifndef RRR_INTERCEPT_ALLOW_GETTID
#	define gettid(void)		RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_GETTID
#endif
/*
#define malloc(a)      RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_MALLOC
#define strdup(a)      RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_STRDUP
#define calloc(a,b)    RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_CALLOC
#define realloc(a,b)   RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_REALLOC
#define free(a)        RRR_INTERCEPT_H_UNSAFE_LIBRARY_FUNCTION_FREE
*/
#define asprintf(...)  rrr_asprintf(__VA_ARGS__)

#endif /* RRR_INTERCEPT_H */
