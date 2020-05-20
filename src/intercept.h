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

// Override possibly dangerous library functions

#ifndef RRR_INTERCEPT_H
#define RRR_INTERCEPT_H

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

// umask calls must be wrapped in global umask lock
#ifndef RRR_INTERCEPT_ALLOW_UMASK
#	define uname(x)			RRR_INTERCEPT_H_UNSAFE_LIBARY_FUNCTION_UMASK
#endif

#endif /* RRR_INTERCEPT_H */
