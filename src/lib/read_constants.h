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

#ifndef RRR_READ_CONSTANTS_H
#define RRR_READ_CONSTANTS_H

// These return values are standardized throughout RRR. Anyone who
// distinguishes between HARD and SOFT errors should use these values,
// possibly wrapped in private more appropriate names for the particular
// application.

// The standardized values allow return values from different frameworks
// in some circumstances to propagate without being translated. A common
// method is to trap the SOFT error only and do some special tasks like
// deferring a message for later retry or closing a connection, and let
// all other values be interpreted as HARD error and quitting all operations.

// These values may be used both with checking directly using == or as
// bit flags. It is not recommended to use bitwise return values for library
// frameworks used by many other frameworks and modules, this becomes method.

// For special cases, consider giving feedback to the caller by using integer
// pointers in the function arguments like (int *a_happened, int *b_happened),
// or by having status information stored in callback data structures.

// Please ignore the fact that the names contain "READ", they are used for
// writing and all sorts of other tasks.

// Return values are ALWAYS of type "int"

// In functions where the type of error is always the same (failed input
// validation is usually always a soft error, init function fails are
// always hard errors), the function should return 0 for ok or 1
// for error, WITHOUT using ANY macros.

// The comments for each value here are examples only.

// OK (doh)
#define RRR_READ_OK				0

// Bad problem like allocation failure. Program should exit or restart.
#define RRR_READ_HARD_ERROR		1

// Soft error, like invalid data from remote client. Connection should be destroyed.
#define RRR_READ_SOFT_ERROR		2

// Not done yet, possibly call me again later
#define RRR_READ_INCOMPLETE		4

// End of file, nothing more to read, etc.
#define RRR_READ_EOF			8

// When adding more, be sure about your powers of 2. Note that if you add more, others
// might start using them.

// Applicable only when using the read framework
#define RRR_READ_COMPLETE_METHOD_TARGET_LENGTH			0
#define RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ		11
#define RRR_READ_F_NO_SLEEPING (1<<0)

#endif /* RRR_READ_CONSTANTS_H */
