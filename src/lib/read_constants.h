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

#ifndef RRR_SOCKET_READ_CONSTANTS_H
#define RRR_SOCKET_READ_CONSTANTS_H

#define RRR_READ_OK				0
#define RRR_READ_HARD_ERROR		1
#define RRR_READ_SOFT_ERROR		2
#define RRR_READ_INCOMPLETE		3
#define RRR_READ_EOF			4

#define RRR_READ_COMPLETE_METHOD_TARGET_LENGTH			0
#define RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ		11

#define RRR_READ_F_NO_SLEEPING			(1<<0)

// #define RRR_READ_F_EOF_AT_ZERO_BYTES_READ	(1<<0)

/*
#define RRR_READ_METHOD_READ_FILE	(1<<0)
#define RRR_READ_METHOD_RECVFROM	(1<<1)
#define RRR_READ_CHECK_EOF			(1<<2)
#define RRR_READ_USE_TIMEOUT		(1<<3)
#define RRR_READ_NO_SLEEPING		(1<<4)
#define RRR_READ_METHOD_RECV		(1<<5)
*/

#endif /* RRR_SOCKET_READ_CONSTANTS_H */
