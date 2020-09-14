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

#ifndef RRR_SOCKET_CONSTANTS_H
#define RRR_SOCKET_CONSTANTS_H

#include "../read_constants.h"

#define RRR_SOCKET_OK					RRR_READ_OK
#define RRR_SOCKET_HARD_ERROR			RRR_READ_HARD_ERROR
#define RRR_SOCKET_SOFT_ERROR			RRR_READ_SOFT_ERROR
#define RRR_SOCKET_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_SOCKET_READ_EOF				RRR_READ_EOF

#define RRR_SOCKET_READ_METHOD_READ_FILE	(1<<0)
#define RRR_SOCKET_READ_METHOD_RECVFROM		(1<<1)
#define RRR_SOCKET_READ_CHECK_EOF			(1<<2)
#define RRR_SOCKET_READ_USE_TIMEOUT			(1<<3)
#define RRR_SOCKET_READ_CHECK_POLLHUP		(1<<4)
#define RRR_SOCKET_READ_METHOD_RECV			(1<<5)
#define RRR_SOCKET_READ_NO_GETSOCKOPTS		(1<<6)
#define RRR_SOCKET_READ_INPUT_DEVICE		(1<<7)

#define RRR_SOCKET_CLIENT_TIMEOUT_S 30

#endif /* RRR_SOCKET_CONSTANTS_H */
