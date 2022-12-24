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

#ifndef RRR_MESSAGE_HOLDER_UTIL_H
#define RRR_MESSAGE_HOLDER_UTIL_H

#include <sys/socket.h>

#include "../rrr_types.h"

struct rrr_msg_holder;

int rrr_msg_holder_util_new_with_empty_message (
		struct rrr_msg_holder **result,
		rrr_biglength message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol
);
int rrr_msg_holder_util_clone_no_locking (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
);
int rrr_msg_holder_util_clone_no_locking_no_metadata (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
);

#endif /* RRR_MESSAGE_HOLDER_UTIL_H */
