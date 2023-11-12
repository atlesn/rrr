/*

Read Route Record

Copyright (C) 2021-2023 Atle Solbakken atle@goliathdns.no

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

#include "../rrr_types.h"

#ifndef RRR_MSG_DUMP_H
#define RRR_MSG_DUMP_H

struct rrr_msg;

int rrr_msg_dump_to_host_and_dump (
		struct rrr_msg *msg,
		rrr_length expected_size
);
int rrr_msg_dump_msg (
		const struct rrr_msg_msg *msg
);

#endif /* RRR_MSG_DUMP_H */
