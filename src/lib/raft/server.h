/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_RAFT_SERVER_H
#define RRR_RAFT_SERVER_H

#include <stdio.h>
#include <stddef.h>

#include "common.h"

struct rrr_raft_channel;
struct rrr_raft_server;
struct rrr_msg_msg;

int rrr_raft_server (
		struct rrr_raft_channel *channel,
		const char *log_prefix,
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
		int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
);

#endif /* RRR_RAFT_SERVER_H */
