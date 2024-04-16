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

#ifndef RRR_RAFT_LOG_H
#define RRR_RAFT_LOG_H

#include <raft.h>

struct rrr_raft_log {
	struct raft_entry *entries;
	size_t count;
	size_t capacity;
	raft_index first_index;
};

int rrr_raft_log_push (
		struct rrr_raft_log *log,
		struct raft_entry *entry,
		raft_index index
);
void rrr_raft_log_cleanup (
		struct rrr_raft_log *log
);
const struct raft_entry *rrr_raft_log_get (
		const struct rrr_raft_log *log,
		raft_index index
);

#endif /* RRR_RAFT_LOG_H */
