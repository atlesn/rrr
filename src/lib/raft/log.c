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

#include "bridge.h"
#include "log.h"

#include "../allocator.h"

int rrr_raft_log_push (
		struct rrr_raft_log *log,
		struct raft_entry *entry,
		raft_index index
) {
	int ret = 0;

	size_t capacity_new;
	struct raft_entry *entries_new;

	assert(index > 0);

	if (log->count == 0) {
		assert(log->first_index == 0);
		log->first_index = index;
	}
	else {
		assert(index == log->first_index + log->count);
	}

	if (log->count == log->capacity) {
		capacity_new = log->capacity + 64;
		if ((entries_new = rrr_reallocate(log->entries, sizeof(*entries_new) * capacity_new)) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		log->capacity = capacity_new;
		log->entries = entries_new;
	}	

	log->entries[log->count++] = *entry;
	entry->buf.base = NULL;
	entry->buf.len = 0;

	out:
	return ret;
}

void rrr_raft_log_cleanup (
		struct rrr_raft_log *log
) {
	size_t i;
	struct raft_entry *entry;

	for (i = 0; i < log->count; i++) {
		entry = log->entries + i;
		assert(entry->batch == NULL);
		RRR_FREE_IF_NOT_NULL(entry->buf.base);
	}

	RRR_FREE_IF_NOT_NULL(log->entries);
}

const struct raft_entry *rrr_raft_log_get (
		const struct rrr_raft_log *log,
		raft_index index
) {
	raft_index pos;

	assert(index >= log->first_index);

	pos = index - log->first_index - 1;
	if (pos >= log->count)
		return NULL;
	
	return log->entries + pos;
}
