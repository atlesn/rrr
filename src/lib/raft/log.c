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

/*
raft_index rrr_raft_get_last_index (
		const struct rrr_raft_log *log
) {
	assert(log->count > 0);
	return log->entries[log->count - 1].index;
}
*/
int rrr_raft_log_push (
		struct rrr_raft_log *log,
		const void *data,
		size_t data_size,
		raft_term term,
		raft_index index,
		enum raft_entry_type type
) {
	int ret = 0;

	size_t capacity_new;
	struct rrr_raft_log_entry *entries_new;
	struct rrr_raft_log_entry *entry;

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

	entry = log->entries + log->count;

	if (data_size > 0) {
		if ((entry->data = rrr_allocate(data_size)) == NULL) {
			RRR_MSG_0("Failed to allocate memory for entry in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memcpy(entry->data, data, data_size);
	}
	else {
		entry->data = NULL;
	}

	entry->data_size = data_size;
	entry->term = term;
	entry->index = index;
	entry->type = type;

	log->count++;

	out:
	return ret;
}

void rrr_raft_log_cleanup (
		struct rrr_raft_log *log
) {
	size_t i;
	struct rrr_raft_log_entry *entry;

	for (i = 0; i < log->count; i++) {
		entry = log->entries + i;
		RRR_FREE_IF_NOT_NULL(entry->data);
	}

	RRR_FREE_IF_NOT_NULL(log->entries);
}

const struct rrr_raft_log_entry *rrr_raft_log_get (
		const struct rrr_raft_log *log,
		raft_index index
) {
	raft_index pos;
	struct rrr_raft_log_entry *entry;

	assert(index >= log->first_index);
	pos = index - log->first_index;
	printf("index %llu first index %llu\n", (unsigned long long) index, (unsigned long long) log->first_index);
	if (pos >= log->count)
		return NULL;
	entry = log->entries + pos;
	assert(entry->index == index);
	return entry;
}

void rrr_raft_log_truncate (
		struct rrr_raft_log *log,
		raft_index index
) {
	raft_index count;

	assert(index >= log->first_index);

	if ((count = index - log->first_index) == 0)
		return;

	log->count -= count;

	assert((log->entries + (index - log->first_index))->index == index);
}
