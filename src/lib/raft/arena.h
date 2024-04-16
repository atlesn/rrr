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

#ifndef RRR_RAFT_ARENA_H
#define RRR_RAFT_ARENA_H

#include <stddef.h>
#include <assert.h>
#include <stdarg.h>

struct rrr_raft_arena {
	void *data;
	size_t pos;
	size_t size;
};

typedef size_t rrr_raft_arena_handle;

static inline void rrr_raft_arena_reset (
		struct rrr_raft_arena *arena
) {
	arena->pos = 0;
}

static inline void *rrr_raft_arena_resolve (
		struct rrr_raft_arena *arena,
		rrr_raft_arena_handle handle
) {
	assert(handle < arena->pos);
	return arena->data + handle;
}

void rrr_raft_arena_cleanup (
		struct rrr_raft_arena *arena
);
rrr_raft_arena_handle rrr_raft_arena_alloc (
		struct rrr_raft_arena *arena,
		size_t size
);
rrr_raft_arena_handle rrr_raft_arena_strdup (
		struct rrr_raft_arena *arena,
		const char *str
);
rrr_raft_arena_handle rrr_raft_arena_memdup (
		struct rrr_raft_arena *arena,
		void *ptr,
		size_t size
);
rrr_raft_arena_handle rrr_raft_arena_vasprintf (
		struct rrr_raft_arena *arena,
		const char *format,
		va_list args
);
rrr_raft_arena_handle rrr_raft_arena_realloc (
		struct rrr_raft_arena *arena,
		rrr_raft_arena_handle handle,
		size_t size,
		size_t oldsize
);

#endif /* RRR_RAFT_ARENA_H */
