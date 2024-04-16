
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

#include "arena.h"

#include "../allocator.h"
#include "../util/gnu.h"

#define ARENA_RESOLVE(handle) \
    (arena->data + handle)

#define RRR_RAFT_ARENA_SENTINEL

void rrr_raft_arena_cleanup (
		struct rrr_raft_arena *arena
) {
	RRR_FREE_IF_NOT_NULL(arena->data);
	arena->pos = 0;
	arena->size = 0;
}

rrr_raft_arena_handle rrr_raft_arena_alloc (
		struct rrr_raft_arena *arena,
		size_t size
) {
	static const size_t align = sizeof(uint64_t);
	static const size_t alloc_min = 65536;

	size_t size_new, pos;
	void *data_new;

	assert(size > 0);

	size += align - (size % align);
#ifdef RRR_RAFT_ARENA_SENTINEL
	size += sizeof(uint64_t);
	if (arena->data != NULL && * (uint64_t *) (arena->data + arena->pos - sizeof(uint64_t)) != 0xdeadbeefdeadbeef) {
		RRR_BUG("BUG: Sentinel overwritten in %s, data is %016llx\n",
			__func__,
			(unsigned long long) * (uint64_t *) (arena->data + arena->pos - sizeof(uint64_t))
		);
	}
#endif /* RRR_RAFT_ARENA_SENTINEL */

	if (arena->pos + size > arena->size) {
		size_new = arena->size + size;
		size_new += alloc_min - (size_new % alloc_min);
		assert(size_new > arena->size);

		if ((data_new = rrr_reallocate(arena->data, size_new)) == NULL) {
			RRR_BUG("CRITICAL: Failed to allocate memory in %s\n", __func__);
		}

		arena->data = data_new;
		arena->size = size_new;
	}

#ifdef RRR_RAFT_ARENA_SENTINEL
	* (uint64_t *) (arena->data + arena->pos + size - sizeof(uint64_t)) = 0xdeadbeefdeadbeef;
#endif

	pos = arena->pos;
	arena->pos += size;
	return pos;
}

rrr_raft_arena_handle rrr_raft_arena_strdup (
		struct rrr_raft_arena *arena,
		const char *str
) {
	rrr_raft_arena_handle handle;
	char *data;
	size_t len;

	len = strlen(str);
	handle = rrr_raft_arena_alloc(arena, len);
	data = ARENA_RESOLVE(handle);
	memcpy(data, str, len + 1);

	return handle;
}

rrr_raft_arena_handle rrr_raft_arena_memdup (
		struct rrr_raft_arena *arena,
		void *ptr,
		size_t size
) {
	rrr_raft_arena_handle handle_new;
	char *ptr_new;

	handle_new = rrr_raft_arena_alloc(arena, size);
	ptr_new = ARENA_RESOLVE(handle_new);

	memcpy(ptr_new, ptr, size);

	return handle_new;
}

rrr_raft_arena_handle rrr_raft_arena_vasprintf (
		struct rrr_raft_arena *arena,
		const char *format,
		va_list args
) {
	char *tmp;
	rrr_raft_arena_handle handle;
	int bytes;

	if ((bytes = rrr_vasprintf(&tmp, format, args)) < 0) {
		RRR_BUG("CRITICAL: Failed to allocate memory in %s\n", __func__);
	}

	handle = rrr_raft_arena_memdup(arena, tmp, bytes + 1);

	rrr_free(tmp);

	return handle;
}

rrr_raft_arena_handle rrr_raft_arena_realloc (
		struct rrr_raft_arena *arena,
		rrr_raft_arena_handle handle,
		size_t size,
		size_t oldsize
) {
	rrr_raft_arena_handle handle_new;
	void *ptr, *data;

	handle_new = rrr_raft_arena_alloc(arena, size);
	data = ARENA_RESOLVE(handle_new);

	if (oldsize > 0) {
		ptr = ARENA_RESOLVE(handle);

		if (oldsize < size) {
			memcpy(data, ptr, oldsize);
		}
		else {
			memcpy(data, ptr, size);
		}
	}

	return handle_new;
}
