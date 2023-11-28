/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "allocator.h"

int rrr_arena_expand (
		struct rrr_arena *arena,
		size_t size,
		const char *name
) {
	void *ptr_tmp;

	assert(size > arena->size);

	if (*arena->name == '\0') {
		strncpy(arena->name, name, sizeof(arena->name) - 1);
		arena->name[sizeof(arena->name) - 1] = '\0';
	}

	size = (size + RRR_ARENA_SIZE_STEP_MIN - 1) & ~(RRR_ARENA_SIZE_STEP_MIN - 1);

	if ((ptr_tmp = rrr_reallocate(arena->ptr, arena->size, size)) == NULL) {
		RRR_MSG_0("Failed to expand arena '%s' to %llu bytes\n",
			arena->name, (unsigned long long) size);
		return 1;
	}

	arena->ptr = ptr_tmp;
	arena->size = size;

	return 0;
}
