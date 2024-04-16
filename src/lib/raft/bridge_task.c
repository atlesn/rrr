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
#include "bridge_task.h"
#include "arena.h"

#include <string.h>

void rrr_raft_task_list_push (
		struct rrr_raft_task_list *list,
		struct rrr_raft_task *task
) {
	size_t capacity_new;
	struct rrr_raft_task *tasks;
	rrr_raft_arena_handle tasks_handle_new;

	if (list->count == list->capacity) {
		capacity_new = list->capacity + 4;
		tasks_handle_new = rrr_raft_arena_realloc (
				&list->arena,
				list->tasks,
				sizeof(*tasks) * capacity_new,
				sizeof(*tasks) * list->capacity
		);
		tasks = rrr_raft_arena_resolve(&list->arena, tasks_handle_new);

		memset(tasks + list->capacity, '\0', sizeof(*tasks) * (capacity_new - list->capacity));

		list->capacity = capacity_new;
		list->tasks = tasks_handle_new;
	}
	else {
		tasks = rrr_raft_arena_resolve(&list->arena, list->tasks);
	}

	tasks[list->count++] = *task;
}

void rrr_raft_task_list_cleanup (
		struct rrr_raft_task_list *list
) {
	rrr_raft_arena_cleanup(&list->arena);
}

struct rrr_raft_task *rrr_raft_task_list_get (
		struct rrr_raft_task_list *list
) {
	return rrr_raft_arena_resolve(&list->arena, list->tasks);
}

#define TASK_LIST_RESOLVE(handle) \
    (__rrr_raft_task_list_resolve(list, handle))

rrr_raft_arena_handle rrr_raft_task_list_strdup (
		struct rrr_raft_task_list *list,
		const char *str
) {
	struct rrr_raft_arena *arena = &list->arena;
	return rrr_raft_arena_strdup(arena, str);
}

rrr_raft_arena_handle rrr_raft_task_list_asprintf (
		struct rrr_raft_task_list *list,
		const char *format,
		...
) {
	static rrr_raft_arena_handle handle;
	va_list args;

	va_start(args, format);

	handle = rrr_raft_arena_vasprintf(&list->arena, format, args);

	va_end(args);

	return handle;
}
