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

struct rrr_raft_task *rrr_raft_task_list_push (
		struct rrr_raft_task_list *list,
		const struct rrr_raft_task *task
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

	tasks[list->count] = *task;

	return &tasks[list->count++];
}

#define PTR_FROM_OFFSET(oe, o, n)                     \
    (void *) n + ((void *) oe - (void *) o);          \
    assert((void *) oe < (void *) o + sizeof(*o) &&   \
    (void *) oe > (void *) o)

void rrr_raft_task_list_push_cloned (
		struct rrr_raft_task_list *list_dst,
		const struct rrr_raft_task_list *list_src,
		const struct rrr_raft_task *task_src,
		const struct rrr_raft_task_cb_data *cb_data,
		const rrr_raft_arena_handle *data_src,
		const size_t *data_size_src
) {
	struct rrr_raft_task *task_dst;
	struct rrr_raft_task_cb_data *cb_data_dst;
	rrr_raft_arena_handle *data_src_dst;
	size_t *data_size_dst;

	task_dst = rrr_raft_task_list_push(list_dst, task_src);

	cb_data_dst = PTR_FROM_OFFSET(cb_data, task_src, task_dst);
	*cb_data_dst = *cb_data;

	data_src_dst = PTR_FROM_OFFSET(data_src, task_src, task_dst);
	*data_src_dst = rrr_raft_arena_alloc(&list_dst->arena, *data_size_src);

	memcpy (
			rrr_raft_arena_resolve(&list_dst->arena, *data_src_dst),
			rrr_raft_arena_resolve_const(&list_src->arena, *data_src),
			*data_size_src
	);

	data_size_dst = PTR_FROM_OFFSET(data_size_src, task_src, task_dst);
	*data_size_dst = *data_size_src;
}

void *rrr_raft_task_list_push_and_allocate_data (
		struct rrr_raft_task_list *list,
		const struct rrr_raft_task *task,
		const rrr_raft_arena_handle *data,
		size_t data_size
) {
	rrr_raft_arena_handle *data_new;
	struct rrr_raft_task *task_new;

	assert((void *) data < (void *) task + sizeof(*task) &&
	       (void *) data > (void *) task);

	task_new = rrr_raft_task_list_push(list, task);

	data_new = PTR_FROM_OFFSET(data, task, task_new);
	*data_new = rrr_raft_arena_alloc(&list->arena, data_size);

	return rrr_raft_arena_resolve(&list->arena, *data_new);
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
