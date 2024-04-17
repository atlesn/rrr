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

#ifndef RRR_RAFT_TASK_H
#define RRR_RAFT_TASK_H

static inline void *rrr_raft_task_list_resolve (
		struct rrr_raft_task_list *list,
		rrr_raft_arena_handle handle
) {
	return rrr_raft_arena_resolve(&list->arena, handle);
}

struct rrr_raft_task *rrr_raft_task_list_push (
		struct rrr_raft_task_list *list,
		const struct rrr_raft_task *task
);
void rrr_raft_task_list_push_cloned (
		struct rrr_raft_task_list *list_dst,
		const struct rrr_raft_task_list *list_src,
		const struct rrr_raft_task *task_src,
		const struct rrr_raft_task_cb_data *cb_data,
		const rrr_raft_arena_handle *data_src,
		const size_t *data_size_src
);
void *rrr_raft_task_list_push_and_allocate_data (
		struct rrr_raft_task_list *list,
		const struct rrr_raft_task *task,
		const rrr_raft_arena_handle *data,
		size_t data_size
);
void rrr_raft_task_list_cleanup (
		struct rrr_raft_task_list *list
);
struct rrr_raft_task *rrr_raft_task_list_get (
		struct rrr_raft_task_list *list
);
rrr_raft_arena_handle rrr_raft_task_list_strdup (
		struct rrr_raft_task_list *list,
		const char *str
);
rrr_raft_arena_handle rrr_raft_task_list_asprintf (
		struct rrr_raft_task_list *list,
		const char *format,
		...
);

#endif /* RRR_RAFT_TASK_H */
