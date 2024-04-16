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

#ifndef RRR_RAFT_BRIDGE_H
#define RRR_RAFT_BRIDGE_H

#include "arena.h"
#include "log.h"

#include <raft.h>

#include <stdint.h>
#include <stdio.h>

#define RRR_RAFT_FILE_NAME_TEMPLATE_CLOSED_SEGMENT "%016llu-%016llu"
#define RRR_RAFT_FILE_NAME_PREFIX_METADATA "metadata"

#define RRR_RAFT_FILE_ARGS_CLOSED_SEGMENT(from, to) \
    RRR_RAFT_FILE_NAME_TEMPLATE_CLOSED_SEGMENT, (unsigned long long) from, (unsigned long long) to

#define RRR_RAFT_DISK_FORMAT 1 /* Same format as C-raft */

#define RRR_RAFT_BRIDGE_DBG_ARGS(msg, ...) \
    RRR_DBG_3("Raft [%i][bridge] " msg "\n", bridge->server_id, __VA_ARGS__)

#define RRR_RAFT_BRIDGE_DBG(msg) \
    RRR_DBG_3("Raft [%i][bridge] " msg "\n", bridge->server_id)

enum rrr_raft_task_type {
	RRR_RAFT_TASK_TIMEOUT = 1,
	RRR_RAFT_TASK_READ_FILE = 2,
	RRR_RAFT_TASK_BOOTSTRAP = 3,
	RRR_RAFT_TASK_WRITE_FILE = 4
};

enum rrr_raft_file_type {
	RRR_RAFT_FILE_TYPE_CONFIGURATION = 1,
	RRR_RAFT_FILE_TYPE_METADATA = 2
};

struct rrr_raft_task_cb_data {
	void *ptr;
	union {
		char data[sizeof(uint64_t) * 3];
	};
};

#define RRR_RAFT_BRIDGE_READFILE_CB_ARGS \
    const char *name, char *buf, size_t buf_size, struct rrr_raft_task_cb_data *cb_data

#define RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS \
    const char *name, const char *data, size_t data_size, struct rrr_raft_task_cb_data *cb_data

struct rrr_raft_task {
	enum rrr_raft_task_type type;
	union {
		struct {
			uint64_t time;
		} timeout;
		struct {
			enum rrr_raft_file_type type;
			rrr_raft_arena_handle name;
			// Set by implementation if file exists and called upon acknowledge
			// until it returns 0 which means completion
			ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS);
			struct rrr_raft_task_cb_data cb_data;
		} readfile;
		struct {
			struct raft_configuration *configuration;
		} bootstrap;
		struct {
			enum rrr_raft_file_type type;
			rrr_raft_arena_handle name;
			// Set by implementation and called upon acknowledge
			// multiple times and the last time with 0 size which means completion
			ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS);
			struct rrr_raft_task_cb_data cb_data;
		} writefile;
	};
};

struct rrr_raft_task_list {
	struct rrr_raft_arena arena;
	rrr_raft_arena_handle tasks;
	size_t count;
	size_t capacity;
};

enum rrr_raft_bridge_state {
	RRR_RAFT_BRIDGE_STATE_STARTED = 1,
	RRR_RAFT_BRIDGE_STATE_CONFIGURED
};

struct rrr_raft_bridge_metadata {
	unsigned long long version;
	raft_term term;
	raft_id voted_for;
};

struct rrr_raft_bridge {
	struct raft *raft;
	int server_id;
	enum rrr_raft_bridge_state state;
	struct rrr_raft_bridge_metadata metadata;
	struct raft_configuration configuration;
	struct rrr_raft_log log;
	raft_index last_applied;
	raft_index snapshot_index;
};

int rrr_raft_bridge_begin (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
);
int rrr_raft_bridge_acknowledge (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
);
void rrr_raft_bridge_cleanup (
		struct rrr_raft_bridge *bridge
);
int rrr_raft_bridge_is_leader (
		const struct rrr_raft_bridge *bridge
);
void rrr_raft_bridge_get_leader (
		raft_id *id,
		const char **address,
		const struct rrr_raft_bridge *bridge
);
int rrr_raft_bridge_configuration_iterate (
		const struct rrr_raft_bridge *bridge,
		int (*cb)(raft_id server_id, const char *server, int role, int catch_up, void *arg),
		void *cb_arg
);

#endif /* RRR_RAFT_BRIDGE_H */
