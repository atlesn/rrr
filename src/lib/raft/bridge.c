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
#include "log.h"

#include "../log.h"

int rrr_raft_bridge_begin (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	struct rrr_raft_task task;

	assert(list->count == 0);

	assert (!(bridge->state & RRR_RAFT_BRIDGE_STATE_STARTED));

	RRR_RAFT_BRIDGE_DBG("starting, requesting metadata to be loaded from disk");

	task.type = RRR_RAFT_TASK_READ_FILE;
	task.readfile.type = RRR_RAFT_FILE_TYPE_METADATA;
	task.readfile.name = rrr_raft_task_list_strdup(list, RRR_RAFT_FILE_NAME_PREFIX_METADATA "1");
	rrr_raft_task_list_push(list, &task);

	task.type = RRR_RAFT_TASK_READ_FILE;
	task.readfile.type = RRR_RAFT_FILE_TYPE_METADATA;
	task.readfile.name = rrr_raft_task_list_strdup(list, RRR_RAFT_FILE_NAME_PREFIX_METADATA "2");
	rrr_raft_task_list_push(list, &task);

	goto out;

	out:
	return ret;
}

void rrr_raft_bridge_cleanup (
		struct rrr_raft_bridge *bridge
) {
	raft_configuration_close(&bridge->configuration);
	rrr_raft_log_cleanup(&bridge->log);
}

int rrr_raft_bridge_is_leader (
		const struct rrr_raft_bridge *bridge
) {
	return bridge->raft->state == RAFT_LEADER;
}

void rrr_raft_bridge_get_leader (
		raft_id *id,
		const char **address,
		const struct rrr_raft_bridge *bridge
) {
	raft_leader(bridge->raft, id, address);
}

int rrr_raft_bridge_configuration_iterate (
		const struct rrr_raft_bridge *bridge,
		int (*cb)(raft_id server_id, const char *server, int role, int catch_up, void *arg),
		void *cb_arg
) {
	int ret = 0;

	unsigned i;
	int catch_up, ret_tmp;
	struct raft_server *server;

	for (i = 0; i < bridge->raft->configuration.n; i++) {
		server = bridge->raft->configuration.servers + i;

		if (rrr_raft_bridge_is_leader(bridge)) {
			if ((ret_tmp = raft_catch_up(bridge->raft, server->id, &catch_up)) != 0) {
				RRR_MSG_0("Failed to get catch up status for server %llu in %s: %s\n",
					server->id, __func__, raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}
		}
		else {
			catch_up = -1;
		}

		if ((ret = cb(server->id, server->address, server->role, catch_up, cb_arg)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}
