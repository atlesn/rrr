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

#include <string.h>

#include "bridge.h"
#include "bridge_ack.h"

#include "../util/rrr_time.h"

int rrr_raft_bridge_apply (
 		struct rrr_raft_bridge *bridge,
		void **data,
 		size_t data_size
) {
	int ret = 0;

//	raft_index index;
	struct raft_event event;
	struct raft_entry entry;

//	index = rrr_raft_get_last_index(&bridge->log);

	entry.type = RAFT_COMMAND;
	entry.term = bridge->metadata.term;
	if ((entry.batch = raft_malloc(data_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}
	memcpy(entry.batch, *data, data_size);
	entry.buf.base = entry.batch;
	entry.buf.len = data_size;

	event.type = RAFT_SUBMIT;
	event.time = RRR_RAFT_TIME_MS();
	event.submit.entries = &entry;
	event.submit.n = 1;

	if ((ret = rrr_raft_bridge_ack_step (bridge, &event)) != 0) {
		goto out;
	}

	out:
	return ret;
}
