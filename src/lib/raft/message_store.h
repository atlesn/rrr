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

#ifndef RRR_RAFT_MESSAGE_STORE_H
#define RRR_RAFT_MESSAGE_STORE_H

#include <stddef.h>

#include "common.h"

struct rrr_raft_message_store;
struct rrr_msg_msg;

int rrr_raft_message_store_new (
		struct rrr_raft_message_store **result,
		int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
);
void rrr_raft_message_store_destroy (
		struct rrr_raft_message_store *store
);
int rrr_raft_message_store_get (
		struct rrr_msg_msg **msg,
		const struct rrr_raft_message_store *store,
		const char *topic,
		size_t topic_length
);
int rrr_raft_message_store_push (
		int *was_found,
		struct rrr_raft_message_store *store,
		const struct rrr_msg_msg *msg_orig
);
size_t rrr_raft_message_store_count (
		const struct rrr_raft_message_store *store
);
int rrr_raft_message_store_iterate (
		const struct rrr_raft_message_store *store,
		int (*callback)(const struct rrr_msg_msg *msg, void *arg),
		void *callback_arg
);

#endif /* RRR_RAFT_MESSAGE_STORE_H */
