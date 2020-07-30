/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CMODULE_DEFER_QUEUE_H
#define RRR_CMODULE_DEFER_QUEUE_H

#include "../util/linked_list.h"

struct rrr_message;
struct rrr_message_addr;

struct rrr_cmodule_deferred_message {
	RRR_LL_NODE(struct rrr_cmodule_deferred_message);
	struct rrr_message *msg;
	struct rrr_message_addr *msg_addr;
};

struct rrr_cmodule_deferred_message_collection {
	RRR_LL_HEAD(struct rrr_cmodule_deferred_message);
};

int rrr_cmodule_deferred_message_destroy (
		struct rrr_cmodule_deferred_message *msg
);
void rrr_cmodule_deferred_message_extract (
		struct rrr_message **message,
		struct rrr_message_addr **message_addr,
		struct rrr_cmodule_deferred_message *source
);
int rrr_cmodule_deferred_message_new_and_push (
		struct rrr_cmodule_deferred_message_collection *collection,
		struct rrr_message *msg,
		const struct rrr_message_addr *msg_addr
);

#endif /* RRR_CMODULE_DEFER_QUEUE */
