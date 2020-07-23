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

#include <stdlib.h>
#include <string.h>

#include "cmodule_defer_queue.h"

#include "../log.h"
#include "../message_addr.h"
#include "../linked_list.h"
#include "../macro_utils.h"

int rrr_cmodule_deferred_message_destroy (
		struct rrr_cmodule_deferred_message *msg
) {
	RRR_FREE_IF_NOT_NULL(msg->msg);
	RRR_FREE_IF_NOT_NULL(msg->msg_addr);
	free(msg);
	return 0;
}

void rrr_cmodule_deferred_message_extract (
		struct rrr_message **message,
		struct rrr_message_addr **message_addr,
		struct rrr_cmodule_deferred_message *source
) {
	*message = source->msg;
	*message_addr = source->msg_addr;
	source->msg = NULL;
	source->msg_addr = NULL;
}

int rrr_cmodule_deferred_message_new_and_push (
		struct rrr_cmodule_deferred_message_collection *collection,
		struct rrr_message *msg,
		const struct rrr_message_addr *msg_addr
) {
	int ret = 0;

	struct rrr_cmodule_deferred_message *node = NULL;
	struct rrr_message_addr *msg_addr_tmp = NULL;

	if ((ret = rrr_message_addr_clone(&msg_addr_tmp, msg_addr)) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_cmodule_deferred_message_push\n");
		goto out;
	}

	if ((node = malloc(sizeof(*node))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_cmodule_deferred_message_push\n");
		goto out;
	}

	memset(node, '\0', sizeof(*node));

	node->msg = msg;
	node->msg_addr = msg_addr_tmp;
	msg_addr_tmp = NULL;

	RRR_LL_APPEND(collection, node);
	node = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg_addr_tmp);
	if (node != NULL) {
		rrr_cmodule_deferred_message_destroy(node);
	}
	return ret;
}
