/*

Read Route Record

Copyright (C) 2018-2023 Atle Solbakken atle@goliathdns.no

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

#include "../log.h"
#include "../allocator.h"
#include "../random.h"

#include "message_holder_collection.h"
#include "message_holder_struct.h"
#include "message_holder.h"

#include "../util/linked_list.h"

void rrr_msg_holder_collection_clear (
		struct rrr_msg_holder_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_msg_holder, rrr_msg_holder_decref(node));
}

void rrr_msg_holder_collection_clear_void (
		void *arg
) {
	rrr_msg_holder_collection_clear(arg);
}

void rrr_msg_holder_collection_sort (
		struct rrr_msg_holder_collection *target,
		int do_lock,
		int (*compare)(
				const struct rrr_msg_holder *a,
				const struct rrr_msg_holder *b
		)
) {
	struct rrr_msg_holder_collection tmp = {0};

	if (do_lock) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_msg_holder);
			rrr_msg_holder_lock(node);
		RRR_LL_ITERATE_END();
	}

	while (RRR_LL_COUNT(target) != 0) {
		struct rrr_msg_holder *smallest = RRR_LL_FIRST(target);
		RRR_LL_ITERATE_BEGIN(target, struct rrr_msg_holder);
			if (compare(node, smallest) < 0) {
				smallest = node;
			}
		RRR_LL_ITERATE_END();

		RRR_LL_REMOVE_NODE_NO_FREE(target, smallest);
		RRR_LL_APPEND(&tmp, smallest);
	}

	if (do_lock) {
		// All nodes now in tmp list
		RRR_LL_ITERATE_BEGIN(&tmp, struct rrr_msg_holder);
			rrr_msg_holder_unlock(node);
		RRR_LL_ITERATE_END();
	}

	*target = tmp;
}

void rrr_msg_holder_collection_rotate (
		struct rrr_msg_holder_collection *target,
		int pos,
		int do_lock
) {
	if (do_lock) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_msg_holder);
			rrr_msg_holder_lock(node);
		RRR_LL_ITERATE_END();
	}

	RRR_LL_ROTATE(target, struct rrr_msg_holder, pos);

	if (do_lock) {
		RRR_LL_ITERATE_BEGIN(target, struct rrr_msg_holder);
			rrr_msg_holder_unlock(node);
		RRR_LL_ITERATE_END();
	}
}
