/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "ip_buffer_entry_collection.h"
#include "ip_buffer_entry_struct.h"
#include "ip_buffer_entry.h"

#include "log.h"
#include "linked_list.h"

void rrr_ip_buffer_entry_collection_clear (
		struct rrr_ip_buffer_entry_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_ip_buffer_entry, rrr_ip_buffer_entry_decref(node));
}

void rrr_ip_buffer_entry_collection_clear_void (
		void *arg
) {
	rrr_ip_buffer_entry_collection_clear(arg);
}

void rrr_ip_buffer_entry_collection_sort (
		struct rrr_ip_buffer_entry_collection *target,
		int (*compare)(void *message_a, void *message_b)
) {
	struct rrr_ip_buffer_entry_collection tmp = {0};

	// TODO : This is probably a bad sorting algorithm

	while (RRR_LL_COUNT(target) != 0) {
		struct rrr_ip_buffer_entry *smallest = RRR_LL_FIRST(target);
		RRR_LL_ITERATE_BEGIN(target, struct rrr_ip_buffer_entry);
			if (compare(node->message, smallest->message) < 0) {
				smallest = node;
			}
		RRR_LL_ITERATE_END();

		RRR_LL_REMOVE_NODE_NO_FREE(target, smallest);
		RRR_LL_APPEND(&tmp, smallest);
	}

	*target = tmp;
}
