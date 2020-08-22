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

#ifndef RRR_MESSAGE_HOLDER_COLLECTION_H
#define RRR_MESSAGE_HOLDER_COLLECTION_H

#include "../util/linked_list.h"

struct rrr_msg_holder;

struct rrr_msg_msg_holder_collection {
	RRR_LL_HEAD(struct rrr_msg_holder);
};

void rrr_msg_holder_collection_clear (
		struct rrr_msg_msg_holder_collection *collection
);
void rrr_msg_holder_collection_clear_void (
		void *arg
);
void rrr_msg_holder_collection_sort (
		struct rrr_msg_msg_holder_collection *target,
		int (*compare)(void *message_a, void *message_b)
);

#endif /* RRR_MESSAGE_HOLDER_COLLECTION_H */
