/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_INSTANCE_FRIENDS_H
#define RRR_INSTANCE_FRIENDS_H

#include "util/linked_list.h"

struct rrr_instance; /* From instances.h */

struct rrr_instance_friend {
	RRR_LL_NODE(struct rrr_instance_friend);
	struct rrr_instance *instance;
};

struct rrr_instance_friend_collection {
	RRR_LL_HEAD(struct rrr_instance_friend);
};

int rrr_instance_friend_collection_check_empty (struct rrr_instance_friend_collection *collection);
int rrr_instance_friend_collection_check_exists (struct rrr_instance_friend_collection *collection, struct rrr_instance *sender);
int rrr_instance_friend_collection_append (struct rrr_instance_friend_collection *collection, struct rrr_instance *sender);
void rrr_instance_friend_collection_clear (struct rrr_instance_friend_collection *collection);
int rrr_instance_friend_collection_count (struct rrr_instance_friend_collection *collection);
int rrr_instance_friend_collection_iterate (
		struct rrr_instance_friend_collection *collection,
		int (*callback)(struct rrr_instance *instance, void *arg),
		void *arg
);

#endif /* RRR_INSTANCE_FRIENDS_H */
