/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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
#include <stdlib.h>
#include <stddef.h>

#include "instance_friends.h"

#include "log.h"
#include "instances.h"
#include "allocator.h"

int rrr_instance_friend_collection_check_empty (
		const struct rrr_instance_friend_collection *collection
) {
	return RRR_LL_IS_EMPTY(collection);
}

int rrr_instance_friend_collection_check_exists (
		const struct rrr_instance_friend_collection *collection,
		const struct rrr_instance *sender
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_friend);
		if (node->instance == sender) {
			return 1;
		}
	RRR_LL_ITERATE_END();

	return 0;
}

void rrr_instance_friend_collection_remove (
		struct rrr_instance_friend_collection *collection,
		struct rrr_instance *sender
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_friend);
		if (node->instance == sender) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_free(node));
}

int rrr_instance_friend_collection_append (
		struct rrr_instance_friend_collection *collection,
		struct rrr_instance *sender,
		void *parameter
) {
	int ret = 0;

	if (rrr_instance_friend_collection_check_exists(collection,sender)) {
		RRR_MSG_0("Sender %s was specified twice\n", sender->module_data->instance_name);
		ret = 1;
		goto out;
	}

	struct rrr_instance_friend *entry = rrr_allocate(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));
	entry->instance = sender;
	entry->parameter = parameter;

	RRR_LL_APPEND(collection, entry);

	out:
	return ret;
}

int rrr_instance_friend_collection_append_from (
		struct rrr_instance_friend_collection *target,
		const struct rrr_instance_friend_collection *source
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(source, struct rrr_instance_friend);
		if ((ret = rrr_instance_friend_collection_append (target, node->instance, node->parameter)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

void rrr_instance_friend_collection_clear (
		struct rrr_instance_friend_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_instance_friend, rrr_free(node));
}

int rrr_instance_friend_collection_count (
		const struct rrr_instance_friend_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

int rrr_instance_friend_collection_iterate (
		struct rrr_instance_friend_collection *collection,
		int (*callback)(struct rrr_instance *instance, void *parameter, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_friend);
		ret = callback(node->instance, node->parameter, arg);
		if (ret != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_instance_friend_collection_iterate_const (
		const struct rrr_instance_friend_collection *collection,
		int (*callback)(const struct rrr_instance *instance, void *parameter, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_instance_friend);
		ret = callback(node->instance, node->parameter, arg);
		if (ret != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}
