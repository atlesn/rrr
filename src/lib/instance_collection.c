/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "instance_collection.h"

#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "../global.h"
#include "instances.h"

int rrr_instance_collection_check_empty (struct rrr_instance_collection *collection) {
	return RRR_LL_IS_EMPTY(collection);
}

int rrr_instance_collection_check_exists (struct rrr_instance_collection *collection, struct instance_metadata *sender) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_collection_entry);
		if (node->instance == sender) {
			return 1;
		}
	RRR_LL_ITERATE_END();

	return 0;
}

int rrr_instance_collection_append (struct rrr_instance_collection *collection, struct instance_metadata *sender) {
	int ret = 0;

	if (rrr_instance_collection_check_exists(collection,sender)) {
		RRR_MSG_ERR("Sender %s was specified twice\n", sender->dynamic_data->instance_name);
		ret = 1;
		goto out;
	}

	struct rrr_instance_collection_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_ERR("Could not allocate memory in senders_add_sender\n");
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));
	entry->instance = sender;

	RRR_LL_APPEND(collection, entry);

	out:
	return ret;
}

void rrr_instance_collection_clear (struct rrr_instance_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_instance_collection_entry, free(node));
}

int rrr_instance_collection_count (struct rrr_instance_collection *collection) {
	return RRR_LL_COUNT(collection);
}

int rrr_instance_collection_iterate (
		struct rrr_instance_collection *collection,
		int (*callback)(struct instance_metadata *instance, void *arg),
		void *arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_instance_collection_entry);
		ret = callback(node->instance, arg);
		if (ret != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}
