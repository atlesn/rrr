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

#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "../global.h"
#include "senders.h"
#include "instances.h"

void senders_init (struct instance_sender_collection *collection) {
	memset(collection, '\0', sizeof(*collection));
}

int senders_check_empty (struct instance_sender_collection *collection) {
	return (collection->first_sender == NULL);
}

int senders_check_exists (struct instance_sender_collection *collection, struct instance_metadata *sender) {
	int ret = 0;
	RRR_SENDER_LOOP(test,collection) {
		if (test->sender == sender) {
			ret = 1;
			break;
		}
	}

	return ret;
}

int senders_add_sender (struct instance_sender_collection *collection, struct instance_metadata *sender) {
	int ret = 0;

	if (senders_check_exists(collection,sender)) {
		VL_MSG_ERR("Sender %s was specified twice\n", sender->dynamic_data->instance_name);
		ret = 1;
		goto out;
	}

	struct instance_sender *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory in __add_to_sender_collection\n");
		ret = 1;
		goto out;
	}

	entry->next = collection->first_sender;
	entry->sender = sender;

	collection->first_sender = entry;

	out:
	return ret;
}

void senders_clear (struct instance_sender_collection *collection) {
	struct instance_sender *sender;
	struct instance_sender *next;

	for (sender = collection->first_sender; sender != NULL; sender = next) {
		next = sender->next;
		free(sender);
	}
	collection->first_sender = NULL;
}

int senders_count (struct instance_sender_collection *collection) {
	int ret = 0;
	for (struct instance_sender *sender = collection->first_sender; sender != NULL; sender = sender->next) {
		ret++;
	}
	return ret;
}

int senders_iterate (
		struct instance_sender_collection *collection,
		int (*callback)(struct instance_metadata *sender, void *arg),
		void *arg
) {
	int ret = 0;
	for (struct instance_sender *sender = collection->first_sender; sender != NULL; sender = sender->next) {
		ret = callback(sender->sender, arg);
		if (ret != 0) {
			break;
		}
	}
	return ret;
}
