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

#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "poll_helper.h"
#include "instances.h"
#include "buffer.h"
#include "message_broker.h"

static int __poll_collection_entry_destroy(struct poll_collection_entry *entry) {
	free(entry);
	return 0;
}

void poll_collection_clear(struct poll_collection *collection) {
	RRR_LL_DESTROY(collection,struct poll_collection_entry, __poll_collection_entry_destroy(node));
}

void poll_collection_clear_void(void *data) {
	poll_collection_clear((struct poll_collection *) data);
}

void poll_collection_init(struct poll_collection *collection) {
	memset(collection, '\0', sizeof(*collection));
}


void poll_collection_remove (struct poll_collection *collection, struct rrr_instance_thread_data *find) {
	int found = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct poll_collection_entry);
		if (node->thread_data == find) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
			found = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __poll_collection_entry_destroy(node));

	if (found != 1) {
		RRR_BUG("BUG: Tried to remove non-existent entry from poll collection\n");
	}
}

int poll_collection_has (struct poll_collection *collection, struct rrr_instance_thread_data *find) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct poll_collection_entry);
		if (node->thread_data == find) {
			RRR_LL_ITERATE_LAST();
			ret = 1;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int poll_collection_add (
		unsigned int *flags_result,
		struct poll_collection *collection,
		struct instance_metadata *instance
) {
	int ret = 0;
	*flags_result = 0;

	struct poll_collection_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_ERR("Could not allocate memory inn poll_collection_add\n");
		ret = RRR_POLL_ERR;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	entry->thread_data = instance->thread_data;

	RRR_LL_APPEND(collection, entry);
	entry = NULL;

	out:
	if (entry != NULL) {
		__poll_collection_entry_destroy(entry);
	}

	return ret;
}

struct poll_callback_data {
	struct poll_collection *collection;
	struct instance_metadata *faulty_instance;
};

int __poll_collection_add_from_senders_callback (struct instance_metadata *instance, void *arg) {
	int ret = 0;

	struct poll_callback_data *data = arg;

	unsigned int flags_result;

	ret = poll_collection_add (&flags_result, data->collection, instance);

	if (ret == RRR_POLL_NOT_FOUND) {
		data->faulty_instance = instance;
		ret = 1;
	}
	else if (ret != 0) {
		RRR_MSG_ERR("Error while adding senders to collection in __poll_collection_add_from_senders_callback\n");
		ret = 1;
	}

	return ret;
}

int poll_collection_add_from_senders (
		struct poll_collection *poll_collection,
		struct instance_metadata **faulty_instance,
		struct rrr_instance_collection *senders
) {
	*faulty_instance = NULL;

	struct poll_callback_data callback_data;
	callback_data.collection = poll_collection;
	callback_data.faulty_instance = NULL;

	int ret = rrr_instance_collection_iterate(senders, &__poll_collection_add_from_senders_callback, &callback_data);

	if (ret != 0) {
		*faulty_instance = callback_data.faulty_instance;
	}

	return ret;
}
/*
#define RRR_MODULE_POLL_SIGNATURE \
		struct instance_thread_data *data, \
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE), \
		struct fifo_callback_args *poll_data
*/

int poll_do_poll (
		struct rrr_instance_thread_data *thread_data,
		struct poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct poll_collection_entry);
		int ret_tmp;

		struct poll_collection_entry *entry = node;

		ret_tmp = rrr_message_broker_poll(INSTANCE_D_BROKER(entry->thread_data), entry->handle, callback, thread_data, wait_milliseconds);

		if (ret_tmp != 1) {
			ret = 1;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int poll_do_poll_delete (
		struct rrr_instance_thread_data *thread_data,
		struct poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct poll_collection_entry);
		int ret_tmp;

		struct poll_collection_entry *entry = node;

		ret_tmp = rrr_message_broker_poll_delete (
				INSTANCE_D_BROKER(entry->thread_data),
				entry->handle,
				callback,
				thread_data,
				wait_milliseconds
		);

		if (	(ret_tmp & RRR_FIFO_CALLBACK_ERR) ==  RRR_FIFO_CALLBACK_ERR ||
				(ret_tmp & RRR_FIFO_GLOBAL_ERR) == RRR_FIFO_GLOBAL_ERR
		) {
			ret = 1;
			RRR_LL_ITERATE_BREAK();
		}
		else if (ret_tmp != 0) {
			RRR_BUG("BUG: Unknown return value %i when polling from module %s\n",
					ret_tmp, INSTANCE_D_MODULE_NAME(entry->thread_data));
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int poll_collection_count (struct poll_collection *collection) {
	return collection->node_count;
}

void poll_add_from_thread_senders (
		struct poll_collection *collection,
		struct rrr_instance_thread_data *thread_data
) {
	struct instance_metadata *faulty_sender;
	poll_collection_add_from_senders(collection, &faulty_sender, thread_data->init_data.senders);
}

void poll_remove_senders_also_in (
		struct poll_collection *target,
		const struct poll_collection *source
) {
	RRR_LL_ITERATE_BEGIN(source, const struct poll_collection_entry);
		const struct rrr_instance_thread_data *to_find = node->thread_data;
		RRR_LL_ITERATE_BEGIN(target, struct poll_collection_entry);
			if (node->thread_data == to_find) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY(target, __poll_collection_entry_destroy(node));
	RRR_LL_ITERATE_END();
}
