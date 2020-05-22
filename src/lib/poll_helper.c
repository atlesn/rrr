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

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "poll_helper.h"
#include "instances.h"
#include "buffer.h"
#include "message_broker.h"

static int __poll_collection_entry_destroy(struct rrr_poll_collection_entry *entry) {
	free(entry);
	return 0;
}

void rrr_poll_collection_clear(struct rrr_poll_collection *collection) {
	RRR_LL_DESTROY(collection,struct rrr_poll_collection_entry, __poll_collection_entry_destroy(node));
}

void rrr_poll_collection_clear_void(void *data) {
	rrr_poll_collection_clear((struct rrr_poll_collection *) data);
}

void rrr_poll_collection_init(struct rrr_poll_collection *collection) {
	memset(collection, '\0', sizeof(*collection));
}


void rrr_poll_collection_remove (struct rrr_poll_collection *collection, struct rrr_instance_thread_data *find) {
	int found = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
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

int rrr_poll_collection_has (struct rrr_poll_collection *collection, struct rrr_instance_thread_data *find) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
		if (node->thread_data == find) {
			RRR_LL_ITERATE_LAST();
			ret = 1;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_poll_collection_add (
		unsigned int *flags_result,
		struct rrr_poll_collection *collection,
		struct instance_metadata *instance
) {
	int ret = 0;
	*flags_result = 0;

	struct rrr_poll_collection_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate memory inn rrr_poll_collection_add\n");
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
	struct rrr_poll_collection *collection;
	struct instance_metadata *faulty_instance;
};

int __poll_collection_add_from_senders_callback (struct instance_metadata *instance, void *arg) {
	int ret = 0;

	struct poll_callback_data *data = arg;

	unsigned int flags_result;

	ret = rrr_poll_collection_add (&flags_result, data->collection, instance);

	if (ret == RRR_POLL_NOT_FOUND) {
		data->faulty_instance = instance;
		ret = 1;
	}
	else if (ret != 0) {
		RRR_MSG_0("Error while adding senders to collection in __poll_collection_add_from_senders_callback\n");
		ret = 1;
	}

	return ret;
}

int rrr_poll_collection_add_from_senders (
		struct rrr_poll_collection *poll_collection,
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

/*
 * DISABLED, NOT USED
int poll_do_poll (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
		int ret_tmp;

		struct rrr_poll_collection_entry *entry = node;

		ret_tmp = rrr_message_broker_poll (
				INSTANCE_D_BROKER_ARGS(entry->thread_data),
				callback,
				thread_data,
				wait_milliseconds
		);

		if (ret_tmp != 1) {
			ret = 1;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}
*/
int rrr_poll_do_poll_delete (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
		int ret_tmp;

		struct rrr_poll_collection_entry *entry = node;

		ret_tmp = rrr_message_broker_poll_delete (
				INSTANCE_D_BROKER_ARGS(entry->thread_data),
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

int rrr_poll_collection_count (struct rrr_poll_collection *collection) {
	return collection->node_count;
}

void rrr_poll_add_from_thread_senders (
		struct rrr_poll_collection *collection,
		struct rrr_instance_thread_data *thread_data
) {
	struct instance_metadata *faulty_sender;
	rrr_poll_collection_add_from_senders(collection, &faulty_sender, thread_data->init_data.senders);
}

void rrr_poll_remove_senders_also_in (
		struct rrr_poll_collection *target,
		const struct rrr_poll_collection *source
) {
	RRR_LL_ITERATE_BEGIN(source, const struct rrr_poll_collection_entry);
		const struct rrr_instance_thread_data *to_find = node->thread_data;
		RRR_LL_ITERATE_BEGIN(target, struct rrr_poll_collection_entry);
			if (node->thread_data == to_find) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY(target, __poll_collection_entry_destroy(node));
	RRR_LL_ITERATE_END();
}
