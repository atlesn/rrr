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
#include "ip_buffer_entry_util.h"

static int __poll_collection_entry_destroy(struct rrr_poll_collection_entry *entry) {
	free(entry);
	return 0;
}

void rrr_poll_collection_clear (
		struct rrr_poll_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_poll_collection_entry, __poll_collection_entry_destroy(node));
}

void rrr_poll_collection_clear_void (
		void *data
) {
	rrr_poll_collection_clear((struct rrr_poll_collection *) data);
}

int rrr_poll_collection_new (
		struct rrr_poll_collection **target
) {
	*target = NULL;

	struct rrr_poll_collection *collection = malloc(sizeof(*collection));
	if (collection == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_poll_collection_new\n");
		return 1;
	}
	memset(collection, '\0', sizeof(*collection));

	*target = collection;

	return 0;
}

void rrr_poll_collection_destroy (
		struct rrr_poll_collection *collection
) {
	rrr_poll_collection_clear(collection);
	free(collection);
}

void rrr_poll_collection_destroy_void (
		void *data
) {
	rrr_poll_collection_destroy(data);
}

int rrr_poll_collection_add (
		unsigned int *flags_result,
		struct rrr_poll_collection *collection,
		struct rrr_instance_metadata *instance
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
	struct rrr_instance_metadata *faulty_instance;
};

static int __poll_collection_add_from_senders_callback (
		struct rrr_instance_metadata *instance,
		void *arg
) {
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

int rrr_poll_do_poll_discard (
		int *discarded_count,
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *collection
) {
	int ret = 0;

	(void)(thread_data);

	*discarded_count = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
		int ret_tmp;

		struct rrr_poll_collection_entry *entry = node;

		int discarded_count_tmp = 0;

		ret_tmp = rrr_message_broker_poll_discard (
				&discarded_count_tmp,
				INSTANCE_D_BROKER_ARGS(entry->thread_data)
		);

		(*discarded_count) += discarded_count_tmp;

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

struct rrr_poll_delete_topic_filtering_callback_data {
	struct rrr_instance_thread_data *thread_data;
	int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
};

static int __rrr_poll_delete_topic_filtering_callback (
		RRR_MODULE_POLL_CALLBACK_SIGNATURE
) {
	struct rrr_poll_delete_topic_filtering_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	int does_match = 0;

	if (rrr_ip_buffer_entry_util_message_topic_match(&does_match, entry, INSTANCE_D_TOPIC(callback_data->thread_data)) != 0) {
		RRR_MSG_0("Error while matching topic against topic filter while polling in instance %s\n",
				INSTANCE_D_NAME(callback_data->thread_data));
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	RRR_MSG_3("Result of topic match while polling in instance %s: %s\n",
			INSTANCE_D_NAME(callback_data->thread_data), (does_match ? "MATCH" : "MISMATCH/DROPPED"));

	if (does_match) {
		// Callback unlocks, !! DO NOT continue to out, RETURN HERE !!
		return callback_data->callback(entry, callback_data->thread_data);
	}

	out:
	rrr_ip_buffer_entry_util_unlock(entry);
	return ret;
}

int rrr_poll_do_poll_delete (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *collection,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int wait_milliseconds
) {
	int ret = 0;

	// Small optimization, skip topic filtering callback when filtering is not active

	int (*callback_to_use)(RRR_MODULE_POLL_CALLBACK_SIGNATURE) = callback;
	void *callback_arg = thread_data;

	struct rrr_poll_delete_topic_filtering_callback_data filter_callback_data;

	if (thread_data->init_data.topic_first_token != NULL) {
		filter_callback_data.callback = callback;
		filter_callback_data.thread_data = thread_data;

		callback_to_use = __rrr_poll_delete_topic_filtering_callback;
		callback_arg = &filter_callback_data;
	}

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_poll_collection_entry);
		int ret_tmp;

		struct rrr_poll_collection_entry *entry = node;

		ret_tmp = rrr_message_broker_poll_delete (
				INSTANCE_D_BROKER_ARGS(entry->thread_data),
				callback_to_use,
				callback_arg,
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

int rrr_poll_collection_count (
		struct rrr_poll_collection *collection
) {
	return collection->node_count;
}

static int __rrr_poll_collection_add_from_senders (
		struct rrr_poll_collection *poll_collection,
		struct rrr_instance_metadata **faulty_instance,
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

void rrr_poll_add_from_thread_senders (
		struct rrr_poll_collection *collection,
		struct rrr_instance_thread_data *thread_data
) {
	struct rrr_instance_metadata *faulty_sender;
	__rrr_poll_collection_add_from_senders(collection, &faulty_sender, thread_data->init_data.senders);
}

