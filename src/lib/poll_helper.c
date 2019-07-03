/*

Voltage Logger

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

void poll_collection_clear(struct poll_collection *collection) {
	struct poll_collection_entry *next;
	for (struct poll_collection_entry *entry = collection->first; entry != NULL; entry = next) {
		next = entry->next;
		free(entry);
	}

	collection->first = NULL;
}

void poll_collection_init(struct poll_collection *collection) {
	memset(collection, '\0', sizeof(*collection));
}

void poll_collection_remove (struct poll_collection *collection, struct instance_thread_data *find) {
	struct poll_collection_entry *entry = NULL;
	struct poll_collection_entry *prev_entry = NULL;
	POLL_COLLECTION_LOOP(test,collection) {
		if (test->thread_data == find) {
			entry = test;
			break;
		}
		prev_entry = test;
	}

	if (entry == NULL) {
		VL_MSG_ERR("BUG: Tried to remove non-existent entry from poll collection\n");
		exit(EXIT_FAILURE);
	}

	if (collection->first != NULL && collection->first == entry) {
		collection->first = entry->next;
	}
	else {
		prev_entry->next = entry->next;
	}

	free(entry);
}

int poll_collection_has (struct poll_collection *collection, struct instance_thread_data *find) {
	int ret = 0;

	POLL_COLLECTION_LOOP(entry,collection) {
		if (entry->thread_data == find) {
			ret = 1;
			break;
		}
	}

	return ret;
}

int poll_collection_add (
		unsigned int *flags_result,
		struct poll_collection *collection,
		unsigned int flags,
		struct instance_metadata *instance
) {
	int ret = 0;
	*flags_result = 0;

	struct poll_collection_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory inn poll_collection_add\n");
		ret = RRR_POLL_ERR;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	int (*print)(RRR_MODULE_PRINT_SIGNATURE);
	int (*poll)(RRR_MODULE_POLL_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);
	int (*poll_delete_ip)(RRR_MODULE_POLL_SIGNATURE);

	print			= instance->dynamic_data->operations.print;
	poll			= instance->dynamic_data->operations.poll;
	poll_delete		= instance->dynamic_data->operations.poll_delete;
	poll_delete_ip	= instance->dynamic_data->operations.poll_delete_ip;

	if ((flags & RRR_POLL_PRINT) > 0 && print != NULL) {
		entry->print = print;
		*flags_result |= RRR_POLL_PRINT;
	}
	if ((flags & RRR_POLL_POLL) > 0 && poll != NULL) {
		entry->poll = poll;
		*flags_result |= RRR_POLL_POLL;
	}
	if ((flags & RRR_POLL_POLL_DELETE) > 0 && poll_delete != NULL) {
		entry->poll_delete = poll_delete;
		*flags_result |= RRR_POLL_POLL_DELETE;
	}
	if ((flags & RRR_POLL_POLL_DELETE_IP) > 0 && poll_delete_ip != NULL) {
		entry->poll_delete = poll_delete_ip;
		*flags_result |= RRR_POLL_POLL_DELETE_IP;
	}

	if (entry->print == NULL && entry->poll == NULL && entry->poll_delete == NULL) {
		ret = RRR_POLL_NOT_FOUND;
		goto out;
	}

	VL_DEBUG_MSG_1 ("Adding poll instance %s flags %u new flags %u\n", INSTANCE_M_NAME(instance), flags, *flags_result);
	entry->thread_data = instance->thread_data;
	entry->flags = *flags_result;
	entry->next = collection->first;
	collection->first = entry;

	out:

	if (ret != 0 && entry != NULL) {
		free(entry);
	}

	return ret;
}

struct poll_callback_data {
	struct poll_collection *collection;
	struct instance_metadata *faulty_instance;
	unsigned int flags;
};

int __poll_collection_add_from_senders_callback (struct instance_metadata *instance, void *arg) {
	int ret = 0;

	struct poll_callback_data *data = arg;

	unsigned int flags_result;

	ret = poll_collection_add (&flags_result, data->collection, data->flags, instance);

	if (ret == RRR_POLL_NOT_FOUND) {
		data->faulty_instance = instance;
		ret = 1;
	}
	else if (ret != 0) {
		VL_MSG_ERR("Error while adding senders to collection in __poll_collection_add_from_senders_callback\n");
		ret = 1;
	}

	return ret;
}

int poll_collection_add_from_senders (
		struct poll_collection *poll_collection,
		struct instance_metadata **faulty_instance,
		struct instance_sender_collection *senders,
		unsigned int flags
) {
	*faulty_instance = NULL;

	struct poll_callback_data callback_data;
	callback_data.collection = poll_collection;
	callback_data.flags = flags;
	callback_data.faulty_instance = NULL;

	int ret = senders_iterate(senders, &__poll_collection_add_from_senders_callback, &callback_data);

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
		struct poll_collection *collection,
		struct instance_thread_data **faulty_instance,
		unsigned int flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		const struct fifo_callback_args *poll_data
) {
	int ret = 0;
	*faulty_instance = NULL;

	POLL_COLLECTION_LOOP(entry,collection) {
		int ret_tmp;

		struct fifo_callback_args callback_args = *poll_data;
		if (RRR_POLL_POLL & flags & entry->flags) {
			ret_tmp = entry->poll(entry->thread_data, callback, &callback_args);
		}
		else {
			VL_MSG_ERR("BUG: Instance requesting poll function from sender which was not stored in poll_do_poll\n");
			ret = 1;
			break;
		}
		if (ret_tmp != 1) {
			*faulty_instance = entry->thread_data;
			ret = 1;
			if (flags & RRR_POLL_BREAK_ON_ERR) {
				break;
			}
		}
	}

	return ret;
}

int poll_do_poll_delete (
		struct poll_collection *collection,
		struct instance_thread_data **faulty_instance,
		unsigned int control_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		const struct fifo_callback_args *poll_data
) {
	int ret = 0;
	*faulty_instance = NULL;

	POLL_COLLECTION_LOOP(entry,collection) {
		int ret_tmp;

		struct fifo_callback_args callback_args = *poll_data;
		if (control_flags & entry->flags) {
			ret_tmp = entry->poll_delete(entry->thread_data, callback, &callback_args);
		}
		else {
			VL_MSG_ERR("BUG: Instance requesting poll function from sender which was not stored in poll_do_poll_delete\n");
			ret = 1;
			break;
		}
		if (ret_tmp == FIFO_CALLBACK_ERR || ret_tmp == FIFO_GLOBAL_ERR) {
			*faulty_instance = entry->thread_data;
			ret = 1;
			if (control_flags & RRR_POLL_BREAK_ON_ERR) {
				break;
			}
		}
		else if (ret_tmp != 0) {
			VL_MSG_ERR("BUG: Unknown return value %i when polling from module %s\n",
					ret_tmp, INSTANCE_D_MODULE_NAME(entry->thread_data));
			exit(EXIT_FAILURE);
		}
	}

	return ret;
}

int poll_do_poll_delete_simple_final (
		struct poll_collection *poll,
		struct instance_thread_data *thread_data,
		int (*poll_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		unsigned int flags
) {
	int ret = 0;

	struct instance_thread_data *faulty_sender;
	struct fifo_callback_args poll_data = {thread_data, thread_data, 0};
	int res = poll_do_poll_delete (
			poll,
			&faulty_sender,
			RRR_POLL_BREAK_ON_ERR|flags,
			poll_callback,
			&poll_data
	);
	if (res != 0) {
		VL_MSG_ERR ("module %s instance %s received error from poll delete function of instance %s\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data), INSTANCE_D_NAME(faulty_sender));
		ret = 1;
	}

	return ret;
}

int poll_collection_count (struct poll_collection *collection) {
	int ret = 0;
	POLL_COLLECTION_LOOP(entry,collection) {
		ret++;
	}
	return ret;
}

int poll_add_from_thread_senders_and_count (
		struct poll_collection *collection,
		struct instance_thread_data *thread_data,
		unsigned int flags
) {
	int ret = 0;

	struct instance_metadata *faulty_sender;
	if (poll_collection_add_from_senders(collection, &faulty_sender, thread_data->init_data.senders, flags) != 0
	) {
		VL_MSG_ERR("Module %s instance %s could not find correct poll functions in sender %s\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data), INSTANCE_M_NAME(faulty_sender));
		ret = 1;
	}
	else if (poll_collection_count(collection) == 0) {
		VL_MSG_ERR ("Error: Senders were not set module %s instance %s\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data));
		ret = 1;
	}

	return ret;
}

void poll_add_from_thread_senders_ignore_error (
		struct poll_collection *collection,
		struct instance_thread_data *thread_data,
		unsigned int flags
) {
	struct instance_metadata *faulty_sender;
	poll_collection_add_from_senders(collection, &faulty_sender, thread_data->init_data.senders, flags);
}
