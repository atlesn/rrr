/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include <stddef.h>
#include <pthread.h>

#include "../global.h"
#include "linked_list.h"
#include "message_broker.h"
#include "ip.h"

void __rrr_message_broker_costumer_destroy (struct rrr_message_broker_costumer *costumer) {
	pthread_mutex_lock(&costumer->lock);
	RRR_FREE_IF_NOT_NULL(costumer->name);
	rrr_fifo_buffer_destroy(&costumer->queue);
	pthread_mutex_unlock(&costumer->lock);

	pthread_mutex_destroy(&costumer->lock);

	free(costumer);
}

int __rrr_message_broker_costumer_new (
		struct rrr_message_broker_costumer **result,
		const char *name_unique
) {
	int ret = 0;

	*result = NULL;

	struct rrr_message_broker_costumer *costumer = malloc(sizeof(*costumer));
	if (costumer == NULL) {
		RRR_MSG_ERR("Could not allocate memory for costumer in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out;
	}

	memset(costumer, '\0', sizeof(*costumer));

	if ((costumer->name = strdup(name_unique)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory for name in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_free;
	}

	if (pthread_mutex_init (&costumer->lock, NULL) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in __rrr_message_broker_costumer_new\n");
		goto out_free_name;
	}

	if (rrr_fifo_buffer_init_custom_free(&costumer->queue, rrr_ip_buffer_entry_destroy_void) != 0) {
		RRR_MSG_ERR("Could not initialize buffer in __rrr_message_broker_costumer_new\n");
		goto out_destroy_mutex;
	}

	*result = costumer;

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&costumer->lock);
	out_free_name:
		free(costumer->name);
	out_free:
		free(costumer);
	out:
		return ret;
}

void rrr_message_broker_cleanup (
		struct rrr_message_broker *broker
) {
	RRR_LL_DESTROY(broker, struct rrr_message_broker_costumer, __rrr_message_broker_costumer_destroy(node));
	pthread_mutex_destroy(&broker->lock);
}

int rrr_message_broker_init (
		struct rrr_message_broker *broker
) {
	int ret = 0;

	memset(broker, '\0', sizeof (*broker));

	if (pthread_mutex_init(&broker->lock, 0) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in rrr_message_broker_init\n");
		ret = 1;
		goto out;
	}

	goto out;
//	out_destroy_mutex:
//		pthread_mutex_destroy(&broker->lock);
	out:
		return ret;
}

static rrr_message_broker_costumer_handle *__rrr_message_broker_costumer_find_by_name_unlocked (
		struct rrr_message_broker *broker,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(broker, struct rrr_message_broker_costumer);
		if (strcmp(name, node->name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static rrr_message_broker_costumer_handle *__rrr_message_broker_costumer_find_by_handle_unlocked (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	RRR_LL_ITERATE_BEGIN(broker, struct rrr_message_broker_costumer);
		if (node == handle) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

void rrr_message_broker_costumer_unregister (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	pthread_mutex_lock(&broker->lock);

	int count_before = RRR_LL_COUNT(broker);

	RRR_LL_REMOVE_NODE(broker, struct rrr_message_broker_costumer, handle, __rrr_message_broker_costumer_destroy(node));

	if (count_before == RRR_LL_COUNT(broker)) {
		RRR_MSG_ERR("Warning: Attempted to remove broker costumer which was not registered in rrr_message_broker_costumer_unregister\n");
	}

	pthread_mutex_unlock(&broker->lock);
}

int rrr_message_broker_costumer_register (
		rrr_message_broker_costumer_handle **result,
		struct rrr_message_broker *broker,
		const char *name_unique
) {
	int ret = 0;

	*result = NULL;

	struct rrr_message_broker_costumer *costumer = NULL;

	pthread_mutex_lock(&broker->lock);

	if (__rrr_message_broker_costumer_find_by_name_unlocked(broker, name_unique) != 0) {
		RRR_BUG("BUG: Attempted to register costumer with non-uniqe name '%s' in rrr_message_broker_costumer_register\n",
				name_unique);
	}

	if (__rrr_message_broker_costumer_new (&costumer, name_unique) != 0) {
		goto out;
	}

	RRR_LL_APPEND(broker, costumer);

	*result = costumer;

	out:
	pthread_mutex_unlock(&broker->lock);
	return ret;
}

#define RRR_MESSAGE_BROKER_VERIFY_AND_LOCK_COSTUMER_HANDLE(err_src)								\
	do { if (__rrr_message_broker_costumer_find_by_handle_unlocked(broker, handle) == NULL) {	\
		RRR_MSG_ERR("Could not find costumer handle %p in %s\n", handle, err_src);				\
		ret = RRR_MESSAGE_BROKER_ERR;															\
		break;																					\
	} struct rrr_message_broker_costumer *costumer = handle;									\
	pthread_mutex_lock(&costumer->lock);

#define RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK()		\
		pthread_mutex_unlock(&costumer->lock);			\
	} while(0)

struct rrr_message_broker_write_entry_intermediate_callback_data {
	ssize_t data_length;
	const struct sockaddr *addr;
	socklen_t socklen;
	int protocol;
	int (*callback)(struct rrr_ip_buffer_entry *new_entry, void *arg);
	void *callback_arg;
};

struct rrr_message_broker_ip_buffer_entry_double_pointer {
	struct rrr_ip_buffer_entry **entry;
};

static void __rrr_message_broker_free_ip_buffer_entry_double_pointer (void *arg) {
	struct rrr_message_broker_ip_buffer_entry_double_pointer *ptr = arg;
	if (*(ptr->entry) == NULL) {
		return;
	}
	rrr_ip_buffer_entry_destroy(*(ptr->entry));
}

static int __rrr_message_broker_write_entry_intermediate (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_message_broker_write_entry_intermediate_callback_data *callback_data = arg;

	int ret = RRR_FIFO_OK;

	struct rrr_ip_buffer_entry *entry = NULL;
	struct rrr_message_broker_ip_buffer_entry_double_pointer double_pointer = { &entry };

	pthread_cleanup_push(__rrr_message_broker_free_ip_buffer_entry_double_pointer, &double_pointer);

	if (rrr_ip_buffer_entry_new_with_empty_message (
			&entry,
			callback_data->data_length,
			callback_data->addr,
			callback_data->socklen,
			callback_data->protocol
	) != 0) {
		RRR_MSG_ERR("Could not allocate ip buffer entry in __rrr_message_broker_write_entry_intermediate\n");
		ret = 1;
		goto out;
	}

	if ((ret = callback_data->callback(entry, callback_data->callback_arg)) != 0) {
		if ((ret & RRR_MESSAGE_BROKER_AGAIN) == RRR_MESSAGE_BROKER_AGAIN) {
			if ((ret & ~(RRR_MESSAGE_BROKER_AGAIN)) != 0) {
				RRR_BUG("BUG: Extra return values from callback (%i) in addition to AGAIN in __rrr_message_broker_write_entry_intermediate\n", ret);
			}
			ret = RRR_FIFO_WRITE_AGAIN;
		}
		else if ((ret & RRR_MESSAGE_BROKER_DROP) == RRR_MESSAGE_BROKER_DROP) {
			if ((ret & ~(RRR_MESSAGE_BROKER_DROP)) != 0) {
				RRR_BUG("BUG: Extra return values from callback (%i) in addition to DROP in __rrr_message_broker_write_entry_intermediate\n", ret);
			}
			ret = RRR_FIFO_WRITE_ABORT;
			goto out;
		}
		else if ((ret & ~(RRR_MESSAGE_BROKER_ERR)) != 0) {
			RRR_BUG("Unknown return values %i from callback to __rrr_message_broker_write_entry_intermediate\n", ret);
		}
		else {
			ret = RRR_FIFO_GLOBAL_ERR;
			goto out;
		}
	}

	*data = (char*) entry;
	*size = sizeof(*entry);
	*order = 0;

	entry = NULL;

	out:
	pthread_cleanup_pop(1);
	return ret;
}

int rrr_message_broker_write_entry (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		ssize_t data_length,
		const struct sockaddr *addr,
		socklen_t socklen,
		int protocol,
		int (*callback)(struct rrr_ip_buffer_entry *new_entry, void *arg),
		void *callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_LOCK_COSTUMER_HANDLE("rrr_message_broker_write_entry");

	struct rrr_message_broker_write_entry_intermediate_callback_data callback_data = {
			data_length,
			addr,
			socklen,
			protocol,
			callback,
			callback_arg
	};

	if ((ret = rrr_fifo_buffer_write (
			&costumer->queue,
			__rrr_message_broker_write_entry_intermediate,
			&callback_data
	)) != 0) {
		RRR_MSG_ERR("Error while writing to buffer in rrr_message_broker_write_entry\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}
