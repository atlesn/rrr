/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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
#include <inttypes.h>
#include <sys/types.h>

#include "log.h"
#include "modules.h"
#include "message_broker.h"
#include "ip/ip.h"
#include "message_holder/message_holder.h"
#include "message_holder/message_holder_slot.h"
#include "message_holder/message_holder_struct.h"
#include "message_holder/message_holder_util.h"
#include "message_holder/message_holder_collection.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"
#include "util/posix.h"
#include "util/rrr_time.h"

// Uncomment to disable buffers for test reasons 
//#define RRR_MESSAGE_BROKER_NO_BUFFER_DEBUG 1

static void __rrr_message_broker_split_buffer_node_destroy (
		struct rrr_message_broker_split_buffer_node *node
) {
	struct rrr_fifo_buffer_stats stats;
	rrr_fifo_buffer_get_stats(&stats, &node->queue);
	RRR_DBG_1("\t- Split buffer stats: %" PRIu64 "/%" PRIu64 "\n",
			stats.total_entries_deleted, stats.total_entries_written);
	rrr_fifo_buffer_destroy(&node->queue);
	free(node);
}

static void __rrr_message_broker_costumer_incref (
		struct rrr_message_broker_costumer *costumer
) {
	costumer->usercount++;
}

static void __rrr_message_broker_costumer_decref (
		struct rrr_message_broker_costumer *costumer
) {
	if (--(costumer->usercount) == 0) {
		struct rrr_fifo_buffer_stats stats;

		if (costumer->slot != NULL) {
			uint64_t entries_deleted = 0;
			uint64_t entries_written = 0;
			rrr_msg_holder_slot_get_stats(&entries_deleted, &entries_written, costumer->slot);
			rrr_fifo_buffer_get_stats_populate(&stats, entries_written, entries_deleted);

			rrr_msg_holder_slot_destroy(costumer->slot);
		}
		else {
			rrr_fifo_buffer_get_stats(&stats, &costumer->main_queue);
		}

		RRR_DBG_1 ("Message broker destroy costumer '%s', buffer stats: %" PRIu64 "/%" PRIu64 "\n",
				costumer->name, stats.total_entries_deleted, stats.total_entries_written);

		RRR_LL_DESTROY (
				&costumer->split_buffers,
				struct rrr_message_broker_split_buffer_node,
				__rrr_message_broker_split_buffer_node_destroy(node)
		);
		rrr_fifo_buffer_destroy(&costumer->main_queue);
		pthread_mutex_destroy(&costumer->split_buffers.lock);
		// Do this at the end in case we need to read the name in a debugger
		RRR_FREE_IF_NOT_NULL(costumer->name);
		free(costumer);
	}
}

static void __rrr_message_broker_costumer_lock_and_decref (
		struct rrr_message_broker *broker,
		struct rrr_message_broker_costumer *costumer
) {
	pthread_mutex_lock(&broker->lock);
	__rrr_message_broker_costumer_decref(costumer);
	pthread_mutex_unlock(&broker->lock);
}

struct rrr_message_broker_costumer_lock_and_decref_void_data {
	struct rrr_message_broker *broker;
	struct rrr_message_broker_costumer *costumer;
};

static void __rrr_message_broker_costumer_lock_and_decref_void (void *arg) {
	struct rrr_message_broker_costumer_lock_and_decref_void_data *data = arg;
	__rrr_message_broker_costumer_lock_and_decref(data->broker, data->costumer);
}

static int __rrr_message_broker_costumer_new (
		struct rrr_message_broker_costumer **result,
		const char *name_unique,
		int no_buffer
) {
	int ret = 0;

#ifdef RRR_MESSAGE_BROKER_NO_BUFFER_DEBUG
	no_buffer = 1;
#endif

	*result = NULL;

	struct rrr_message_broker_costumer *costumer = malloc(sizeof(*costumer));
	if (costumer == NULL) {
		RRR_MSG_0("Could not allocate memory for costumer in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out;
	}

	memset(costumer, '\0', sizeof(*costumer));

	if ((costumer->name = strdup(name_unique)) == NULL) {
		RRR_MSG_0("Could not allocate memory for name in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_free;
	}

	if (rrr_fifo_buffer_init_custom_free(&costumer->main_queue, rrr_msg_holder_decref_void) != 0) {
		RRR_MSG_0("Could not initialize buffer in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_free_name;
	}

	if ((rrr_posix_mutex_init(&costumer->split_buffers.lock, 0)) != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_destroy_fifo;
	}

	if (no_buffer) {
		if ((ret = rrr_msg_holder_slot_new(&costumer->slot)) != 0) {
			goto out_destroy_split_buffer_lock;
		}
	}

	costumer->usercount = 1;

	*result = costumer;

	goto out;
	out_destroy_split_buffer_lock:
		pthread_mutex_destroy(&costumer->split_buffers.lock);
	out_destroy_fifo:
		rrr_fifo_buffer_destroy(&costumer->main_queue);
	out_free_name:
		free(costumer->name);
	out_free:
		free(costumer);
	out:
		return ret;
}

void rrr_message_broker_unregister_all_hard (
		struct rrr_message_broker *broker
) {
	pthread_mutex_lock(&broker->lock);
	if (RRR_DEBUGLEVEL_1) {
		RRR_LL_ITERATE_BEGIN(broker, struct rrr_message_broker_costumer);
			RRR_MSG_0("Message broker decref on costumer '%s' upon unregister_all_hard, usercount: %i\n",
					node->name, node->usercount);
		RRR_LL_ITERATE_END();
	}
	RRR_LL_DESTROY(broker, struct rrr_message_broker_costumer, __rrr_message_broker_costumer_decref(node));
	pthread_mutex_unlock(&broker->lock);
}

void rrr_message_broker_cleanup (
		struct rrr_message_broker *broker
) {
	rrr_message_broker_unregister_all_hard(broker);
	pthread_mutex_destroy(&broker->lock);
}

int rrr_message_broker_init (
		struct rrr_message_broker *broker
) {
	int ret = 0;

	memset(broker, '\0', sizeof (*broker));

	if (rrr_posix_mutex_init(&broker->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_message_broker_init\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&broker->lock);
	broker->creator = pthread_self();
	pthread_mutex_unlock(&broker->lock);

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

rrr_message_broker_costumer_handle *rrr_message_broker_costumer_find_by_name (
		struct rrr_message_broker *broker,
		const char *name
) {
	rrr_message_broker_costumer_handle *ret = NULL;

	pthread_mutex_lock(&broker->lock);
	ret = __rrr_message_broker_costumer_find_by_name_unlocked(broker, name);
	pthread_mutex_unlock(&broker->lock);

	return ret;
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

static rrr_message_broker_costumer_handle *__rrr_message_broker_costumer_find_by_handle_and_incref (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	static rrr_message_broker_costumer_handle *result = NULL;

	pthread_mutex_lock(&broker->lock);
	result = __rrr_message_broker_costumer_find_by_handle_unlocked(broker, handle);
	if (result != NULL) {
		__rrr_message_broker_costumer_incref(result);
	}
	pthread_mutex_unlock(&broker->lock);

	return result;
}
	
void __rrr_message_broker_costumer_get_name (
		char *buf,
		size_t buf_size,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {

	pthread_mutex_lock(&broker->lock);

	struct rrr_message_broker_costumer *costumer = __rrr_message_broker_costumer_find_by_handle_unlocked(broker, handle);
	if (costumer != NULL) {
		strncpy(buf, costumer->name, buf_size);
	}
	else {
		*buf = '\0';
	}

	pthread_mutex_unlock(&broker->lock);

	buf[buf_size - 1]  = '\0';
}

void rrr_message_broker_costumer_unregister (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	pthread_mutex_lock(&broker->lock);

	RRR_DBG_8("Message broker unregistering handle %p\n", handle);

	int count_before = RRR_LL_COUNT(broker);

	RRR_LL_REMOVE_NODE_IF_EXISTS(broker, struct rrr_message_broker_costumer, handle, __rrr_message_broker_costumer_decref(node));

	if (count_before == RRR_LL_COUNT(broker)) {
		RRR_MSG_0("Warning: Attempted to remove broker costumer which was not registered in rrr_message_broker_costumer_unregister\n");
	}

	pthread_mutex_unlock(&broker->lock);
}

int rrr_message_broker_costumer_register (
		rrr_message_broker_costumer_handle **result,
		struct rrr_message_broker *broker,
		const char *name_unique,
		int no_buffer
) {
	int ret = 0;

	*result = NULL;

	struct rrr_message_broker_costumer *costumer = NULL;

	pthread_mutex_lock(&broker->lock);

	if (__rrr_message_broker_costumer_find_by_name_unlocked(broker, name_unique) != 0) {
		RRR_BUG("BUG: Attempted to register costumer with non-uniqe name '%s' in rrr_message_broker_costumer_register\n",
				name_unique);
	}

	if ((ret = __rrr_message_broker_costumer_new (&costumer, name_unique, no_buffer)) != 0) {
		goto out;
	}

	RRR_LL_APPEND(broker, costumer);

	*result = costumer;

	RRR_DBG_8("Message broker registered costumer '%s' handle is %p no buffer is %i\n", name_unique, costumer, no_buffer);

	out:
	pthread_mutex_unlock(&broker->lock);
	return ret;
}

#define RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE(err_src)                                                          \
    do { if (__rrr_message_broker_costumer_find_by_handle_and_incref(broker, handle) == NULL) {                                \
        RRR_MSG_0("Could not find costumer handle %p in %s\n", handle, err_src);                                               \
        ret = RRR_MESSAGE_BROKER_ERR;                                                                                          \
        break;                                                                                                                 \
    } struct rrr_message_broker_costumer *costumer = handle;                                                                   \
    struct rrr_message_broker_costumer_lock_and_decref_void_data costumer_decref_data =                                        \
        { broker, costumer };                                                                                                  \
    pthread_cleanup_push(__rrr_message_broker_costumer_lock_and_decref_void, &costumer_decref_data)

#define RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK()            \
    pthread_cleanup_pop(1);                                    \
    } while(0)

static int __rrr_message_broker_split_output_buffer_new_and_add (
		struct rrr_message_broker_split_buffer_collection *target
) {
	int ret = 0;

	struct rrr_message_broker_split_buffer_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_message_broker_split_output_buffer_new\n");
		ret = 1;
		goto out;
	}

	memset(node, '\0', sizeof(*node));

	if (rrr_fifo_buffer_init_custom_free(&node->queue, rrr_msg_holder_decref_void) != 0) {
		RRR_MSG_0("Could not initialize buffer in __rrr_message_broker_split_output_buffer_new\n");
		ret = 1;
		goto out_free;
	}

	RRR_LL_APPEND(target, node);
	node = NULL;

	goto out;
	out_free:
		free(node);
	out:
		return ret;
}

// Call in preload stage only from main thread. Number of slots
// have to match or exceed the number of different reader threads which
// will read from us, if not we will give a BUG()
int rrr_message_broker_setup_split_output_buffer (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int slots
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_setup_split_output_buffer");

	pthread_mutex_lock(&broker->lock);

	if (broker->creator != pthread_self()) {
		RRR_BUG("BUG: rrr_message_broker_setup_split_output_buffer called from other thread than creator\n");
	}

	if (costumer->slot != NULL) {
		// This function is safe to call multiple times
		if ((ret = rrr_msg_holder_slot_reader_count_set(costumer->slot, slots)) != 0) {
			goto out_unlock;
		}
	}
	else {
		// We can't create extra slots as they would fill up with messages
		// Make this a bug trap after configuration option in buffer module has been removed
		if (RRR_LL_COUNT(&costumer->split_buffers) > 0) {
			RRR_MSG_0("Warning: rrr_message_broker_setup_split_output_buffer called more than once, ignoring successive calls\n");
			goto out_unlock;
		}

		while (slots--) {
			if ((ret = __rrr_message_broker_split_output_buffer_new_and_add(&costumer->split_buffers)) != 0) {
				goto out_unlock;
			}
		}
	}

	out_unlock:
	pthread_mutex_unlock(&broker->lock);

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

struct rrr_message_broker_write_entry_intermediate_callback_data {
	struct rrr_message_broker_costumer *costumer;
	const struct sockaddr *addr;
	socklen_t socklen;
	int protocol;
	int (*callback)(struct rrr_msg_holder *new_entry, void *arg);
	void *callback_arg;
};

struct rrr_message_broker_message_holder_double_pointer {
	struct rrr_msg_holder **entry;
};

static void __rrr_message_broker_free_message_holder_double_pointer (void *arg) {
	struct rrr_message_broker_message_holder_double_pointer *ptr = arg;
	if (*(ptr->entry) == NULL) {
		return;
	}
	rrr_msg_holder_decref(*(ptr->entry));
}

static int __rrr_message_broker_write_entry_callback_handling (
		int *write_drop,
		int *write_again,
		struct rrr_msg_holder *entry,
		int (*callback)(struct rrr_msg_holder *new_entry, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*write_drop = 0;
	*write_again = 0;

	if ((ret = callback(entry, callback_arg)) != 0) {
		if ((ret & RRR_MESSAGE_BROKER_AGAIN) == RRR_MESSAGE_BROKER_AGAIN) {
			if ((ret & ~(RRR_MESSAGE_BROKER_AGAIN|RRR_MESSAGE_BROKER_DROP)) != 0) {
				RRR_BUG("BUG: Extra return values from callback (%i) in addition to AGAIN which was not DROP in __rrr_message_broker_write_entry_callback_handling\n", ret);
			}
			*write_again = 1;
		}

		if ((ret & RRR_MESSAGE_BROKER_DROP) == RRR_MESSAGE_BROKER_DROP) {
			if ((ret & ~(RRR_MESSAGE_BROKER_AGAIN|RRR_MESSAGE_BROKER_DROP)) != 0) {
				RRR_BUG("BUG: Extra return values from callback (%i) in addition to DROP which was not AGAIN in __rrr_message_broker_write_entry_callback_handling\n", ret);
			}
			*write_drop = 1;
		}

		ret &= ~(RRR_MESSAGE_BROKER_DROP|RRR_MESSAGE_BROKER_AGAIN);

		if ((ret & ~(RRR_MESSAGE_BROKER_ERR)) != 0) {
			RRR_BUG("Unknown return values %i from callback to __rrr_message_broker_write_entry_callback_handling\n", ret);
		}
	}

	return ret;
}

static int __rrr_message_broker_write_entry_slot_intermediate (
		int *do_drop,
		int *do_again,
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct rrr_message_broker_write_entry_intermediate_callback_data *callback_data = arg;

	int ret = 0;

	if ((ret = __rrr_message_broker_write_entry_callback_handling (
			do_drop,
			do_again,
			entry,
			callback_data->callback,
			callback_data->callback_arg
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_message_broker_write_entry_intermediate (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_message_broker_write_entry_intermediate_callback_data *callback_data = arg;

	int ret = RRR_FIFO_OK;

	*data = NULL;
	*size = 0;
	*order = 0;

	struct rrr_msg_holder *entry = NULL;
	struct rrr_message_broker_message_holder_double_pointer double_pointer = { &entry };

	pthread_cleanup_push(__rrr_message_broker_free_message_holder_double_pointer, &double_pointer);

	if (rrr_msg_holder_new (
			&entry,
			0,
			callback_data->addr,
			callback_data->socklen,
			callback_data->protocol,
			NULL
	) != 0) {
		RRR_MSG_0("Could not allocate ip buffer entry in __rrr_message_broker_write_entry_intermediate\n");
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}

	// Callback must always unlock entry. If the callback is possibly slow
	// and has cancellation points, it must wrap unlock in pthread_cleanup_push

	rrr_msg_holder_lock(entry);

	int write_drop = 0;
	int write_again = 0;

	if ((ret = __rrr_message_broker_write_entry_callback_handling (
			&write_drop,
			&write_again,
			entry,
			callback_data->callback,
			callback_data->callback_arg
	)) != 0) {
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}

	if (write_again) {
		ret |= RRR_FIFO_WRITE_AGAIN;
	}

	if (write_drop) {
		ret |= RRR_FIFO_WRITE_DROP;
		goto out;
	}

	{
		rrr_msg_holder_lock(entry);
		if (entry->usercount != 1) {
			RRR_BUG("BUG: Usercount was not 1 after callback in __rrr_message_broker_write_entry_intermediate\n");
		}
		if (entry->message != NULL && entry->data_length == 0) {
			RRR_BUG("BUG: Entry message was set but data length was left being + in __rrr_message_broker_write_entry_intermediate, callback must set data length\n");
		}

		// Prevents cleanup_pop below to free the entry now that everything is in order
		rrr_msg_holder_incref_while_locked(entry);
		rrr_msg_holder_unlock(entry);
	}

	*data = (char*) entry;
	*size = sizeof(*entry);
	*order = 0;

	out:
	pthread_cleanup_pop(1);
	return ret;
}

int __rrr_message_broker_get_next_unique_id_callback (
		void *callback_arg_1,
		void *callback_arg_2
) {
	uint64_t *unique_counter = callback_arg_1;

	(void)(callback_arg_2);

	(*unique_counter)++;

	if (*unique_counter== 0) {
		*unique_counter = 1;
	}

	return 0;
}

int rrr_message_broker_get_next_unique_id (
		uint64_t *result,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	*result = 0;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_get_next_unique_id");

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_with_lock_do (
				costumer->slot,
				__rrr_message_broker_get_next_unique_id_callback,
				&costumer->unique_counter,
				NULL
		)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_fifo_buffer_with_write_lock_do (
				&costumer->main_queue,
				__rrr_message_broker_get_next_unique_id_callback,
				&costumer->unique_counter,
				NULL
		)) != 0) {
			goto out;
		}
	}

	*result = costumer->unique_counter;

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

// Callback must return the entry in unlocked state to us with refcount being excactly 1
int rrr_message_broker_write_entry (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		const struct sockaddr *addr,
		socklen_t socklen,
		int protocol,
		int (*callback)(struct rrr_msg_holder *new_entry, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg

) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_write_entry");

	struct rrr_message_broker_write_entry_intermediate_callback_data callback_data = {
			costumer,
			addr,
			socklen,
			protocol,
			callback,
			callback_arg
	};

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_write (
				costumer->slot,
				addr,
				socklen,
				protocol,
				__rrr_message_broker_write_entry_slot_intermediate,
				&callback_data,
				check_cancel_callback,
				check_cancel_callback_arg
		)) != 0) { 
			RRR_MSG_0("Error while writing to buffer (slot) in rrr_message_broker_write_entry\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}
	else {
		if ((ret = rrr_fifo_buffer_write (
				&costumer->main_queue,
				__rrr_message_broker_write_entry_intermediate,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer (main_queue) in rrr_message_broker_write_entry\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

static int __rrr_message_broker_clone_and_write_entry_callback (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	const struct rrr_msg_holder *source = arg;

	int ret = 0;

	struct rrr_msg_holder *target = NULL;

	if (rrr_msg_holder_util_clone_no_locking(&target, source) != 0) {
		RRR_MSG_0("Could not clone ip buffer entry in __rrr_message_broker_write_clone_and_write_entry_callback\n");
		ret = 1;
		goto out;
	}

	*data = (char *) target;
	*size = sizeof(*target);
	*order = 0;

	target = NULL;

	out:
	return ret;
}

// Note : Used by inject functions. entry is not properly const
//        as we will call unlock() on function out. entry
//        must be handed to us in locked state
int rrr_message_broker_clone_and_write_entry (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		const struct rrr_msg_holder *entry
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_clone_and_write_entry");

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_write_clone (
				costumer->slot,
				entry,
				NULL,
				NULL
		)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_fifo_buffer_write (
				&costumer->main_queue,
				__rrr_message_broker_clone_and_write_entry_callback,
				(void *) entry
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer in rrr_message_broker_clone_and_write_entry\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	out:
	// Cast away const OK
	rrr_msg_holder_unlock((struct rrr_msg_holder *) entry);
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

static int __rrr_message_broker_write_entry_unsafe_callback(RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_msg_holder *entry = arg;

	*data = (char *) entry;
	*size = sizeof(*entry);
	*order = 0;

	rrr_msg_holder_incref_while_locked(entry);

	return 0;
}

// Only to be used when we already are inside a read callback and the
// entry we passed in is guaranteed to have been allocated and modified
// exclusively in message broker context. Entry must be locked before calling.
int rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		struct rrr_msg_holder *entry,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_write_entry_unsafe");

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_write_incref(costumer->slot, entry, check_cancel_callback, check_cancel_callback_arg)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_fifo_buffer_write (
				&costumer->main_queue,
				__rrr_message_broker_write_entry_unsafe_callback,
				entry
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer in rrr_message_broker_write_entry_unsafe\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int __rrr_message_broker_write_entries_from_collection_callback (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_msg_holder_collection *collection = arg;

	struct rrr_msg_holder *entry = RRR_LL_SHIFT(collection);

	*data = (char*) entry;
	*size = sizeof(*entry);
	*order = 0;

	return (RRR_LL_COUNT(collection) > 0 ? RRR_FIFO_WRITE_AGAIN : RRR_FIFO_OK);
}

// This function removes entries one by one from the given collection. All refcounts passed in
// must equal exactly 1. No entries may be locked prior to calling this function. If this function
// fails, entries might still reside inside the collection which have not yet been added to the
// buffer. The caller owns these. Read about 'unsafe' above.
int rrr_message_broker_write_entries_from_collection_unsafe (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		struct rrr_msg_holder_collection *collection,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (RRR_LL_COUNT(collection) == 0) {
		goto out_final;
	}

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_write_entries_from_collection");

	if (costumer->slot != NULL) {
		ret = rrr_msg_holder_slot_write_from_collection(costumer->slot, collection, check_cancel_callback, check_cancel_callback_arg);
	}
	else {
		ret = rrr_fifo_buffer_write(&costumer->main_queue, __rrr_message_broker_write_entries_from_collection_callback, collection);
	}

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	out_final:
	return ret;
}

struct rrr_message_broker_read_entry_intermediate_callback_data {
	struct rrr_message_broker *broker;
	struct rrr_message_broker_costumer *source;
	rrr_message_broker_costumer_handle *self;
	int broker_poll_flags;
	int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
	void *callback_arg;
};

static int __rrr_message_broker_poll_intermediate_backstop_handling (
		int *backstop,
		struct rrr_msg_holder *entry,
		struct rrr_message_broker_read_entry_intermediate_callback_data *callback_data
) {
	*backstop = 0;

	if ( callback_data->broker_poll_flags & RRR_MESSAGE_BROKER_POLL_F_CHECK_BACKSTOP &&
	     entry->source == callback_data->self
	) {
		if (RRR_DEBUGLEVEL_2) {
			char name[128];
			 __rrr_message_broker_costumer_get_name (name, sizeof(name), callback_data->broker, callback_data->self);
			RRR_DBG_2("Message broker backstop in %s: Message read from %s originates from self\n",
					name, callback_data->source->name);
		}
		*backstop = 1;
		rrr_msg_holder_unlock(entry);
		return 0;
	}

	// Set regardless of flag, we don't know if the source wishes to check backstop or not
	if (entry->source == NULL) {
		entry->source = callback_data->source;
	}

	return callback_data->callback(entry, callback_data->callback_arg);
}

static int __rrr_message_broker_poll_delete_intermediate (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_message_broker_read_entry_intermediate_callback_data *callback_data = arg;
	struct rrr_msg_holder *entry = (struct rrr_msg_holder *) data;

	(void)(size);

	int ret = 0;

	rrr_msg_holder_lock(entry);

	int backstop_dummy = 0;
	ret = __rrr_message_broker_poll_intermediate_backstop_handling (
			&backstop_dummy,
			entry,
			callback_data
	);

	// Callback must unlock
	rrr_msg_holder_decref(entry);

	return ret;
}

static int __rrr_message_broker_poll_intermediate (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_message_broker_read_entry_intermediate_callback_data *callback_data = arg;
	struct rrr_msg_holder *entry = (struct rrr_msg_holder *) data;

	(void)(size);

	int ret = RRR_FIFO_SEARCH_KEEP;

	rrr_msg_holder_incref(entry);
	rrr_msg_holder_lock(entry);

	int backstop = 0;
	ret = __rrr_message_broker_poll_intermediate_backstop_handling (
			&backstop,
			entry,
			callback_data
	);

	if (backstop) {
		ret |= RRR_FIFO_SEARCH_FREE;
		ret |= RRR_FIFO_SEARCH_GIVE;
	}

	// Callback must unlock
	rrr_msg_holder_decref(entry);

	return ret;
}

static int __rrr_message_broker_poll_slot_intermediate (
		int *do_keep,
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct rrr_message_broker_read_entry_intermediate_callback_data *callback_data = arg;

	int ret = 0;

	*do_keep = 0;

	int backstop = 0;
	int actions = __rrr_message_broker_poll_intermediate_backstop_handling (
			&backstop,
			entry,
			callback_data
	);

	unsigned char do_keep_tmp = 0;
	unsigned char do_give_tmp = 0;
	unsigned char do_free_tmp = 0;
	unsigned char do_stop_tmp = 0;

	if (backstop) {
		do_give_tmp = 1;
		do_free_tmp = 1;
	}
	else {
		if ((ret = rrr_fifo_buffer_search_return_value_process (
				&do_keep_tmp,
				&do_give_tmp,
				&do_free_tmp,
				&do_stop_tmp,
				actions
		)) != 0) {
			goto out;
		}
	}

	if (do_keep_tmp) {
		*do_keep = 1;
	}
	else if (do_give_tmp) {
		rrr_msg_holder_incref(entry);
		if (do_free_tmp) {
			rrr_msg_holder_decref(entry);
		}
	}

	// do_stop_tmp need not be checked, we may only return one result anyway (hence we always stop)

	out:
	return ret;
}

static int __rrr_message_broker_poll_delete_slot_intermediate (
		int *do_keep,
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct rrr_message_broker_read_entry_intermediate_callback_data *callback_data = arg;

	int ret = 0;

	*do_keep = 0;

	// Locking handled by mgs_holder_slot framework

	int backstop_dummy = 0;
	ret = __rrr_message_broker_poll_intermediate_backstop_handling (
			&backstop_dummy,
			entry,
			callback_data
	);

	return ret;
}

static void __rrr_message_broker_get_source_buffer (
		int *source_buffer_is_main,
		struct rrr_fifo_buffer **use_buffer,
		struct rrr_message_broker_costumer *costumer,
		rrr_message_broker_costumer_handle *self
) {
	pthread_mutex_lock(&costumer->split_buffers.lock);

	if (RRR_LL_COUNT(&costumer->split_buffers) == 0) {
		*source_buffer_is_main = 1;
		*use_buffer = &costumer->main_queue;
		goto out;
	}
	else {
		*source_buffer_is_main = 0;
	}

	struct rrr_fifo_buffer *found_buffer = NULL;

	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		if (node->owner == self) {
			found_buffer = &node->queue;
			RRR_LL_ITERATE_LAST();
		}
		else if (node->owner == NULL) {
			// Allocate
			node->owner = self;
			found_buffer = &node->queue;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	if (found_buffer == NULL) {
		RRR_BUG("Not enough slots in __rrr_message_broker_split_buffers_handle\n");
	}

	*use_buffer = found_buffer;

	out:
	pthread_mutex_unlock(&costumer->split_buffers.lock);
}

static int __rrr_message_broker_split_buffers_fill_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_message_broker_costumer *costumer = arg;

	(void)(size);

	int ret = 0;

	// Split buffer lock must be held by caller

	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		// Use delayed write in case there are other threads reading from their buffer
		if ((ret = rrr_fifo_buffer_write_delayed (
				&node->queue,
				__rrr_message_broker_clone_and_write_entry_callback,
				(void *) data
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer in __rrr_message_broker_split_buffers_fill_callback\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret | RRR_FIFO_SEARCH_FREE;
}

static int __rrr_message_broker_split_buffers_fill (
		struct rrr_message_broker_costumer *costumer
) {
	int ret = 0;

	if (rrr_fifo_buffer_get_entry_count(&costumer->main_queue) == 0) {
		goto out_no_unlock;
	}

	// Somebody else is probably doing this already
	if (pthread_mutex_trylock(&costumer->split_buffers.lock) != 0) {
		goto out_no_unlock;
	}

	if ((ret = rrr_fifo_buffer_read_clear_forward (
			&costumer->main_queue,
			__rrr_message_broker_split_buffers_fill_callback,
			costumer,
			0
	)) != 0) {
		RRR_MSG_0("Error from FIFO in __rrr_message_broker_split_buffers_fill\n");
		goto out;
	}

	out:
		pthread_mutex_unlock(&costumer->split_buffers.lock);
	out_no_unlock:
		return ret;
}

#define RRR_MESSAGE_BROKER_POLL_SPLIT_BUFFER_HANDLING()                  \
    struct rrr_fifo_buffer *source_buffer = NULL;                        \
    do {                                                                 \
        int source_buffer_is_main = 0;                                   \
        __rrr_message_broker_get_source_buffer (                         \
    	    &source_buffer_is_main, &source_buffer, costumer, self       \
        ); if (source_buffer_is_main == 0 &&                             \
    	    (ret = __rrr_message_broker_split_buffers_fill(costumer)     \
        ) != 0) { goto out; }} while(0)

struct rrr_message_broker_poll_discard_callback_data {
	int count;
};

static int __rrr_message_broker_poll_discard_callback (
		void *arg,
		char *data,
		unsigned long int size
) {
	struct rrr_message_broker_poll_discard_callback_data *callback_data = arg;

	(void)(data);
	(void)(size);

	callback_data->count++;

	return 0;
}

int rrr_message_broker_poll_discard (
		int *discarded_count,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	*discarded_count = 0;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_poll_discard");

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_discard (discarded_count, costumer->slot, self)) != 0) {
			goto out;
		}
	}
	else {
		RRR_MESSAGE_BROKER_POLL_SPLIT_BUFFER_HANDLING();

		struct rrr_message_broker_poll_discard_callback_data callback_data = { 0 };

		rrr_fifo_buffer_clear_with_callback(source_buffer, __rrr_message_broker_poll_discard_callback, &callback_data);

		*discarded_count = callback_data.count;
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int rrr_message_broker_poll_delete (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_poll_delete");

	struct rrr_message_broker_read_entry_intermediate_callback_data callback_data = {
			broker,
			costumer,
			self,
			broker_poll_flags,
			callback,
			callback_arg
	};

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_read (
				costumer->slot,
				self,
				__rrr_message_broker_poll_delete_slot_intermediate,
				&callback_data,
				wait_milliseconds
		)) != 0) {
			goto out;
		}
	}
	else {
		RRR_MESSAGE_BROKER_POLL_SPLIT_BUFFER_HANDLING();

		if ((ret = rrr_fifo_buffer_read_clear_forward (
				source_buffer,
				__rrr_message_broker_poll_delete_intermediate,
				&callback_data,
				wait_milliseconds
		)) != 0) {
			goto out;
		}
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int rrr_message_broker_poll (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_poll");

	struct rrr_message_broker_read_entry_intermediate_callback_data callback_data = {
			broker,
			handle,
			self,
			broker_poll_flags,
			callback,
			callback_arg
	};

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_read (
				costumer->slot,
				self,
				__rrr_message_broker_poll_slot_intermediate,
				&callback_data,
				wait_milliseconds
		)) != 0) {
			goto out;
		}
	}
	else {
		RRR_MESSAGE_BROKER_POLL_SPLIT_BUFFER_HANDLING();

		if ((ret = rrr_fifo_buffer_search (
				source_buffer,
				__rrr_message_broker_poll_intermediate,
				&callback_data,
				wait_milliseconds
		)) != 0) {
			goto out;
		}
	}

	out:
	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int rrr_message_broker_set_ratelimit (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int set
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_set_ratelimit");

	rrr_fifo_buffer_set_do_ratelimit(&costumer->main_queue, set);

	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		rrr_fifo_buffer_set_do_ratelimit(&node->queue, set);
	RRR_LL_ITERATE_END();

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int rrr_message_broker_get_entry_count_and_ratelimit (
		int *entry_count,
		int *ratelimit_active,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	*entry_count = 0;
	*ratelimit_active = 0;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_set_ratelimit");

	if (costumer->slot != NULL) {
		*ratelimit_active = 0;
		*entry_count = rrr_msg_holder_slot_count(costumer->slot);
	}
	else {
		// Ratelimit is the same on split buffers
		*ratelimit_active = rrr_fifo_buffer_get_ratelimit_active(&costumer->main_queue);
		*entry_count = rrr_fifo_buffer_get_entry_count(&costumer->main_queue);

		RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
			(*entry_count) += rrr_fifo_buffer_get_entry_count(&node->queue);
		RRR_LL_ITERATE_END();
	}

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

// Note that stats from any split queues are not retrieved
int rrr_message_broker_get_fifo_stats (
		struct rrr_fifo_buffer_stats *target,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_get_fifo_stats");

	if (costumer->slot != NULL) {
		uint64_t entries_deleted = 0;
		uint64_t entries_written = 0;
		rrr_msg_holder_slot_get_stats(&entries_deleted, &entries_written, costumer->slot);
		rrr_fifo_buffer_get_stats_populate(target, entries_written, entries_deleted);
	}
	else {
		rrr_fifo_buffer_get_stats(target, &costumer->main_queue);
	}

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();

	return ret;
}

int rrr_message_broker_with_ctx_do (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_with_ctx_do");

	ret = callback(callback_arg_1, callback_arg_2);

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();
	return ret;
}

int rrr_message_broker_with_ctx_and_buffer_lock_do (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	RRR_MESSAGE_BROKER_VERIFY_AND_INCREF_COSTUMER_HANDLE("rrr_message_broker_with_ctx_do");

	if (costumer->slot != NULL) {
		ret = rrr_msg_holder_slot_with_lock_do(costumer->slot, callback, callback_arg_1, callback_arg_2);
	}
	else {
		ret = rrr_fifo_buffer_with_write_lock_do(&costumer->main_queue, callback, callback_arg_1, callback_arg_2);
	}

	RRR_MESSAGE_BROKER_COSTUMER_HANDLE_UNLOCK();

	return ret;
}

