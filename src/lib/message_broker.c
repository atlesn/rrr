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
#include "fifo_protected.h"
#include "allocator.h"
#include "random.h"
#include "event/event.h"
#include "event/event_functions.h"
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

struct rrr_message_broker_split_buffer_node {
	RRR_LL_NODE(struct rrr_message_broker_split_buffer_node);
	struct rrr_fifo_protected queue;
	struct rrr_message_broker_costumer *owner;
};

struct rrr_message_broker_split_buffer_collection {
	RRR_LL_HEAD(struct rrr_message_broker_split_buffer_node);
	pthread_mutex_t lock;
};

struct rrr_message_broker_costumer {
	RRR_LL_NODE(struct rrr_message_broker_costumer);
	struct rrr_fifo_protected main_queue;
	struct rrr_message_broker_split_buffer_collection split_buffers;
	struct rrr_msg_holder_slot *slot;
	char *name;
	int usercount;
	int flags;
	int split_buffers_active;
	uint64_t unique_counter;
	struct rrr_event_queue *events;
	struct rrr_message_broker_costumer *write_notify_listeners[RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX];
	struct rrr_message_broker_costumer *senders[RRR_MESSAGE_BROKER_SENDERS_MAX];
};

struct rrr_message_broker {
	RRR_LL_HEAD(struct rrr_message_broker_costumer);
	pthread_mutex_t lock;
	pthread_t creator;
};

struct rrr_event_queue *rrr_message_broker_event_queue_get (
		struct rrr_message_broker_costumer *costumer
) {
	return costumer->events;
}

static void __rrr_message_broker_split_buffer_node_destroy (
		struct rrr_message_broker_split_buffer_node *node
) {
	struct rrr_fifo_protected_stats stats;
	rrr_fifo_protected_get_stats(&stats, &node->queue);
	RRR_DBG_1("\t- Split buffer stats for %s: %" PRIu64 "/%" PRIu64 "\n",
			(node->owner != NULL ? node->owner->name : "(not yet populated)"),
			stats.total_entries_deleted,
			stats.total_entries_written
	);
	rrr_fifo_protected_destroy(&node->queue);
	rrr_free(node);
}

static void __rrr_message_broker_costumer_incref_unlocked (
		struct rrr_message_broker_costumer *costumer
) {
	costumer->usercount++;
}

static void __rrr_message_broker_costumer_decref (
		int *did_destroy,
		struct rrr_message_broker_costumer *costumer
);

static int __rrr_message_broker_friend_add (
		struct rrr_message_broker_costumer **target,
		size_t target_size,
		struct rrr_message_broker_costumer *listener_costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	for (size_t i = 0; i < target_size; i++) {
		if (target[i] == NULL) {
			__rrr_message_broker_costumer_incref_unlocked(listener_costumer);
			target[i] = listener_costumer;
			listener_costumer = NULL;
			break;
		}
	}

	if (listener_costumer != NULL) {
		RRR_MSG_0("Friend list was full in __rrr_message_broker_friend_add\n");
		ret = 1;
	}

	return ret;
}

static void __rrr_message_broker_friends_clear (
		struct rrr_message_broker_costumer **target,
		size_t target_size
) {
	for (size_t i = 0; i < target_size; i++) {
		if (target[i] == NULL) {
			break;
		}
		int did_destroy_dummy = 0;
		__rrr_message_broker_costumer_decref(&did_destroy_dummy, target[i]);
		target[i] = NULL;
	}
}

static void __rrr_message_broker_costumer_destroy (
		struct rrr_message_broker_costumer *costumer
) {
	RRR_DBG_1 ("Message broker destroy costumer '%s'\n", costumer->name);

	if (costumer->slot != NULL) {
		rrr_msg_holder_slot_destroy(costumer->slot);
	}

	rrr_event_queue_destroy(costumer->events);
	rrr_fifo_protected_destroy(&costumer->main_queue);
	pthread_mutex_destroy(&costumer->split_buffers.lock);
	// Do this at the end in case we need to read the name in a debugger
	RRR_FREE_IF_NOT_NULL(costumer->name);
	rrr_free(costumer);
}

static void __rrr_message_broker_costumer_decref (
		int *did_destroy,
		struct rrr_message_broker_costumer *costumer
) {
	*did_destroy = 0;

	if (--(costumer->usercount) > 0) {
		return;
	}

	 __rrr_message_broker_costumer_destroy(costumer);

	*did_destroy = 1;
}

// Same as decref just with debug message
void rrr_message_broker_costumer_unregister (
		struct rrr_message_broker *broker,
		struct rrr_message_broker_costumer *costumer
) {
	RRR_DBG_8("Message broker unregistering costumer %s\n", costumer->name);

	pthread_mutex_lock(&broker->lock);
	int did_destroy;
	__rrr_message_broker_costumer_decref (&did_destroy, costumer);
	pthread_mutex_unlock(&broker->lock);
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

	struct rrr_message_broker_costumer *costumer = rrr_allocate(sizeof(*costumer));
	if (costumer == NULL) {
		RRR_MSG_0("Could not allocate memory for costumer in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out;
	}

	memset(costumer, '\0', sizeof(*costumer));

	if ((costumer->name = rrr_strdup(name_unique)) == NULL) {
		RRR_MSG_0("Could not allocate memory for name in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_free;
	}

	if (rrr_fifo_protected_init(&costumer->main_queue, rrr_msg_holder_decref_void) != 0) {
		RRR_MSG_0("Could not initialize buffer in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_free_name;
	}

	if ((rrr_posix_mutex_init(&costumer->split_buffers.lock, 0)) != 0) {
		RRR_MSG_0("Could not initialize mutex A in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_destroy_fifo;
	}

	if ((ret = rrr_event_queue_new(&costumer->events)) != 0){
		RRR_MSG_0("Could not create event queue in __rrr_message_broker_costumer_new\n");
		ret = 1;
		goto out_destroy_split_buffer_lock;
	}

	if (no_buffer) {
		if ((ret = rrr_msg_holder_slot_new(&costumer->slot)) != 0) {
			goto out_cleanup_events;
		}
	}

	costumer->usercount = 1;

	*result = costumer;

	goto out;
	out_cleanup_events:
		rrr_event_queue_destroy(costumer->events);
	out_destroy_split_buffer_lock:
		pthread_mutex_destroy(&costumer->split_buffers.lock);
	out_destroy_fifo:
		rrr_fifo_protected_destroy(&costumer->main_queue);
	out_free_name:
		rrr_free(costumer->name);
	out_free:
		rrr_free(costumer);
	out:
		return ret;
}

void rrr_message_broker_unregister_all (
		struct rrr_message_broker *broker
) {
	pthread_mutex_lock(&broker->lock);

	// There is a certain risk that ghost threads may crash when we do this
	RRR_LL_ITERATE_BEGIN(broker, struct rrr_message_broker_costumer);
		struct rrr_message_broker_costumer *costumer = node;

		__rrr_message_broker_friends_clear(costumer->write_notify_listeners, RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX);
		__rrr_message_broker_friends_clear(costumer->senders, RRR_MESSAGE_BROKER_SENDERS_MAX);

		struct rrr_fifo_protected_stats stats;

		if (costumer->slot != NULL) { 
			uint64_t entries_deleted = 0;
			uint64_t entries_written = 0;
			rrr_msg_holder_slot_get_stats(&entries_deleted, &entries_written, costumer->slot);
			rrr_fifo_protected_get_stats_populate(&stats, entries_written, entries_deleted);
		}
		else {
			rrr_fifo_protected_get_stats(&stats, &costumer->main_queue);
		}

		RRR_DBG_1 ("Message broker unregister costumer '%s', buffer stats: %" PRIu64 "/%" PRIu64 "\n",
				costumer->name, stats.total_entries_deleted, stats.total_entries_written
		);
		RRR_LL_DESTROY (
				&costumer->split_buffers,
				struct rrr_message_broker_split_buffer_node,
				__rrr_message_broker_split_buffer_node_destroy(node)
		);
	RRR_LL_ITERATE_END();

	if (RRR_DEBUGLEVEL_1) {
		RRR_LL_ITERATE_BEGIN(broker, struct rrr_message_broker_costumer);
			if (node->usercount > 1) {
				RRR_MSG_0("Warning: Message broker costumer '%s' still present while unregistering all with %i users, memory may leak\n",
						node->name, node->usercount - 1);
			}
		RRR_LL_ITERATE_END();
	}

	int did_destroy;
	RRR_LL_DESTROY(broker, struct rrr_message_broker_costumer, __rrr_message_broker_costumer_decref(&did_destroy, node));

	pthread_mutex_unlock(&broker->lock);
}

void rrr_message_broker_destroy (
		struct rrr_message_broker *broker
) {
	rrr_message_broker_unregister_all(broker);
	pthread_mutex_destroy(&broker->lock);
	rrr_free(broker);
}

int rrr_message_broker_new (
		struct rrr_message_broker **target
) {
	int ret = 0;

	*target = NULL;

	struct rrr_message_broker *broker = NULL;

	if ((broker = rrr_allocate(sizeof(*broker))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_message_broker_new\n");
		ret = 1;
		goto out;
	}

	memset(broker, '\0', sizeof (*broker));

	if (rrr_posix_mutex_init(&broker->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_message_broker_init\n");
		ret = 1;
		goto out_free;
	}

	pthread_mutex_lock(&broker->lock);
	broker->creator = pthread_self();
	pthread_mutex_unlock(&broker->lock);

	*target = broker;

	goto out;
//	out_destroy_mutex:
//		pthread_mutex_destroy(&broker->lock);
	out_free:
		rrr_free(broker);
	out:
		return ret;
}

static struct rrr_message_broker_costumer *__rrr_message_broker_costumer_find_by_name_unlocked (
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

struct rrr_message_broker_costumer *rrr_message_broker_costumer_find_by_name (
		struct rrr_message_broker *broker,
		const char *name
) {
	struct rrr_message_broker_costumer *ret = NULL;

	pthread_mutex_lock(&broker->lock);
	ret = __rrr_message_broker_costumer_find_by_name_unlocked(broker, name);
	pthread_mutex_unlock(&broker->lock);

	return ret;
}

void __rrr_message_broker_costumer_get_name (
		char *buf,
		size_t buf_size,
		struct rrr_message_broker *broker,
		struct rrr_message_broker_costumer *costumer
) {

	pthread_mutex_lock(&broker->lock);
	strncpy(buf, costumer->name, buf_size);
	pthread_mutex_unlock(&broker->lock);

	buf[buf_size - 1]  = '\0';
}

int rrr_message_broker_costumer_register (
		struct rrr_message_broker_costumer **result,
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
	__rrr_message_broker_costumer_incref_unlocked(costumer);

	// Usercount is now 2
	// - 1 count owned by message broker linked list
	// - 1 count owned by registrar

	*result = costumer;

	RRR_DBG_8("Message broker registered costumer '%s' handle is %p no buffer is %i\n", name_unique, costumer, no_buffer);

	out:
	pthread_mutex_unlock(&broker->lock);
	return ret;
}

static int __rrr_message_broker_split_output_buffer_new_and_add (
		struct rrr_message_broker_split_buffer_collection *target
) {
	int ret = 0;

	struct rrr_message_broker_split_buffer_node *node = rrr_allocate(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_message_broker_split_output_buffer_new\n");
		ret = 1;
		goto out;
	}

	memset(node, '\0', sizeof(*node));

	if (rrr_fifo_protected_init(&node->queue, rrr_msg_holder_decref_void) != 0) {
		RRR_MSG_0("Could not initialize buffer in __rrr_message_broker_split_output_buffer_new\n");
		ret = 1;
		goto out_free;
	}

	RRR_LL_APPEND(target, node);
	node = NULL;

	goto out;
	out_free:
		rrr_free(node);
	out:
		return ret;
}

// Call in preload stage only from main thread.
// No locking, call prior to starting threads. Number of slots
// have to match or exceed the number of different reader threads which
// will read from us, if not we will give a BUG()
int rrr_message_broker_setup_split_output_buffer (
		struct rrr_message_broker_costumer *costumer,
		rrr_length slots
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (costumer->slot != NULL) {
		// This function is safe to call multiple times
		if ((ret = rrr_msg_holder_slot_reader_count_set(costumer->slot, slots)) != 0) {
			goto out;
		}
	}
	else {
		if (RRR_LL_COUNT(&costumer->split_buffers) > 0) {
			RRR_BUG("BUG: rrr_message_broker_setup_split_output_buffer called more than once\n");
		}

		while (slots--) {
			if ((ret = __rrr_message_broker_split_output_buffer_new_and_add(&costumer->split_buffers)) != 0) {
				goto out;
			}
		}
	}

	costumer->split_buffers_active = 1;

	out:
	return ret;
}

static int __rrr_message_broker_write_notifications_send_final (
		struct rrr_message_broker_costumer *listener,
		uint8_t amount,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	return rrr_event_pass (
			listener->events,
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			amount,
			check_cancel_callback,
			check_cancel_callback_arg
	);
}

static int __rrr_message_broker_write_notifications_send_all (
		struct rrr_message_broker_costumer *costumer,
		uint8_t amount,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	for (int i = 0; i < RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX; i++) {
		struct rrr_message_broker_costumer *listener = costumer->write_notify_listeners[i];
		if (listener == NULL) {
			goto out;
		}

		if ((ret = __rrr_message_broker_write_notifications_send_final (
				listener,
				amount,
				check_cancel_callback,
				check_cancel_callback_arg
		)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_message_broker_write_notifications_send_random (
		struct rrr_message_broker_costumer *costumer,
		uint8_t amount,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	rrr_biglength max = 0;
	for (int i = 0; i < RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX; i++) {
		if (costumer->write_notify_listeners[i] == NULL) {
			break;
		}
		max++;
	}

	if (max > 0) {
		rrr_biglength target = (rrr_biglength) rrr_rand();
		target = target % max;
		return __rrr_message_broker_write_notifications_send_final (
				costumer->write_notify_listeners[target],
				amount,
				check_cancel_callback,
				check_cancel_callback_arg
		);
	}

	return 0;
}

static int __rrr_message_broker_write_notifications_send (
		struct rrr_message_broker_costumer *costumer,
		uint8_t amount,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	return costumer->split_buffers_active
		? __rrr_message_broker_write_notifications_send_all(costumer, amount, check_cancel_callback, check_cancel_callback_arg)
		: __rrr_message_broker_write_notifications_send_random(costumer, amount, check_cancel_callback, check_cancel_callback_arg)
	;
}

struct rrr_message_broker_write_entry_intermediate_callback_data {
	struct rrr_message_broker_costumer *costumer;
	const struct sockaddr *addr;
	socklen_t socklen;
	uint8_t protocol;
	uint8_t entries_written;
	int (*callback)(struct rrr_msg_holder *new_entry, void *arg);
	void *callback_arg;
	int (*check_cancel_callback)(void *arg);
	void *check_cancel_callback_arg;
	const struct rrr_instance_friend_collection *nexthops;
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

static int __rrr_message_broker_write_entry_callback_intermediate (
		int *write_drop,
		int *write_again,
		struct rrr_msg_holder *entry,
		const struct rrr_instance_friend_collection *nexthops,
		int (*callback)(struct rrr_msg_holder *new_entry, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*write_drop = 0;
	*write_again = 0;

	entry->buffer_time = rrr_time_get_64();

	if (nexthops != NULL) {
		rrr_msg_holder_nexthops_set(entry, nexthops);
	}

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

	if ((ret = __rrr_message_broker_write_entry_callback_intermediate (
			do_drop,
			do_again,
			entry,
			callback_data->nexthops,
			callback_data->callback,
			callback_data->callback_arg
	)) != 0) {
		ret = 1;
		goto out;
	}

	if (!(*do_drop)) {
		callback_data->entries_written++;
	}

	if (callback_data->entries_written == 0xff) {
		*do_again = 0;
	}

	out:
	return ret;
}

static int __rrr_message_broker_write_entry_intermediate (RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS) {
	struct rrr_message_broker_write_entry_intermediate_callback_data *callback_data = arg;

	int ret = RRR_FIFO_PROTECTED_OK;

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
		ret = RRR_FIFO_PROTECTED_GLOBAL_ERR;
		goto out;
	}

	// Callback must always unlock entry. If the callback is possibly slow
	// and has cancellation points, it must wrap unlock in pthread_cleanup_push

	rrr_msg_holder_lock(entry);

	int write_drop = 0;
	int write_again = 0;

	if ((ret = __rrr_message_broker_write_entry_callback_intermediate (
			&write_drop,
			&write_again,
			entry,
			callback_data->nexthops,
			callback_data->callback,
			callback_data->callback_arg
	)) != 0) {
		ret = RRR_FIFO_PROTECTED_GLOBAL_ERR;
		goto out;
	}

	if (callback_data->check_cancel_callback(callback_data->check_cancel_callback_arg) == 0) {
		if (write_again) {
			ret |= RRR_FIFO_PROTECTED_WRITE_AGAIN;
		}
	}

	if (write_drop) {
		ret |= RRR_FIFO_PROTECTED_WRITE_DROP;
		goto out;
	}

	if ((++callback_data->entries_written) == 0xff) {
		ret &= ~(RRR_FIFO_PROTECTED_WRITE_AGAIN);
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
		struct rrr_message_broker_costumer *costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	*result = 0;

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
		if ((ret = rrr_fifo_protected_with_write_lock_do (
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
	return ret;
}

// Callback must return the entry in unlocked state to us with refcount being excactly 1
int rrr_message_broker_write_entry (
		struct rrr_message_broker_costumer *costumer,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint8_t protocol,
		const struct rrr_instance_friend_collection *nexthops,
		int (*callback)(struct rrr_msg_holder *new_entry, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg

) {
	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_message_broker_write_entry_intermediate_callback_data callback_data = {
			costumer,
			addr,
			socklen,
			protocol,
			0,
			callback,
			callback_arg,
			check_cancel_callback,
			check_cancel_callback_arg,
			nexthops
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
		if ((ret = rrr_fifo_protected_write (
				&costumer->main_queue,
				__rrr_message_broker_write_entry_intermediate,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer (main_queue) in rrr_message_broker_write_entry\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	if (callback_data.entries_written > 0) {
		ret = __rrr_message_broker_write_notifications_send (
				costumer,
				callback_data.entries_written,
				check_cancel_callback,
				check_cancel_callback_arg
		);
	}

	out:
	return ret;
}

struct rrr_message_broker_clone_and_write_entry_callback_data {
	const struct rrr_msg_holder *source;
	const struct rrr_instance_friend_collection *nexthops;
};

static int __rrr_message_broker_clone_and_write_entry_callback (RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS) {
	struct rrr_message_broker_clone_and_write_entry_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_holder *target = NULL;

	if (rrr_msg_holder_util_clone_no_locking(&target, callback_data->source) != 0) {
		RRR_MSG_0("Could not clone ip buffer entry in %s\n", __func__);
		ret = 1;
		goto out;
	}

	rrr_msg_holder_lock(target);
	target->buffer_time = rrr_time_get_64();
	ret = rrr_msg_holder_nexthops_set(target, callback_data->nexthops);
	rrr_msg_holder_unlock(target);

	if (ret != 0) {
		RRR_MSG_0("Failed to set nexthops in %s\n", __func__);
		goto out;
	}

	*data = (char *) target;
	*size = sizeof(*target);
	*order = 0;

	target = NULL;

	out:
	if (target != NULL) {
		rrr_msg_holder_decref(target);
	}
	return ret;
}

struct rrr_message_broker_clone_and_write_entry_slot_callback_data {
	const struct rrr_instance_friend_collection *nexthops;
};
				
static void __rrr_message_broker_clone_and_write_entry_slot_callback (
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct rrr_message_broker_clone_and_write_entry_slot_callback_data *callback_data = arg;

	rrr_msg_holder_lock(entry);
	entry->buffer_time = rrr_time_get_64();
	if (rrr_msg_holder_nexthops_set(entry, callback_data->nexthops) != 0) {
		RRR_BUG("Unhandleable error: Failed to set nexthops in %s\n", __func__);
	}
	rrr_msg_holder_unlock(entry);
}

int rrr_message_broker_clone_and_write_entry (
		struct rrr_message_broker_costumer *costumer,
		const struct rrr_msg_holder *entry,
		const struct rrr_instance_friend_collection *nexthops
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (costumer->slot != NULL) {
		struct rrr_message_broker_clone_and_write_entry_slot_callback_data callback_data = {
			nexthops
		};

		if ((ret = rrr_msg_holder_slot_write_clone (
				costumer->slot,
				entry,
				NULL,
				NULL,
				__rrr_message_broker_clone_and_write_entry_slot_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}
	else {
		struct rrr_message_broker_clone_and_write_entry_callback_data callback_data = {
			entry,
			nexthops
		};

		if (rrr_fifo_protected_write (
				&costumer->main_queue,
				__rrr_message_broker_clone_and_write_entry_callback,
				&callback_data
		) != 0) {
			RRR_MSG_0("Error while writing to buffer in rrr_message_broker_clone_and_write_entry_no_unlock\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	ret = __rrr_message_broker_write_notifications_send (
			costumer,
			1,
			NULL,
			NULL
	);

	out:
	return ret;
}

static int __rrr_message_broker_write_entry_unsafe_callback(RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS) {
	struct rrr_msg_holder *entry = arg;

	*data = (char *) entry;
	*size = sizeof(*entry);
	*order = 0;

	rrr_msg_holder_incref_while_locked(entry);

	return 0;
}

// Only to be used when we already are inside a read callback and the
// entry we passed in is guaranteed to have been allocated and modified
// exclusively in message broker context.
int rrr_message_broker_incref_and_write_entry_unsafe (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_msg_holder *entry,
		const struct rrr_instance_friend_collection *nexthops,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	rrr_msg_holder_lock(entry);
	entry->buffer_time = rrr_time_get_64();
	ret = rrr_msg_holder_nexthops_set(entry, nexthops);
	rrr_msg_holder_unlock(entry);

	if (ret != 0) {
		RRR_MSG_0("Failed to set nexthops in %s\n", __func__);
		goto out;
	}

	if (costumer->slot != NULL) {
		if ((ret = rrr_msg_holder_slot_write_incref (
				costumer->slot,
				entry,
				check_cancel_callback,
				check_cancel_callback_arg
		)) != 0) {
			goto out;
		}
	}
	else {
		if (rrr_fifo_protected_write (
				&costumer->main_queue,
				__rrr_message_broker_write_entry_unsafe_callback,
				entry
		) != 0) {
			RRR_MSG_0("Error while writing to buffer in rrr_message_broker_write_entry_unsafe\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	ret = __rrr_message_broker_write_notifications_send (
			costumer,
			1,
			check_cancel_callback,
			check_cancel_callback_arg
	);

	out:
	return ret;
}

int __rrr_message_broker_write_entries_from_collection_callback (RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS) {
	struct rrr_msg_holder_collection *collection = arg;

	struct rrr_msg_holder *entry = RRR_LL_SHIFT(collection);

	*data = (char*) entry;
	*size = sizeof(*entry);
	*order = 0;

	return (RRR_LL_COUNT(collection) > 0 ? RRR_FIFO_PROTECTED_WRITE_AGAIN : RRR_FIFO_PROTECTED_OK);
}

// This function removes entries one by one from the given collection. All refcounts passed in
// must equal exactly 1. If this function ails, entries might still reside inside the collection
// which have not yet been added to the buffer. The caller owns these. Read about 'unsafe' above.
int rrr_message_broker_write_entries_from_collection_unsafe (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_msg_holder_collection *collection,
		const struct rrr_instance_friend_collection *nexthops,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (RRR_LL_COUNT(collection) == 0) {
		goto out;
	}

	int written_entries = RRR_LL_COUNT(collection);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);
		node->buffer_time = rrr_time_get_64();
		ret = rrr_msg_holder_nexthops_set(node, nexthops);
		rrr_msg_holder_unlock(node);
		if (ret != 0) {
			RRR_MSG_0("Failed to set nexthops in %s\n", __func__);
			goto out;
		}
	RRR_LL_ITERATE_END();

	if (costumer->slot != NULL) {
		ret = rrr_msg_holder_slot_write_from_collection(costumer->slot, collection, check_cancel_callback, check_cancel_callback_arg);
	}
	else {
		ret = rrr_fifo_protected_write(&costumer->main_queue, __rrr_message_broker_write_entries_from_collection_callback, collection);
	}

	while (written_entries > 0) {
		if (written_entries > 0xff) {
			ret = __rrr_message_broker_write_notifications_send (
					costumer,
					0xff,
					check_cancel_callback,
					check_cancel_callback_arg
			);
			written_entries -= 0xff;
		}
		else {
			ret = __rrr_message_broker_write_notifications_send (
					costumer,
					(uint8_t) written_entries,
					check_cancel_callback,
					check_cancel_callback_arg
			);
			written_entries = 0;
		}
	}

	out:
	return ret;
}

struct rrr_message_broker_read_entry_intermediate_callback_data {
	uint16_t *amount;
	struct rrr_message_broker_costumer *source;
	struct rrr_message_broker_costumer *self;
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

	if ((callback_data->broker_poll_flags & RRR_MESSAGE_BROKER_POLL_F_CHECK_BACKSTOP) &&
	     entry->source == callback_data->self
	) {
		if (RRR_DEBUGLEVEL_2) {
			RRR_DBG_2("Message broker backstop in %s: Message read from %s originates from self\n",
					callback_data->self->name, callback_data->source->name);
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

static int __rrr_message_broker_poll_delete_intermediate (RRR_FIFO_PROTECTED_READ_CALLBACK_ARGS) {
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

	if (--(*callback_data->amount) == 0) {
		ret |= RRR_FIFO_PROTECTED_SEARCH_STOP;
	}

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

	--(*callback_data->amount);

	// We always stop, the slot only has at most one element.
	return ret & ~(RRR_FIFO_PROTECTED_SEARCH_STOP);
}

static void __rrr_message_broker_get_source_buffer (
		int *source_buffer_is_main,
		struct rrr_fifo_protected **use_buffer,
		struct rrr_message_broker_costumer *costumer,
		struct rrr_message_broker_costumer *self
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

	struct rrr_fifo_protected *found_buffer = NULL;

	int pos = 0;
	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		if (node->owner == self) {
			found_buffer = &node->queue;
			RRR_LL_ITERATE_LAST();
		}
		else if (node->owner == NULL) {
			// Allocate
			RRR_DBG_1("Message broker costumer %s add split buffer reader %s at position %i\n",
				costumer->name, self->name, pos);
			node->owner = self;
			found_buffer = &node->queue;
			RRR_LL_ITERATE_LAST();
		}
		pos++;
	RRR_LL_ITERATE_END();

	if (found_buffer == NULL) {
		RRR_BUG("Not enough slots in __rrr_message_broker_get_source_buffer\n");
	}

	*use_buffer = found_buffer;

	out:
	pthread_mutex_unlock(&costumer->split_buffers.lock);
}

static int __rrr_message_broker_split_buffers_fill_callback (RRR_FIFO_PROTECTED_READ_CALLBACK_ARGS) {
	struct rrr_message_broker_costumer *costumer = arg;
	struct rrr_msg_holder *entry = (struct rrr_msg_holder *) data;

	(void)(size);

	int ret = 0;

	// Split buffer lock must be held by caller

	rrr_msg_holder_lock(entry);

	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		struct rrr_message_broker_clone_and_write_entry_callback_data callback_data = {
			entry,
			&entry->nexthops
		};

		// Use delayed write in case there are other threads reading from their buffer
		if ((ret = rrr_fifo_protected_write_delayed (
				&node->queue,
				__rrr_message_broker_clone_and_write_entry_callback,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Error while writing to buffer in __rrr_message_broker_split_buffers_fill_callback\n");
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	rrr_msg_holder_unlock(entry);
	return ret | RRR_FIFO_PROTECTED_SEARCH_FREE;
}

static int __rrr_message_broker_split_buffers_fill (
		struct rrr_message_broker_costumer *costumer
) {
	int ret = 0;

	if (rrr_fifo_protected_get_entry_count(&costumer->main_queue) == 0) {
		goto out_no_unlock;
	}

	// Somebody else is probably doing this already
	if (pthread_mutex_trylock(&costumer->split_buffers.lock) != 0) {
		goto out_no_unlock;
	}

	if ((ret = rrr_fifo_protected_read_clear_forward (
			&costumer->main_queue,
			__rrr_message_broker_split_buffers_fill_callback,
			costumer
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
    struct rrr_fifo_protected *source_buffer = NULL;                     \
    do {                                                                 \
        int source_buffer_is_main = 0;                                   \
        __rrr_message_broker_get_source_buffer (                         \
    	    &source_buffer_is_main, &source_buffer, costumer, self       \
        ); if (source_buffer_is_main == 0 &&                             \
    	    (ret = __rrr_message_broker_split_buffers_fill(costumer)     \
        ) != 0) { goto out; }} while(0)

#define FRIENDS_ITERATE_BEGIN(list,max)                                  \
    do {for (size_t i = 0; i < max; i++) {                               \
        if (self->list[i] == NULL) {                                     \
            break;                                                       \
        }                                                                \
        struct rrr_message_broker_costumer *costumer = self->list[i]

#define FRIENDS_ITERATE_END()                                            \
    }} while(0)

size_t rrr_message_broker_senders_count (
		struct rrr_message_broker_costumer *self
) {
	size_t ret = 0;

	FRIENDS_ITERATE_BEGIN(senders,RRR_MESSAGE_BROKER_SENDERS_MAX);
		(void)(costumer);
		ret++;
	FRIENDS_ITERATE_END();

	return ret;
}

int rrr_message_broker_poll_delete (
		uint16_t *amount,
		struct rrr_message_broker_costumer *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_message_broker_read_entry_intermediate_callback_data callback_data = {
			amount,
			NULL,
			self,
			broker_poll_flags,
			callback,
			callback_arg
	};

	FRIENDS_ITERATE_BEGIN(senders,RRR_MESSAGE_BROKER_SENDERS_MAX);
		callback_data.source = costumer;

		if (costumer->slot != NULL) {
			if ((ret = rrr_msg_holder_slot_read (
					costumer->slot,
					self,
					__rrr_message_broker_poll_delete_slot_intermediate,
					&callback_data
			)) != 0) {
				goto out;
			}
		}
		else {
			RRR_MESSAGE_BROKER_POLL_SPLIT_BUFFER_HANDLING();

			if ((ret = rrr_fifo_protected_read_clear_forward (
					source_buffer,
					__rrr_message_broker_poll_delete_intermediate,
					&callback_data
			)) != 0) {
				goto out;
			}
		}

		if (*amount == 0) {
			break;
		}
	FRIENDS_ITERATE_END();

	out:
	return ret;
}

int rrr_message_broker_set_ratelimit (
		struct rrr_message_broker_costumer *costumer,
		int set
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	rrr_fifo_protected_set_do_ratelimit(&costumer->main_queue, set);

	RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
		rrr_fifo_protected_set_do_ratelimit(&node->queue, set);
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_message_broker_get_entry_count_and_ratelimit (
		unsigned int *entry_count,
		int *ratelimit_active,
		struct rrr_message_broker_costumer *costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	*entry_count = 0;
	*ratelimit_active = 0;

	if (costumer->slot != NULL) {
		*ratelimit_active = 0;
		*entry_count = rrr_msg_holder_slot_count(costumer->slot);
	}
	else {
		// Ratelimit is the same on split buffers
		*ratelimit_active = rrr_fifo_protected_get_ratelimit_active(&costumer->main_queue);
		*entry_count = rrr_fifo_protected_get_entry_count(&costumer->main_queue);

		RRR_LL_ITERATE_BEGIN(&costumer->split_buffers, struct rrr_message_broker_split_buffer_node);
			(*entry_count) += rrr_fifo_protected_get_entry_count(&node->queue);
		RRR_LL_ITERATE_END();
	}

	return ret;
}

// Note that stats from any split queues are not retrieved
int rrr_message_broker_get_fifo_stats (
		struct rrr_fifo_protected_stats *target,
		struct rrr_message_broker_costumer *costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (costumer->slot != NULL) {
		uint64_t entries_deleted = 0;
		uint64_t entries_written = 0;
		rrr_msg_holder_slot_get_stats(&entries_deleted, &entries_written, costumer->slot);
		rrr_fifo_protected_get_stats_populate(target, entries_written, entries_deleted);
	}
	else {
		rrr_fifo_protected_get_stats(target, &costumer->main_queue);
	}

	return ret;
}

int rrr_message_broker_with_ctx_and_buffer_lock_do (
		struct rrr_message_broker_costumer *costumer,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if (costumer->slot != NULL) {
		ret = rrr_msg_holder_slot_with_lock_do(costumer->slot, callback, callback_arg_1, callback_arg_2);
	}
	else {
		ret = rrr_fifo_protected_with_write_lock_do(&costumer->main_queue, callback, callback_arg_1, callback_arg_2);
	}

	return ret;
}

static int __rrr_message_broker_write_listener_add (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_message_broker_costumer *listener_costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if ((ret = __rrr_message_broker_friend_add(
			costumer->write_notify_listeners,
			RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX,
			listener_costumer
	)) != 0) {
		RRR_MSG_0("Failed to add write notification listener to costumer %s, too many listeners\n", costumer->name);
	}

	return ret;
}

// No locking, call prior to starting threads
int rrr_message_broker_sender_add (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_message_broker_costumer *listener_costumer
) {
	int ret = RRR_MESSAGE_BROKER_OK;

	if ((ret = __rrr_message_broker_friend_add (
			costumer->senders,
			RRR_MESSAGE_BROKER_SENDERS_MAX,
			listener_costumer
	)) != 0) {
		RRR_MSG_0("Failed to add sender to costumer %s, too many senders\n", costumer->name);
		goto out;
	}

	// Reverse arguments
	ret = __rrr_message_broker_write_listener_add(listener_costumer, costumer);

	out:
	return ret;
}
