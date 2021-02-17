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

#ifndef RRR_MESSAGE_BROKER_H
#define RRR_MESSAGE_BROKER_H

#include <pthread.h>
#include <sys/socket.h>

#include "buffer.h"
#include "poll_helper.h"
#include "event.h"
#include "util/linked_list.h"

#define RRR_MESSAGE_BROKER_OK		0
#define RRR_MESSAGE_BROKER_POST		RRR_MESSAGE_BROKER_OK
#define RRR_MESSAGE_BROKER_ERR		(1<<0)
#define RRR_MESSAGE_BROKER_DROP		(1<<1)
#define RRR_MESSAGE_BROKER_AGAIN	(1<<2)

#define RRR_MESSAGE_BROKER_POLL_F_CHECK_BACKSTOP    (1<<0)

#define RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX 64

struct rrr_msg_holder;
struct rrr_msg_holder_collection;
struct rrr_msg_holder_slot;

// Do not cast this to struct rrr_message_broker_costumer except from
// inside this framework, memory might become freed up at any time
typedef void rrr_message_broker_costumer_handle;

struct rrr_message_broker_split_buffer_node {
	RRR_LL_NODE(struct rrr_message_broker_split_buffer_node);
	struct rrr_fifo_buffer queue;
	rrr_message_broker_costumer_handle *owner;
};

struct rrr_message_broker_split_buffer_collection {
	RRR_LL_HEAD(struct rrr_message_broker_split_buffer_node);
	pthread_mutex_t lock;
};

struct rrr_message_broker_costumer {
	RRR_LL_NODE(struct rrr_message_broker_costumer);
	struct rrr_fifo_buffer main_queue;
	struct rrr_message_broker_split_buffer_collection split_buffers;
	struct rrr_msg_holder_slot *slot;
	char *name;
	int usercount;
	int flags;
	uint64_t unique_counter;
	pthread_mutex_t event_lock;
	pthread_cond_t event_cond;
	struct rrr_event_queue events;
	struct rrr_message_broker_costumer *write_notify_listeners[RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX];
};

struct rrr_message_broker {
	RRR_LL_HEAD(struct rrr_message_broker_costumer);
	pthread_mutex_t lock;
	pthread_t creator;
};

void rrr_message_broker_unregister_all (
		struct rrr_message_broker *broker
);
void rrr_message_broker_costumer_unregister (
		rrr_message_broker_costumer_handle *handle
);
void rrr_message_broker_cleanup (
		struct rrr_message_broker *broker
);
int rrr_message_broker_init (
		struct rrr_message_broker *broker
);
rrr_message_broker_costumer_handle *rrr_message_broker_costumer_find_by_name (
		struct rrr_message_broker *broker,
		const char *name
);
int rrr_message_broker_costumer_register (
		rrr_message_broker_costumer_handle **result,
		struct rrr_message_broker *broker,
		const char *name_unique,
		int no_buffer
);
int rrr_message_broker_setup_split_output_buffer (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int slots
);
int rrr_message_broker_get_next_unique_id (
		uint64_t *result,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
);
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
);
int rrr_message_broker_clone_and_write_entry (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		const struct rrr_msg_holder *entry
);
int rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		struct rrr_msg_holder *entry,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_message_broker_write_entries_from_collection_unsafe (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		struct rrr_msg_holder_collection *collection,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_message_broker_poll_discard (
		int *discarded_count,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self
);
int rrr_message_broker_poll_delete (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
);
int rrr_message_broker_poll (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
);
int rrr_message_broker_set_ratelimit (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int set
);
int rrr_message_broker_get_entry_count_and_ratelimit (
		int *entry_count,
		int *ratelimit_active,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
);
int rrr_message_broker_get_fifo_stats (
		struct rrr_fifo_buffer_stats *target,
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle
);
int rrr_message_broker_with_ctx_do (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
);
int rrr_message_broker_event_dispatch (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS),
		void *arg
);
int rrr_message_broker_with_ctx_and_buffer_lock_do (
		struct rrr_message_broker *broker,
		rrr_message_broker_costumer_handle *handle,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
);
void rrr_message_broker_write_listener_init (
		rrr_message_broker_costumer_handle *handle,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
);
int rrr_message_broker_write_listener_add (
		rrr_message_broker_costumer_handle *handle,
		rrr_message_broker_costumer_handle *listener_handle
);

#endif /* RRR_MESSAGE_BROKER_H */
