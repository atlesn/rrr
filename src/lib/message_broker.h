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

#define RRR_MESSAGE_BROKER_SENDERS_MAX                64
#define RRR_MESSAGE_BROKER_WRITE_NOTIFY_LISTENER_MAX  RRR_MESSAGE_BROKER_SENDERS_MAX

struct rrr_msg_holder;
struct rrr_msg_holder_collection;
struct rrr_msg_holder_slot;
struct rrr_message_broker_costumer;
struct rrr_message_broker;

void rrr_message_broker_unregister_all (
		struct rrr_message_broker *broker
);
void rrr_message_broker_costumer_unregister (
		struct rrr_message_broker *broker,
		struct rrr_message_broker_costumer *costumer
);
void rrr_message_broker_destroy (
		struct rrr_message_broker *broker
);
int rrr_message_broker_new (
		struct rrr_message_broker **target
);
struct rrr_message_broker_costumer *rrr_message_broker_costumer_find_by_name (
		struct rrr_message_broker *broker,
		const char *name
);
int rrr_message_broker_costumer_register (
		struct rrr_message_broker_costumer **result,
		struct rrr_message_broker *broker,
		const char *name_unique,
		int no_buffer
);
int rrr_message_broker_setup_split_output_buffer (
		struct rrr_message_broker_costumer *costumer,
		int slots
);
int rrr_message_broker_get_next_unique_id (
		uint64_t *result,
		struct rrr_message_broker_costumer *costumer
);
int rrr_message_broker_write_entry (
		struct rrr_message_broker_costumer *costumer,
		const struct sockaddr *addr,
		socklen_t socklen,
		int protocol,
		int (*callback)(struct rrr_msg_holder *new_entry, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_message_broker_clone_and_write_entry (
		struct rrr_message_broker_costumer *costumer,
		const struct rrr_msg_holder *entry
);
int rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_msg_holder *entry,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_message_broker_write_entries_from_collection_unsafe (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_msg_holder_collection *collection,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
size_t rrr_message_broker_senders_count (
		struct rrr_message_broker_costumer *self
);
int rrr_message_broker_poll_delete (
		uint16_t *amount,
		struct rrr_message_broker_costumer *self,
		int broker_poll_flags,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg,
		unsigned int wait_milliseconds
);
int rrr_message_broker_set_ratelimit (
		struct rrr_message_broker_costumer *costumer,
		int set
);
int rrr_message_broker_get_entry_count_and_ratelimit (
		int *entry_count,
		int *ratelimit_active,
		struct rrr_message_broker_costumer *costumer
);
int rrr_message_broker_get_fifo_stats (
		struct rrr_fifo_buffer_stats *target,
		struct rrr_message_broker_costumer *costumer
);
struct rrr_event_queue *rrr_message_broker_event_queue_get (
		struct rrr_message_broker_costumer *costumer
);
int rrr_message_broker_with_ctx_and_buffer_lock_do (
		struct rrr_message_broker_costumer *costumer,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
);
int rrr_message_broker_sender_add (
		struct rrr_message_broker_costumer *costumer,
		struct rrr_message_broker_costumer *listener_costumer
);

#endif /* RRR_MESSAGE_BROKER_H */
