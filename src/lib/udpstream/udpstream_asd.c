/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "../log.h"
#include "../allocator.h"
#include "src/lib/udpstream/udpstream.h"
#include "udpstream_asd.h"
#include "../buffer.h"
#include "../read.h"
#include "../ip/ip.h"
#include "../event/event_collection.h"
#include "../message_holder/message_holder.h"
#include "../message_holder/message_holder_struct.h"
#include "../socket/rrr_socket_constants.h"
#include "../messages/msg_checksum.h"
#include "../messages/msg_msg.h"
#include "../messages/msg.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"

#define RRR_UDPSTREAM_ASD_CONNECT_TIMEOUT_MS 5000
#define RRR_UDPSTREAM_ASD_BUFFER_MAX 500
#define RRR_UDPSTREAM_ASD_MESSAGE_ID_MAX 0xffffffff
#define RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS (RRR_UDPSTREAM_RESEND_INTERVAL_FRAME_MS * 4)

// Max unreleased messages awaiting release ACK
#define RRR_UDPSTREAM_ASD_RELEASE_QUEUE_MAX (RRR_UDPSTREAM_WINDOW_SIZE_MAX * 2)

// Note : The following method to avoid duplicate IDs is very inefficient
// This many delivered messages must follow a message before it is deleted from release queue
#define RRR_UDPSTREAM_ASD_DELIVERY_GRACE_COUNTER (RRR_UDPSTREAM_WINDOW_SIZE_MAX)

#define RRR_UDPSTREAM_ASD_RELEASE_QUEUE_WINDOW_SIZE_REDUCTION_THRESHOLD 200
#define RRR_UDPSTREAM_ASD_WINDOW_SIZE_REDUCTION_AMOUNT -20

#define RRR_UDPSTREAM_ASD_ACK_FLAGS_RST       (0<<0)
#define RRR_UDPSTREAM_ASD_ACK_FLAGS_MSG       (1<<0)
#define RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK      (1<<1)
#define RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK      (1<<2)
#define RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK      (1<<3)
#define RRR_UDPSTREAM_ASD_ACK_FLAGS_DELIVERED (1<<15)

// The control packets resembles functionality of MQTT QoS2, for this
// purpose called "assured single delivery". This type of management of whole
// messages is not performed by the udpstream API and must be implemented by API user.

//  MSG = Original message
// DACK = Delivery ACK
// RACK = Release ACK
// CACK = Complete ACK

struct rrr_udpstream_asd_queue_entry {
	RRR_LL_NODE(struct rrr_udpstream_asd_queue_entry);
	struct rrr_msg_holder *message;
	uint32_t message_id;
	uint64_t send_time;
	int delivered_grace_counter;
	int ack_status_flags;
	int send_count;
};

struct rrr_udpstream_asd_queue {
	RRR_LL_NODE(struct rrr_udpstream_asd_queue);
	RRR_LL_HEAD(struct rrr_udpstream_asd_queue_entry);
	uint32_t source_connect_handle;
};

struct rrr_udpstream_asd_queue_collection {
	RRR_LL_HEAD(struct rrr_udpstream_asd_queue);
};

struct rrr_udpstream_asd {
	struct rrr_udpstream udpstream;

	// Stores inbound messages from multiple remote hosts
	struct rrr_udpstream_asd_queue_collection release_queues;

	// Stores outbound messages to default remote host
	struct rrr_udpstream_asd_queue send_queue;

	struct rrr_event_queue *queue;
	struct rrr_event_collection events;
	rrr_event_handle event_periodic;

	char *remote_host;
	char *remote_port;

	int is_connected;
	uint64_t connection_attempt_time;
	uint32_t connect_handle;

	uint32_t message_id_pos;

	unsigned int sent_count;
	unsigned int delivered_count;

	int delivery_grace_started_count;
	
	int reset_on_next_connect;

	int (*receive_callback)(struct rrr_msg_holder *message, void *arg);
	void *receive_callback_arg;
};

struct rrr_udpstream_asd_control_msg {
	uint32_t flags;
	uint32_t message_id;
} __attribute((packed));

static struct rrr_udpstream_asd_control_msg __rrr_udpstream_asd_control_msg_split (uint64_t application_data) {
	struct rrr_udpstream_asd_control_msg result;

	result.flags = application_data >> 32;
	result.message_id = application_data & 0xffffffff;

	return result;
}

static uint64_t __rrr_udpstream_asd_control_msg_join (struct rrr_udpstream_asd_control_msg msg) {
	uint64_t result;

	result = (((uint64_t) msg.flags) << 32) | ((uint64_t) msg.message_id);

	return result;
}

static int __rrr_udpstream_asd_queue_entry_destroy (
		struct rrr_udpstream_asd_queue_entry *entry
) {
	if (entry->message != NULL) {
		rrr_msg_holder_decref(entry->message);
	}
	rrr_free(entry);
	return 0;
}

static struct rrr_udpstream_asd_queue_entry *__rrr_udpstream_asd_queue_find_entry (
		struct rrr_udpstream_asd_queue *queue,
		uint32_t message_id
) {
	if (RRR_LL_FIRST(queue) != NULL && message_id < RRR_LL_FIRST(queue)->message_id) {
		return NULL;
	}
	if (RRR_LL_LAST(queue) != NULL && message_id > RRR_LL_LAST(queue)->message_id) {
		return NULL;
	}

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (node->message_id > message_id) {
			return NULL;
		}
		if (node->message_id == message_id) {
			return node;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

static void __rrr_udpstream_asd_queue_reset_send_times (
		struct rrr_udpstream_asd_queue *queue
) {
	int count = 0;
	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (node->send_time != 0) {
			count++;
			node->send_time = rrr_time_get_64() - (2 * RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS * 1000);
		}
	RRR_LL_ITERATE_END();
	RRR_DBG_3("ASD reset send time for %i entries\n", count);
}

static int __rrr_udpstream_asd_queue_entry_deliver (
		struct rrr_udpstream_asd *session,
		struct rrr_udpstream_asd_queue_entry *node
) {
	int ret = 0;

	if (node->delivered_grace_counter != 0) {
		goto out;
	}

	struct rrr_msg_holder *message = node->message;

	RRR_DBG_3("ASD D %u:%u MSG timestamp %" PRIu64 ", grace started\n",
			session->connect_handle, node->message_id, node->send_time);

	// Callback must ALWAYS unlock
	rrr_msg_holder_lock(message);
	if ((ret = session->receive_callback(message, session->receive_callback_arg)) != 0) {
		RRR_MSG_0("Error from callback in __rrr_udpstream_asd_queue_entry_deliver\n");
		ret = 1;
		goto out;
	}

	rrr_msg_holder_decref(message);
	node->message = NULL;

	node->delivered_grace_counter = RRR_UDPSTREAM_ASD_DELIVERY_GRACE_COUNTER;
	session->delivery_grace_started_count++;

	out:
	return ret;
}

static struct rrr_udpstream_asd_queue_entry *__rrr_udpstream_asd_queue_collection_find_entry (
		struct rrr_udpstream_asd_queue_collection *collection,
		uint32_t connect_handle,
		uint32_t message_id
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_udpstream_asd_queue);
		if (node->source_connect_handle == connect_handle) {
			return __rrr_udpstream_asd_queue_find_entry(node, message_id);
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

static int __rrr_udpstream_asd_queue_collection_iterate (
		struct rrr_udpstream_asd_queue_collection *collection,
		int (*callback)(struct rrr_udpstream_asd_queue *queue, void *private_arg),
		void *private_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_udpstream_asd_queue);
		if (callback(node, private_arg) != 0) {
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_udpstream_asd_queue_collection_count_entries (
		struct rrr_udpstream_asd_queue_collection *collection
) {
	int total = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_udpstream_asd_queue);
		total += RRR_LL_COUNT(node);
	RRR_LL_ITERATE_END();

	return total;
}

static void __rrr_udpstream_asd_queue_insert_ordered (
		struct rrr_udpstream_asd_queue *queue,
		struct rrr_udpstream_asd_queue_entry *entry
) {
	if (RRR_LL_LAST(queue) == NULL || RRR_LL_LAST(queue)->message_id < entry->message_id) {
		RRR_LL_APPEND(queue, entry);
		return;
	}

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (entry->message_id < node->message_id) {
			RRR_LL_ITERATE_INSERT(queue, entry);
			entry = NULL;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	if (entry != NULL) {
		RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
			RRR_MSG_0("dump queue boundaries: %" PRIu32 "\n", node->message_id);
		RRR_LL_ITERATE_END();
		RRR_BUG("Entry with boundary %" PRIu32 " was not inserted in __rrr_udpstream_asd_queue_insert_ordered\n", entry->message_id);
	}
}

static int __rrr_udpstream_asd_queue_incref_and_insert_entry (
		struct rrr_udpstream_asd_queue *queue,
		struct rrr_msg_holder *ip_entry,
		uint32_t message_id
) {
	int ret = 0;
	struct rrr_udpstream_asd_queue_entry *new_entry = NULL;

	if (__rrr_udpstream_asd_queue_find_entry(queue, message_id) != NULL) {
		goto out;
	}

	if ((new_entry = rrr_allocate(sizeof(*new_entry))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_udpstream_asd_queue_insert_entry_or_free\n");
		ret = 1;
		goto out;
	}
	memset(new_entry, '\0', sizeof(*new_entry));

	rrr_msg_holder_incref_while_locked(ip_entry);
	new_entry->message_id = message_id;
	new_entry->message = ip_entry;

	__rrr_udpstream_asd_queue_insert_ordered(queue, new_entry);
	new_entry = NULL;

	out:
	if (new_entry != NULL) {
		__rrr_udpstream_asd_queue_entry_destroy(new_entry);
	}

	return ret;
}

static int __rrr_udpstream_asd_queue_new (struct rrr_udpstream_asd_queue **target, uint32_t connect_handle) {
	*target = NULL;

	struct rrr_udpstream_asd_queue *queue = rrr_allocate(sizeof(*queue));

	if (queue == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_udpstream_asd_queue_new\n");
		return 1;
	}

	memset(queue, '\0', sizeof(*queue));

	queue->source_connect_handle = connect_handle;

	*target = queue;

	return 0;
}

static int __rrr_udpstream_asd_queue_collection_incref_and_insert_entry (
		struct rrr_udpstream_asd_queue_collection *collection,
		struct rrr_msg_holder *entry,
		uint32_t connect_handle,
		uint32_t message_id
) {
	int ret = 0;

	struct rrr_udpstream_asd_queue *target = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_udpstream_asd_queue);
		if (connect_handle == node->source_connect_handle) {
			target = node;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	if (target == NULL) {
		if (__rrr_udpstream_asd_queue_new(&target, connect_handle) != 0) {
			RRR_MSG_0("Could not create new queue in __rrr_udpstream_asd_queue_collection_insert_entry\n");
			ret = 1;
			goto out;
		}
		RRR_LL_APPEND(collection, target);
	}

	ret = __rrr_udpstream_asd_queue_incref_and_insert_entry(target, entry, message_id);

	out:
	return ret;
}

static void __rrr_udpstream_asd_queue_clear(struct rrr_udpstream_asd_queue *queue) {
	RRR_LL_DESTROY(queue, struct rrr_udpstream_asd_queue_entry, __rrr_udpstream_asd_queue_entry_destroy(node));
}

static void __rrr_udpstream_asd_queue_destroy(struct rrr_udpstream_asd_queue *queue) {
	__rrr_udpstream_asd_queue_clear(queue);
	rrr_free(queue);
}

static void __rrr_udpstream_asd_queue_collection_clear(struct rrr_udpstream_asd_queue_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_udpstream_asd_queue, __rrr_udpstream_asd_queue_destroy(node));
}

static int __rrr_udpstream_asd_send_control_message (
		struct rrr_udpstream_asd *session,
		uint32_t flags,
		uint32_t connect_handle,
		uint32_t message_id
) {
	struct rrr_udpstream_asd_control_msg control_msg = {
			flags,
			message_id
	};

	uint64_t application_data = __rrr_udpstream_asd_control_msg_join(control_msg);

	RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " CTRL flags %" PRIu32 "\n",
			connect_handle, message_id, flags);

	int ret = rrr_udpstream_send_control_frame(&session->udpstream, connect_handle, application_data);

	ret &= ~(RRR_UDPSTREAM_NOT_READY);

	return ret;
}

static int __rrr_udpstream_asd_buffer_after_connect_tasks (
		struct rrr_udpstream_asd *session
) {
	int ret = 0;

	if (session->reset_on_next_connect) {
		RRR_DBG_3("ASD TX %" PRIu32 " RST\n", session->connect_handle);
		if ((ret = __rrr_udpstream_asd_send_control_message(session, RRR_UDPSTREAM_ASD_ACK_FLAGS_RST, session->connect_handle, 0)) != 0) {
			RRR_MSG_0("Could not queue reset frame in __rrr_udpstream_asd_buffer_connect_if_needed\n");
			goto out;
		}
		session->reset_on_next_connect = 0;
	}

	__rrr_udpstream_asd_queue_reset_send_times (&session->send_queue);

	out:
	return ret;
}

static int __rrr_udpstream_asd_buffer_connect_if_needed (
		struct rrr_udpstream_asd *session
) {
	int ret = RRR_UDPSTREAM_ASD_OK;

	int udpstream_ret = rrr_udpstream_connection_check(&session->udpstream, session->connect_handle);
	if (udpstream_ret == 0) {
		session->connection_attempt_time = 0;
		if (session->is_connected == 0) {
			RRR_DBG_3("ASD %" PRIu32 " ready\n", session->connect_handle);

			if ((ret = __rrr_udpstream_asd_buffer_after_connect_tasks (session)) != 0) {
				goto out;
			}

			session->is_connected = 1;
		}
		goto out;
	}
	else if (udpstream_ret == RRR_UDPSTREAM_NOT_READY) {
		session->is_connected = 0;
	}
	else {
		session->is_connected = 0;
	}

	if (session->remote_host != NULL && *(session->remote_host) != '\0') {
		if (session->connection_attempt_time > 0) {
			if (rrr_time_get_64() - session->connection_attempt_time > RRR_UDPSTREAM_ASD_CONNECT_TIMEOUT_MS * 1000) {
				RRR_MSG_0("Connection attempt to remote %s:%s timed out after %i ms in UDP-stream ASD session\n",
						session->remote_host, session->remote_port, RRR_UDPSTREAM_ASD_CONNECT_TIMEOUT_MS);
				session->connection_attempt_time = 0;
			}
			else {
				goto out;
			}
		}

		uint32_t connect_handle = session->connect_handle;

		RRR_DBG_3("ASD %u CONNECT send queue count %i\n",
				session->connect_handle, RRR_LL_COUNT(&session->send_queue));

		if ((ret = rrr_udpstream_connect (
				&connect_handle,
				&session->udpstream,
				session->remote_host,
				session->remote_port
		)) != 0) {
			RRR_MSG_0("Could not send connect to remote %s:%s in __rrr_udpstream_asd_buffer_connect_if_needed\n",
					session->remote_host, session->remote_port);
			ret = 1;
			goto out;
		}

		if (connect_handle != session->connect_handle) {
			RRR_BUG("Connect handle was changed by UDP-stream in __rrr_udpstream_asd_buffer_connect_if_needed\n");
		}

		session->connection_attempt_time = rrr_time_get_64();
	}

	out:
	if (ret == 0 && !session->is_connected) {
		ret = RRR_UDPSTREAM_ASD_NOT_READY;
	}
	return ret;
}

static void __rrr_udpstream_asd_release_queue_clear_by_handle (
		struct rrr_udpstream_asd *session,
		uint32_t connect_handle
) {
	RRR_LL_ITERATE_BEGIN(&session->release_queues, struct rrr_udpstream_asd_queue);
		if (node->source_connect_handle == connect_handle) {
			__rrr_udpstream_asd_queue_clear(node);
		}
	RRR_LL_ITERATE_END();
}

static int __rrr_udpstream_asd_control_frame_callback (
		uint32_t connect_handle,
		uint64_t application_data,
		void *arg
) {
	int ret = 0;

	struct rrr_udpstream_asd *session = arg;

	struct rrr_udpstream_asd_control_msg control_msg = __rrr_udpstream_asd_control_msg_split(application_data);

	struct rrr_udpstream_asd_queue_entry *node = NULL;

	uint32_t reply_ack_flags = 0;

	if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) {
		RRR_DBG_3("ASD RX %" PRIu32 ":%" PRIu32 " DACK\n",
				session->connect_handle, control_msg.message_id);

		node = __rrr_udpstream_asd_queue_find_entry(
				&session->send_queue,
				control_msg.message_id
		);
		if (node != NULL) {
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK;
		}

		RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " RACK\n",
				session->connect_handle, control_msg.message_id);
		reply_ack_flags = RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;
	}
	else if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK) {
		node = __rrr_udpstream_asd_queue_collection_find_entry(
				&session->release_queues,
				connect_handle,
				control_msg.message_id
		);

		if (node != NULL) {
			RRR_DBG_3("ASD RX %" PRIu32 ":%" PRIu32 " RACK\n",
					session->connect_handle, control_msg.message_id);
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;

			if ((ret = __rrr_udpstream_asd_queue_entry_deliver (
					session,
					node
			)) != 0) {
				goto out;
			}
		}
		else {
			RRR_DBG_3("ASD RX %" PRIu32 ":%" PRIu32 " RACK (unknown)\n",
					session->connect_handle, control_msg.message_id);
		}

		RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " CACK\n",
				session->connect_handle, control_msg.message_id);
		reply_ack_flags = RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK;
	}
	else if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK) {
		RRR_DBG_3("ASD RX %" PRIu32 ":%" PRIu32 " CACK\n",
				session->connect_handle, control_msg.message_id);

		node = __rrr_udpstream_asd_queue_find_entry (
				&session->send_queue,
				control_msg.message_id
		);
		if (node != NULL) {
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK;
		}
	}
	else if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_RST) {
		RRR_DBG_3("ASD RX %" PRIu32 " RST\n",
				connect_handle);
		__rrr_udpstream_asd_release_queue_clear_by_handle(session, connect_handle);
	}
	else {
		RRR_DBG_3("ASD RX %" PRIu32 " ACK (unknown flags %" PRIu32 ")\n",
				control_msg.message_id, control_msg.flags);
	}

	// We cannot reply with ACK messages immediately as we already are in locked UDP-stream
	// context. Instead, the control messages to be sent are queued and sent in the next send iteration.
	// Corresponding ACKs to received ACKs are always sent, also when the IDs are not found in the
	// buffers.
	if (reply_ack_flags != 0) {
		ret = __rrr_udpstream_asd_send_control_message(
				session,
				reply_ack_flags,
				connect_handle,
				control_msg.message_id
		);
	}

	out:
	return ret;
}

static void  __rrr_udpstream_asd_periodic_event_add (
		struct rrr_udpstream_asd *session
) {
	if (!EVENT_PENDING(session->event_periodic)) {
		EVENT_ADD(session->event_periodic);
	}
	EVENT_ACTIVATE(session->event_periodic);
}

int rrr_udpstream_asd_queue_and_incref_message (
		struct rrr_udpstream_asd *session,
		struct rrr_msg_holder *ip_message
) {
	int ret = RRR_UDPSTREAM_ASD_OK;
	uint32_t id = 0;

	if (session->remote_host == NULL || *(session->remote_host) == '\0') {
		RRR_BUG("Attempted to queue message with rrr_udpstream_asd_queue_message while remote host was not set\n");
	}

	if (RRR_LL_COUNT(&session->send_queue) >= RRR_UDPSTREAM_ASD_BUFFER_MAX) {
		ret = RRR_UDPSTREAM_ASD_NOT_READY;
		goto out;
	}

	id = ++(session->message_id_pos);
	if (id == 0) {
		id = ++(session->message_id_pos);
	}

	RRR_DBG_3("ASD Q %" PRIu32 ":%" PRIu32 "\n",
		session->connect_handle, session->message_id_pos);

	// Not very likely
	if (__rrr_udpstream_asd_queue_find_entry(&session->send_queue, id) != NULL) {
		RRR_BUG("IDs exhausted in rrr_udpstream_asd_queue_message\n");
	}

	if ((ret = __rrr_udpstream_asd_queue_incref_and_insert_entry (
			&session->send_queue,
			ip_message,
			id
	)) != 0) {
		RRR_MSG_0("Could not insert ASD node into send queue in rrr_udpstream_asd_queue_message\n");
		ret = 1;
		goto out;
	}

	__rrr_udpstream_asd_periodic_event_add(session);

	out:
	return ret;
}

static int __rrr_udpstream_asd_send_message (
		struct rrr_udpstream_asd *session,
		struct rrr_udpstream_asd_queue_entry *node
) {
	int ret = 0;

	struct rrr_msg_msg *message = node->message->message;
	struct rrr_msg_msg *message_network = NULL;
	message_network = rrr_msg_msg_duplicate(message);
	const rrr_length message_network_size = MSG_TOTAL_SIZE(message_network);

	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) message_network);
	rrr_msg_checksum_and_to_network_endian ((struct rrr_msg *) message_network);

	// Note: There is no locking on the connect handle. If it for some reason is invalid,
	// udpstream will detect this.
	if ((ret = rrr_udpstream_queue_outbound_data (
			&session->udpstream,
			session->connect_handle,
			message_network,
			message_network_size,
			node->message_id
	)) != 0) {
		if (ret == RRR_UDPSTREAM_NOT_READY) {
			ret = RRR_UDPSTREAM_ASD_NOT_READY;
			goto out;
		}
		else if (ret == RRR_UDPSTREAM_NOT_READY || ret == RRR_UDPSTREAM_SOFT_ERR) {
			ret = RRR_UDPSTREAM_ASD_NOT_READY;
			goto out;
		}
		else {
			RRR_MSG_0("Error while queuing message for sending in UDP-stream ASD handle %u\n",
					session->connect_handle);
			ret = RRR_UDPSTREAM_ASD_HARD_ERR;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message_network);
	return ret;
}

static int __rrr_udpstream_asd_do_release_queue_send_tasks (
		struct rrr_udpstream_asd_queue *queue,
		void *private_arg
) {
	struct rrr_udpstream_asd *session = private_arg;

	uint64_t time_now = rrr_time_get_64();
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (node->send_time == 0 || time_now - node->send_time > RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS * 1000) {
			// Always update send time to prevent hardcore looping upon error conditions
			node->send_time = time_now;

			if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) == 0 || (node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK) == 0) {
				// We have not sent delivery ACK or need to re-send it
				RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " DACK DUP\n",
						session->connect_handle, node->message_id);
				ret = __rrr_udpstream_asd_send_control_message (
						session,
						RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK,
						queue->source_connect_handle,
						node->message_id
				);

				node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK;
				node->send_count++;
			}

			ret &= ~(RRR_UDPSTREAM_NOT_READY);

			if (ret != 0) {
				RRR_DBG_3("Error while sending message in __rrr_udpstream_asd_do_release_queue_send_tasks return was %i\n", ret);
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	out:
	return ret;
}

static int __rrr_udpstream_asd_do_send_tasks (
		int *no_more_send,
		struct rrr_udpstream_asd *session
) {
	int ret = 0;

	uint64_t time_now = rrr_time_get_64();

	int buffer_was_full = 0;

	// Send data messages and reminder ACKs for outbound messages
	RRR_LL_ITERATE_BEGIN(&session->send_queue, struct rrr_udpstream_asd_queue_entry);
		if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK) != 0) {
			session->delivered_count++;
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->send_time == 0 || time_now - node->send_time > RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS * 1000) {
			if (node->send_time == 0) {
				session->sent_count++;
			}

			// Always update send time to prevent hardcore looping upon error conditions
			node->send_time = time_now;
			node->send_count++;

			const char *dup = node->send_count > 1 ? " DUP" : "";

			if (node->ack_status_flags == 0 || node->ack_status_flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_MSG) {
				// We are missing delivery ACK, re-send message
				if (buffer_was_full == 0) {
					RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " MSG%s\n",
						session->connect_handle, node->message_id, dup);
					ret = __rrr_udpstream_asd_send_message(session, node);
					if (ret == RRR_UDPSTREAM_ASD_NOT_READY) {
						RRR_DBG_3("ASD TX failed (NOT READY)\n");
						buffer_was_full = 1;
						ret = 0;
					}
					else {
						node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_MSG;
					}
				}
			}
			else if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) != 0) {
				RRR_DBG_3("ASD TX %" PRIu32 ":%" PRIu32 " RACK%s\n",
						session->connect_handle, node->message_id, dup);

				// We are missing complete ACK, re-send release ACK
				ret = __rrr_udpstream_asd_send_control_message(
						session,
						RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK,
						session->connect_handle,
						node->message_id
				);
				node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;
			}
			else {
				RRR_BUG("Unknown ACK flags %u for node in rrr_udpstream_asd_do_send_tasks\n", node->ack_status_flags);
			}

			if (ret != 0) {
				RRR_DBG_3("Error while sending message A in rrr_udpstream_asd_do_send_tasks return was %i\n", ret);
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->send_queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	out:
	*no_more_send = RRR_LL_COUNT(&session->send_queue) == 0;
	return ret;
}

/* Disabled, not currently used. ipclient has it's own allocator.
int rrr_udpstream_asd_default_allocator (
		uint32_t size,
		int (*callback)(void **joined_data, void *allocation_handle, void *udpstream_callback_arg),
		void *udpstream_callback_arg,
		void *arg
) {
	(void)(arg);

	int ret = 0;

	struct rrr_msg_msg_holder *new_entry = NULL;

	if (rrr_msg_msg_holder_new (
			&new_entry,
			0,
			NULL,
			0,
			RRR_IP_UDP,
			NULL
	) != 0) {
		RRR_MSG_0("Could not create ip buffer message in rrr_udpstream_asd_default_allocator\n");
		ret = 1;
		goto out;
	}

	void *joined_data = NULL;

	if ((joined_data = malloc(size)) == NULL) {
		RRR_MSG_0("Could not allocate memory for joined data in __rrr_udpstream_process_receive_buffer\n");
		ret = 1;
		goto out_destroy;
	}

	rrr_msg_msg_holder_lock(new_entry);

	new_entry->message = joined_data;
	new_entry->data_length = size;

	ret = callback(&joined_data, new_entry, udpstream_callback_arg);

	if (joined_data != NULL) {
		rrr_msg_msg_holder_destroy_while_locked(new_entry);
	}
	else {
		rrr_msg_msg_holder_unlock(new_entry);
	}

	goto out;
	out_destroy:
		rrr_msg_msg_holder_destroy(new_entry);
	out:
		return ret;
}
*/

struct rrr_asd_receive_messages_final_callback_data {
	struct rrr_udpstream_asd *session;
	const struct rrr_udpstream_receive_data *udpstream_receive_data;
	int count;
};

static int __rrr_udpstream_asd_receive_messages_callback_final (struct rrr_msg_msg **message, void *arg1, void *arg2) {
	(void)(arg2);

	int ret = 0;

	struct rrr_asd_receive_messages_final_callback_data *receive_data = arg1;
	struct rrr_udpstream_asd *session = receive_data->session;
	struct rrr_msg_holder *entry = receive_data->udpstream_receive_data->allocation_handle;

	// Any allocator must put an ip buffer entry in the allocation handle
	// The entry must be locked already at this location, allocator is responsible for ensuring that
	// The allocator must unlock the entry after the callback chain is complete

	if (receive_data->udpstream_receive_data->application_data > 0xffffffff) {
		RRR_MSG_0("Application data/message ID out of range (%" PRIu64 ") in __rrr_udpstream_asd_receive_messages_callback_final connect handle %" PRIu32 ", message dropped\n",
				receive_data->udpstream_receive_data->application_data,
				session->connect_handle
		);
		ret = 1;
		goto out;
	}

	RRR_DBG_3("ASD RX %" PRIu32 ":%" PRIu64 " MSG timestamp %" PRIu64 "\n",
			session->connect_handle, receive_data->udpstream_receive_data->application_data, (*message)->timestamp);

	if ((ret = __rrr_udpstream_asd_queue_collection_incref_and_insert_entry (
			&session->release_queues,
			entry,
			receive_data->udpstream_receive_data->connect_handle,
			(uint32_t) receive_data->udpstream_receive_data->application_data
	)) != 0) {
		RRR_MSG_0("Could not insert ASD message into release queue\n");
		ret = 1;
		goto out;
	}
	else {
		// Tells the allocator that we are now using the memory
		*message = NULL;
	}

	receive_data->count++;

	out:
	return ret;
}

static int __rrr_udpstream_asd_receive_messages_possible_callback (
		RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_POSSIBLE_ARGS
) {
	struct rrr_udpstream_asd *session = arg;

	const int release_queue_count = __rrr_udpstream_asd_queue_collection_count_entries(&session->release_queues);
	return release_queue_count < RRR_UDPSTREAM_ASD_RELEASE_QUEUE_MAX;
}

static int __rrr_udpstream_asd_receive_messages_callback (
		RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_udpstream_asd *session = arg;

	int ret = 0;


#if SSIZE_MAX > RRR_LENGTH_MAX
	if ((rrr_slength) receive_data->data_size > (rrr_slength) RRR_LENGTH_MAX) {
		RRR_MSG_0("Received message too big in __rrr_udpstream_asd_receive_messages_callback\n");
		ret = RRR_UDPSTREAM_ASD_HARD_ERR;
		goto out;
	}
#endif

	struct rrr_asd_receive_messages_final_callback_data callback_data = {
			session,
			receive_data,
			0
	};

	if ((ret = rrr_msg_to_host_and_verify_with_callback (
			(struct rrr_msg **) joined_data,
			(rrr_length) receive_data->data_size,
			__rrr_udpstream_asd_receive_messages_callback_final,
			NULL,
			NULL,
			NULL,
			NULL,
			&callback_data,
			NULL
	)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_MSG_0("Invalid message received in __rrr_udpstream_asd_receive_messages_callback, application data was %" PRIu64 "\n",
					receive_data->application_data);
			ret = 0;
		}
		else {
			RRR_MSG_0("Error while processing message in __rrr_udpstream_asd_receive_messages_callback return was %i\n",
					ret);
			ret = 1;
			goto out;
		}
	}

	__rrr_udpstream_asd_periodic_event_add(session);

	out:
	return ret;
}

static int __rrr_udpstream_asd_queue_update_delivery_grace (
		int *grace_count,
		struct rrr_udpstream_asd_queue *queue,
		int delivered_count
) {
	*grace_count = 0;

	// Once grace counter reaches zero, the queue entry is finally removed. A fixed number
	// of new messages need to be delivered after an delivered entry is removed, this is
	// to prevent ID collisions. The grace "distance" must be much greater than window size.
	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (node->delivered_grace_counter > 0) {
			(*grace_count)++;
			node->delivered_grace_counter -= delivered_count;
			// Important to check for less than or equal to zero, or the
			// entry might be delivered to application again
			if (node->delivered_grace_counter <= 0) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	return 0;
}

int __rrr_udpstream_asd_queue_regulate_window_size (
		struct rrr_udpstream_asd *session,
		struct rrr_udpstream_asd_queue *queue,
		int grace_count
) {
	int ret = 0;

	if (RRR_LL_COUNT(queue) - grace_count > RRR_UDPSTREAM_ASD_RELEASE_QUEUE_WINDOW_SIZE_REDUCTION_THRESHOLD) {
		if ((ret = rrr_udpstream_regulate_window_size (
				&session->udpstream,
				queue->source_connect_handle,
				RRR_UDPSTREAM_ASD_WINDOW_SIZE_REDUCTION_AMOUNT
		)) != 0) {
			// Don't produce fatal error here, let something else fail
			RRR_DBG_3("Error while regulating window size in ASD while delivering messages, return from UDP-stream was %i\n", ret);
			ret = 0;
		}
	}

	return ret;
}

static int __rrr_udpstream_asd_deliver_and_maintain_queue (
		int *all_are_grace,
		struct rrr_udpstream_asd *session,
		struct rrr_udpstream_asd_queue *queue
) {
	int ret = 0;

	int graced_messages_count = 0;

	*all_are_grace = 0;

	// Update grace counters
	if ((ret = __rrr_udpstream_asd_queue_update_delivery_grace (
			&graced_messages_count,
			queue,
			session->delivery_grace_started_count
	)) != 0) {
		RRR_MSG_0("Error while updating grace in __rrr_udpstream_asd_deliver_and_maintain_queue \n");
		goto out;
	}
	session->delivery_grace_started_count = 0;

	// Reduce message traffic if we have many ACK handshakes to complete
	if ((ret = __rrr_udpstream_asd_queue_regulate_window_size (
			session,
			queue,
			graced_messages_count
	)) != 0) {
		RRR_MSG_0("Error while adjusting window sizes in __rrr_udpstream_asd_deliver_and_maintain_queue \n");
		goto out;
	}

	*all_are_grace = graced_messages_count == RRR_LL_COUNT(queue);

	out:
	return ret;
}

// Deliver ready messages to application through callback function
static int __rrr_udpstream_asd_deliver_and_maintain_queues (
		int *queues_empty,
		struct rrr_udpstream_asd *session
) {
	int ret = 0;

	*queues_empty = 1;

	// Note : We could have deleted empty queues here, but they never get empty
	//        due to the grace time of delivered messages

	RRR_LL_ITERATE_BEGIN(&session->release_queues, struct rrr_udpstream_asd_queue);
		int all_are_grace = 0;
		if ((ret = __rrr_udpstream_asd_deliver_and_maintain_queue (
				&all_are_grace,
				session,
				node
		)) != 0) {
			RRR_MSG_0("ASD error while maintaining release queue for connect handle %u\n", node->source_connect_handle);
			goto out;
		}

		if (!all_are_grace) {
			*queues_empty = 0;
		}
	RRR_LL_ITERATE_END();

	// Send data messages and reminder ACKs for inbound messages
	if ((ret = __rrr_udpstream_asd_queue_collection_iterate (
			&session->release_queues,
			__rrr_udpstream_asd_do_release_queue_send_tasks,
			session
	)) != 0) {
		RRR_MSG_0("Error while iterating release queues in __rrr_udpstream_asd_deliver_and_maintain_queues\n");
		goto out;
	}

	out:
	return ret;
}

void rrr_udpstream_asd_destroy (
		struct rrr_udpstream_asd *session
) {
	rrr_event_collection_clear(&session->events);
	__rrr_udpstream_asd_queue_collection_clear(&session->release_queues);
	__rrr_udpstream_asd_queue_clear(&session->send_queue);
	rrr_udpstream_close(&session->udpstream);
	rrr_udpstream_clear(&session->udpstream);
	RRR_FREE_IF_NOT_NULL(session->remote_host);
	RRR_FREE_IF_NOT_NULL(session->remote_port);
	rrr_free(session);
}

static int __rrr_udpstream_asd_tick (
		struct rrr_udpstream_asd *session,
		int *no_more_send,
		int *no_more_delivery
) {
	int ret = 0;

	*no_more_send = 1;
	*no_more_delivery = 1;

	if ((ret = __rrr_udpstream_asd_buffer_connect_if_needed(session)) != 0 &&
	     ret != RRR_UDPSTREAM_ASD_NOT_READY
	) {
		RRR_MSG_0("Error from connect_if_needed in ASD connect handle %" PRIu32 "\n", session->connect_handle);
		goto out;
	}

	if ((ret = __rrr_udpstream_asd_deliver_and_maintain_queues (no_more_delivery, session)) != 0) {
		goto out;
	}

	if ((ret = __rrr_udpstream_asd_do_send_tasks (no_more_send, session)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void __rrr_udpstream_asd_event_periodic (
		int fd,
		short flags,
		void *arg
) {
	struct rrr_udpstream_asd *session = arg;

	(void)(fd);
	(void)(flags);

	int no_more_send, no_more_delivery;

	if (__rrr_udpstream_asd_tick (session, &no_more_send, &no_more_delivery) != 0) {
		rrr_event_dispatch_break(session->queue);
	}

	if (no_more_send && no_more_delivery) {
		EVENT_REMOVE(session->event_periodic);
	}
}

int rrr_udpstream_asd_new (
		struct rrr_udpstream_asd **target,
		struct rrr_event_queue *queue,
		unsigned int local_port,
		const char *remote_host,
		const char *remote_port,
		uint32_t client_id,
		int accept_connections,
		int disallow_ip_swap,
		int v4_only,
		int reset_on_next_connect,
		int (*allocator_callback)(RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS),
		void *allocator_callback_arg,
		int (*receive_callback)(struct rrr_msg_holder *message, void *arg),
		void *receive_callback_arg
) {
	int ret = 0;

	*target = NULL;

	struct rrr_udpstream_asd *session = rrr_allocate(sizeof(*session));
	if (session == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out;
	}
	memset(session, '\0', sizeof(*session));

	rrr_event_collection_init(&session->events, queue);

	if (remote_host != NULL && *remote_host != '\0') {
		if ((session->remote_host = rrr_strdup(remote_host)) == NULL) {
			RRR_MSG_0("Could not allocate remote host string in rrr_udpstream_asd_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (remote_port != NULL && *remote_port != '\0') {
		if ((session->remote_port = rrr_strdup(remote_port)) == NULL) {
			RRR_MSG_0("Could not allocate remote port string in rrr_udpstream_asd_new\n");
			ret = 1;
			goto out_free_remote_host;
		}
	}

	int udpstream_flags = 0;
	if (accept_connections != 0) {
		udpstream_flags |= RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS;
	}
	if (disallow_ip_swap != 0) {
		udpstream_flags |= RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP;
	}

	if ((ret = rrr_udpstream_init (
			&session->udpstream,
			queue,
			udpstream_flags|RRR_UDPSTREAM_FLAGS_FIXED_CONNECT_HANDLE,
			__rrr_udpstream_asd_control_frame_callback,
			session,
			allocator_callback,
			allocator_callback_arg,
			NULL,
			NULL,
			__rrr_udpstream_asd_receive_messages_possible_callback,
			session,
			__rrr_udpstream_asd_receive_messages_callback,
			session
	)) != 0) {
		RRR_MSG_0("Could not initialize udpstream in rrr_udpstream_asd_new\n");
		goto out_free_remote_port;
	}

	if (v4_only) {
		if ((ret = rrr_udpstream_bind_v4_only(&session->udpstream, local_port)) != 0) {
			RRR_MSG_0("Could not bind to local port %u with IPv4 only in rrr_udpstream_asd_new\n", local_port);
			goto out_clear_udpstream;
		}
	}
	else {
		if ((ret = rrr_udpstream_bind_v6_priority(&session->udpstream, local_port)) != 0) {
			RRR_MSG_0("Could not bind to local port %u with IPv6 priority in rrr_udpstream_asd_new\n", local_port);
			goto out_clear_udpstream;
		}
	}

	if ((ret = rrr_event_collection_push_periodic (
			&session->event_periodic,
			&session->events,
			__rrr_udpstream_asd_event_periodic,
			session,
			10 * 1000 // 10 ms
	)) != 0) {
		RRR_MSG_0("Failed to create periodic event in rrr_udpstream_asd_new\n");
		goto out_close_udpstream;
	}


	session->queue = queue;
	session->connect_handle = client_id;
	session->receive_callback = receive_callback;
	session->receive_callback_arg = receive_callback_arg;
	session->reset_on_next_connect = reset_on_next_connect;

	*target = session;
	session = NULL;
	goto out;

	out_close_udpstream:
		rrr_udpstream_close(&session->udpstream);
	out_clear_udpstream:
		rrr_udpstream_clear(&session->udpstream);
	out_free_remote_port:
		rrr_free(session->remote_port);
	out_free_remote_host:
		rrr_free(session->remote_host);
	out_free:
		rrr_free(session);
	out:
		return ret;
}

void rrr_udpstream_asd_get_and_reset_counters (
		unsigned int *sent_count,
		unsigned int *delivered_count,
		struct rrr_udpstream_asd *session
) {
	*sent_count = session->sent_count;
	*delivered_count = session->delivered_count;

	session->sent_count = 0;
	session->delivered_count = 0;
}
