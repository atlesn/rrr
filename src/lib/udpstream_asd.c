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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "ip.h"
#include "udpstream_asd.h"
#include "buffer.h"
#include "vl_time.h"
#include "rrr_socket_common.h"
#include "messages.h"

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
		ip_buffer_entry_destroy(entry->message);
	}
	free(entry);
	return 0;
}
/*
static void __rrr_udpstream_asd_queue_remove_entry (
		struct rrr_udpstream_asd_queue *queue,
		uint32_t message_id
) {
	int iterations = 0;

	if (RRR_LL_COUNT(queue) == 0) {
		return;
	}

	if (message_id < RRR_LL_FIRST(queue)->message_id ||
		message_id > RRR_LL_LAST(queue)->message_id
	) {
		return;
	}

	int64_t diff_to_last = RRR_LL_LAST(queue)->message_id - message_id;
	int64_t diff_to_first = message_id - RRR_LL_FIRST(queue)->message_id;

	RRR_LL_ITERATE_BEGIN_EITHER(queue, struct rrr_udpstream_asd_queue_entry, (diff_to_last < diff_to_first));
		iterations++;
//		printf ("cmp %" PRIu64 " vs %" PRIu64 "\n", boundary_id_combined, node->boundary_id_combined);
		if (node->message_id == message_id) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __rrr_udpstream_asd_queue_entry_destroy(node));

//	printf ("iterations to remove: %i\n", iterations);
}

static struct ip_buffer_entry *__rrr_udpstream_asd_queue_remove_entry_and_get_data (
		struct rrr_udpstream_asd_queue *queue,
		uint32_t message_id
) {
	struct ip_buffer_entry *ret = NULL;

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
//		VL_DEBUG_MSG("cmp boundary %" PRIu64 " vs %" PRIu64 "\n", boundary_id_combined, node->boundary_id_combined);
		if (node->message_id == message_id) {
			ret = node->message;
			node->message = NULL;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	return ret;
}
*/
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
	RRR_LL_ITERATE_END(queue);

	return NULL;
}

static void __rrr_udpstream_asd_queue_insert_ordered (
		struct rrr_udpstream_asd_queue *queue,
		struct rrr_udpstream_asd_queue_entry *entry
) {
	if (RRR_LL_LAST(queue) == NULL || RRR_LL_LAST(queue)->message_id < entry->message_id) {
//		VL_DEBUG_MSG("queue append entry with ip buf entry %p boundary %" PRIu64 "\n",
//				entry->entry, entry->boundary_id);
		RRR_LL_APPEND(queue, entry);
		return;
	}

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
		if (entry->message_id < node->message_id) {
			RRR_LL_ITERATE_INSERT(queue, entry);
//			VL_DEBUG_MSG("queue insert entry with ip buf entry %p boundary %" PRIu64 " before %" PRIu64 "\n",
//					entry->entry, entry->boundary_id, node->boundary_id);
			entry = NULL;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	if (entry != NULL) {
		RRR_LL_ITERATE_BEGIN(queue, struct rrr_udpstream_asd_queue_entry);
			VL_MSG_ERR("dump queue boundaries: %" PRIu32 "\n", node->message_id);
		RRR_LL_ITERATE_END();
		VL_BUG("Entry with boundary %" PRIu32 " was not inserted in __rrr_udpstream_asd_queue_insert_ordered\n", entry->message_id);
	}
}

// message pointer set to NULL if memory gets new owner
static int __rrr_udpstream_asd_queue_insert_entry (
		struct rrr_udpstream_asd_queue *queue,
		struct ip_buffer_entry **message,
		uint32_t message_id
) {
	int ret = 0;
	struct rrr_udpstream_asd_queue_entry *new_entry = NULL;

	if (__rrr_udpstream_asd_queue_find_entry(queue, message_id) != NULL) {
		goto out;
	}

	if ((new_entry = malloc(sizeof(*new_entry))) == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_udpstream_asd_queue_insert_entry_or_free\n");
		ret = 1;
		goto out;
	}
	memset(new_entry, '\0', sizeof(*new_entry));

	new_entry->message_id = message_id;
	new_entry->message = *message;
	*message = NULL;

	__rrr_udpstream_asd_queue_insert_ordered(queue, new_entry);
	new_entry = NULL;

	out:
	if (new_entry != NULL) {
		__rrr_udpstream_asd_queue_entry_destroy(new_entry);
	}

	return ret;
}

void rrr_udpstream_asd_destroy (
		struct rrr_udpstream_asd *session
) {
	pthread_mutex_destroy(&session->queue_lock);
	pthread_mutex_destroy(&session->connect_lock);
	pthread_mutex_destroy(&session->message_id_lock);
	RRR_LL_DESTROY(&session->release_queue, struct rrr_udpstream_asd_queue_entry, __rrr_udpstream_asd_queue_entry_destroy(node));
	RRR_LL_DESTROY(&session->send_queue, struct rrr_udpstream_asd_queue_entry, __rrr_udpstream_asd_queue_entry_destroy(node));
	RRR_LL_DESTROY(&session->control_send_queue, struct rrr_udpstream_asd_control_queue_entry, free(node));
	rrr_udpstream_close(&session->udpstream);
	rrr_udpstream_clear(&session->udpstream);
	RRR_FREE_IF_NOT_NULL(session->remote_host);
	RRR_FREE_IF_NOT_NULL(session->remote_port);
	free(session);
}

int rrr_udpstream_asd_new (
		struct rrr_udpstream_asd **target,
		unsigned int local_port,
		const char *remote_host,
		const char *remote_port,
		uint32_t client_id
) {
	int ret = 0;

	*target = NULL;

	struct rrr_udpstream_asd *session = malloc(sizeof(*session));
	if (session == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out;
	}
	memset(session, '\0', sizeof(*session));

	if ((session->remote_host = strdup(remote_host)) == NULL) {
		VL_MSG_ERR("Could not allocate remote host string in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out_free;
	}

	if ((session->remote_port = strdup(remote_port)) == NULL) {
		VL_MSG_ERR("Could not allocate remote port string in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out_free_remote_host;
	}


	// TODO : Configurable non-accepting mode
	if ((ret = rrr_udpstream_init (&session->udpstream, RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS)) != 0) {
		VL_MSG_ERR("Could not initialize udpstream in rrr_udpstream_asd_new\n");
		goto out_free_remote_port;
	}

	if ((ret = rrr_udpstream_bind(&session->udpstream, local_port)) != 0) {
		VL_MSG_ERR("Could not bind to local port %u in rrr_udpstream_asd_new\n", local_port);
		goto out_clear_udpstream;
	}

	if (pthread_mutex_init(&session->message_id_lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize id lock in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out_close_udpstream;
	}

	if (pthread_mutex_init(&session->connect_lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize connect lock in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out_destroy_id_lock;
	}

	if (pthread_mutex_init(&session->queue_lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize queue lock in rrr_udpstream_asd_new\n");
		ret = 1;
		goto out_destroy_connect_lock;
	}

	session->client_id = client_id;

	*target = session;
	session = NULL;
	goto out;

	out_destroy_connect_lock:
		pthread_mutex_destroy(&session->connect_lock);
	out_destroy_id_lock:
		pthread_mutex_destroy(&session->message_id_lock);
	out_close_udpstream:
		rrr_udpstream_close(&session->udpstream);
	out_clear_udpstream:
		rrr_udpstream_clear(&session->udpstream);
	out_free_remote_port:
		free(session->remote_port);
	out_free_remote_host:
		free(session->remote_host);
	out_free:
		free(session);
	out:
		return ret;
}

static int __rrr_udpstream_asd_buffer_connect_if_needed (
		struct rrr_udpstream_asd *session
) {
	int ret = RRR_UDPSTREAM_ASD_OK;

	pthread_mutex_lock(&session->connect_lock);

	if (session->connect_handle != 0) {
		int udpstream_ret = rrr_udpstream_connection_check(&session->udpstream, session->connect_handle);
		if (udpstream_ret == 0) {
			session->connection_attempt_time = 0;
			session->is_connected = 1;
			goto out;
		}
		else if (udpstream_ret == RRR_UDPSTREAM_NOT_READY) {
			session->is_connected = 0;
		}
		else {
			session->connect_handle = 0;
			session->is_connected = 0;
		}
	}

	if (session->connection_attempt_time > 0) {
		if (time_get_64() - session->connection_attempt_time > RRR_UDPSTREAM_ASD_CONNECT_TIMEOUT_MS * 1000) {
			VL_MSG_ERR("Connection attempt to remote %s:%s timed out after %i ms in UDP-stream ASD session\n",
					session->remote_host, session->remote_port, RRR_UDPSTREAM_ASD_CONNECT_TIMEOUT_MS);
			session->connection_attempt_time = 0;
		}
		else {
			goto out;
		}
	}

	if ((ret = rrr_udpstream_connect (
			&session->connect_handle,
			&session->udpstream,
			session->remote_host,
			session->remote_port
	)) != 0) {
		VL_MSG_ERR("Could not send connect to remote %s:%s in __rrr_udpstream_asd_buffer_connect_if_needed\n",
				session->remote_host, session->remote_port);
		ret = 1;
		goto out;
	}

	session->connection_attempt_time = time_get_64();

	out:
	pthread_mutex_unlock(&session->connect_lock);
	return ret;
}

static int __rrr_udpstream_asd_queue_control_frame (struct rrr_udpstream_asd *session, uint32_t message_id, uint32_t ack_flags) {
	int ret = 0;

	struct rrr_udpstream_asd_control_queue_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_udpstream_asd_queue_control_frame\n");
		ret = 1;
		goto out;
	}

	entry->ack_flags = ack_flags;
	entry->message_id = message_id;

	RRR_LL_APPEND(&session->control_send_queue, entry);

	out:
	return ret;
}

static int __rrr_udpstream_asd_control_frame_listener (uint16_t stream_id, uint64_t application_data, void *arg) {
	int ret = 0;

	(void)(stream_id);

	struct rrr_udpstream_asd *session = arg;

	pthread_mutex_lock(&session->queue_lock);

	struct rrr_udpstream_asd_control_msg control_msg = __rrr_udpstream_asd_control_msg_split(application_data);

	struct rrr_udpstream_asd_queue_entry *node = NULL;

	uint32_t reply_ack_flags = 0;

	if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) {
		VL_DEBUG_MSG_3("UDP-stream ASD DELIVERY ACK for message id %" PRIu32 "\n",
				control_msg.message_id);

		node = __rrr_udpstream_asd_queue_find_entry(&session->send_queue, control_msg.message_id);
		if (node != NULL) {
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK;
		}

		reply_ack_flags = RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;
	}
	else if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK) {
		VL_DEBUG_MSG_3("UDP-stream ASD RELEASE ACK for message id %" PRIu32 "\n",
				control_msg.message_id);

		node = __rrr_udpstream_asd_queue_find_entry(&session->release_queue, control_msg.message_id);
		if (node != NULL) {
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;
		}

		reply_ack_flags = RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK;
	}
	else if (control_msg.flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK) {
		VL_DEBUG_MSG_3("UDP-stream ASD COMPLETE ACK for message id %" PRIu32 "\n",
				control_msg.message_id);

		node = __rrr_udpstream_asd_queue_find_entry(&session->send_queue, control_msg.message_id);
		if (node != NULL) {
			node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK;
		}
	}
	else {
		VL_DEBUG_MSG_1("UDP-stream ASD received control frame with unknown ACK flags %u for stream-id %u\n",
				control_msg.flags, control_msg.message_id);
	}

	// We cannot reply with ACK messages immediately as we already are in locked UDP-stream
	// context. Instead, the control messages to be sent are queued and sent in the next send iteration.
	// Corresponding ACKs to received ACKs are always sent, also when the IDs are not found in the
	// buffers.
	if (reply_ack_flags != 0) {
		ret = __rrr_udpstream_asd_queue_control_frame(session, control_msg.message_id, reply_ack_flags);
	}

	out:
	pthread_mutex_unlock(&session->queue_lock);
	return ret;
}

// ip_message set to NULL if memory is managed by new buffer
int rrr_udpstream_asd_queue_message (
		struct rrr_udpstream_asd *session,
		struct ip_buffer_entry **ip_message
) {
	int ret = RRR_UDPSTREAM_ASD_OK;
	uint32_t id = 0;

	pthread_mutex_lock(&session->queue_lock);
	pthread_mutex_lock(&session->message_id_lock);

	if (RRR_LL_COUNT(&session->send_queue) >= RRR_UDPSTREAM_ASD_BUFFER_MAX) {
		ret = RRR_UDPSTREAM_ASD_BUFFER_FULL;
		goto out;
	}

	int64_t retry_max = 0xffffffff;

	// TODO : Try 4 billion times? Really?
	id_retry:
	if (--retry_max < 0) {
		VL_MSG_ERR("IDs were exhausted in rrr_udpstream_asd_queue_message for ASD handle %u\n",
				session->connect_handle);
		ret = RRR_UDPSTREAM_ASD_ERR;
		goto out;
	}
	id = ++(session->message_id_pos);
	if (id == 0) {
		id = ++(session->message_id_pos);
	}

	if (__rrr_udpstream_asd_queue_find_entry(&session->send_queue, id) != NULL) {
		goto id_retry;
	}

	if ((ret = __rrr_udpstream_asd_queue_insert_entry(&session->send_queue, ip_message, id)) != 0) {
		VL_MSG_ERR("Could not insert ASD node into send queue in rrr_udpstream_asd_queue_message\n");
		ret = 1;
		goto out;
	}

	out:
	pthread_mutex_unlock(&session->message_id_lock);
	pthread_mutex_unlock(&session->queue_lock);
	return ret;
}

int __rrr_udpstream_asd_send_message (
		struct rrr_udpstream_asd *session,
		struct rrr_udpstream_asd_queue_entry *node
) {
	int ret = 0;

	struct vl_message *message = node->message->message;
	struct vl_message *message_network = NULL;
	message_network = message_duplicate(message);
	ssize_t message_network_size = MSG_TOTAL_SIZE(message_network);

	message_prepare_for_network((struct vl_message *) message_network);
	rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message_network);

	// Note: There is no locking on the connect handle. If it for some reason is invalid,
	// udpstream will detect this.
	if ((ret = rrr_udpstream_queue_outbound_data (
			&session->udpstream,
			session->connect_handle,
			message_network,
			message_network_size,
			node->message_id
	)) != 0) {
		if (ret == RRR_UDPSTREAM_BUFFER_FULL) {
			ret = RRR_UDPSTREAM_ASD_BUFFER_FULL;
			goto out;
		}
		else if (ret == RRR_UDPSTREAM_NOT_READY || ret == RRR_UDPSTREAM_IDS_EXHAUSTED || ret == RRR_UDPSTREAM_UNKNOWN_CONNECT_ID) {
			ret = RRR_UDPSTREAM_ASD_NOT_READY;
			goto out;
		}
		else {
			VL_MSG_ERR("Error while queuing message for sending in UDP-stream ASD handle %u\n",
					session->connect_handle);
			ret = RRR_UDPSTREAM_ASD_ERR;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message_network);
	return ret;
}

int __rrr_udpstream_asd_send_control_message (
		struct rrr_udpstream_asd *session,
		uint32_t flags,
		uint32_t message_id
) {
	struct rrr_udpstream_asd_control_msg control_msg = {
			flags,
			message_id
	};

	uint64_t application_data = __rrr_udpstream_asd_control_msg_join(control_msg);

	return rrr_udpstream_send_control_frame(&session->udpstream, session->connect_handle, application_data);
}

static int __rrr_udpstream_asd_do_send_tasks (struct rrr_udpstream_asd *session) {
	int ret = 0;

	uint64_t time_now = time_get_64();

	pthread_mutex_lock(&session->queue_lock);

	// Send control messages
	RRR_LL_ITERATE_BEGIN(&session->control_send_queue, struct rrr_udpstream_asd_control_queue_entry);
		ret = __rrr_udpstream_asd_send_control_message(session, node->ack_flags, node->message_id);
		if (ret != 0) {
			VL_DEBUG_MSG_1("Could not send control message in rrr_udpstream_asd_do_send_tasks return was %i\n", ret);
			ret = 1;
			goto out;
		}
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->control_send_queue, 0; free(node));

	// Send data messages and reminder ACKs for outbound messages
	RRR_LL_ITERATE_BEGIN(&session->send_queue, struct rrr_udpstream_asd_queue_entry);
		if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK) != 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->send_time == 0 || time_now - node->send_time > RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS * 1000) {
			// Always update send time to prevent hardcore looping upon error conditions
			node->send_time = time_now;

			if (node->ack_status_flags == 0 || node->ack_status_flags == RRR_UDPSTREAM_ASD_ACK_FLAGS_MSG) {
				// We are missing delivery ACK, re-send message
				ret = __rrr_udpstream_asd_send_message(session, node);
				node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_MSG;
			}
			else if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) != 0) {
				// We are missing complete ACK, re-send release ACK
				ret = __rrr_udpstream_asd_send_control_message(session, RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK, node->message_id);
				node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK;
			}
			else {
				VL_BUG("Unknown ACK flags %u for node in rrr_udpstream_asd_do_send_tasks\n", node->ack_status_flags);
			}

			if (ret != 0) {
				VL_DEBUG_MSG_1("Error while sending message A in rrr_udpstream_asd_do_send_tasks return was %i\n", ret);
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->send_queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	// Send data messages and reminder ACKs for inbound messages
	RRR_LL_ITERATE_BEGIN(&session->release_queue, struct rrr_udpstream_asd_queue_entry);
		if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_CACK) != 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->send_time == 0 || time_now - node->send_time > RRR_UDPSTREAM_ASD_RESEND_INTERVAL_MS * 1000) {
			// Always update send time to prevent hardcore looping upon error conditions
			node->send_time = time_now;

			if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) == 0 || (node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK) == 0) {
				// We have not sent delivery ACK or need to re-send it
				ret = __rrr_udpstream_asd_send_control_message(session, RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK, node->message_id);
				node->ack_status_flags |= RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK;
			}

			if (ret != 0) {
				VL_DEBUG_MSG_1("Error while sending message B in rrr_udpstream_asd_do_send_tasks return was %i\n", ret);
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->release_queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	out:
	pthread_mutex_unlock(&session->queue_lock);
	return ret;
}

struct rrr_asd_receive_messages_callback_data {
	struct rrr_udpstream_asd *session;
	const struct rrr_udpstream_receive_data *udpstream_receive_data;
	int count;
};


static int __rrr_udpstream_asd_receive_messages_callback_final (struct vl_message *message, void *arg) {
	int ret = 0;

	struct rrr_asd_receive_messages_callback_data *receive_data = arg;
	struct rrr_udpstream_asd *session = receive_data->session;
	struct ip_buffer_entry *new_entry = NULL;

	if (ip_buffer_entry_new (
			&new_entry,
			MSG_TOTAL_SIZE(message),
			receive_data->udpstream_receive_data->addr,
			receive_data->udpstream_receive_data->addr_len,
			message
	) != 0) {
		VL_MSG_ERR("Could not create ip buffer message in __rrr_udpstream_asd_receive_messages_callback_final\n");
		ret = 1;
		goto out;
	}

	// TODO : Make this a soft error?
	if (receive_data->udpstream_receive_data->application_data > 0xffffffff) {
		VL_MSG_ERR("Application data/message ID out of range (%" PRIu64 ") in __rrr_udpstream_asd_receive_messages_callback_final connect handle %" PRIu32 ", message dropped\n",
				receive_data->udpstream_receive_data->application_data,
				session->connect_handle
		);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_udpstream_asd_queue_insert_entry (
			&session->release_queue,
			&new_entry,
			receive_data->udpstream_receive_data->application_data
	)) != 0) {
		VL_MSG_ERR("Could not insert ASD message into release queue\n");
		ret = 1;
		goto out;
	}

	receive_data->count++;

	out:
	if (new_entry != NULL) {
		ip_buffer_entry_destroy(new_entry);
	}
	return ret;
}

static int __rrr_udpstream_asd_receive_messages_callback (const struct rrr_udpstream_receive_data *receive_data, void *arg) {
	struct rrr_asd_receive_messages_callback_data *callback_data = arg;

	int ret = 0;

	callback_data->udpstream_receive_data = receive_data;

	struct rrr_socket_common_receive_message_callback_data socket_callback_data = {
			__rrr_udpstream_asd_receive_messages_callback_final, callback_data
	};

	// This function will always free the data, also upon errors
	if ((ret = rrr_socket_common_receive_message_raw_callback (
			receive_data->data,
			receive_data->data_size,
			&socket_callback_data
	)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Invalid message received in __rrr_udpstream_asd_receive_messages_callback, application data was %" PRIu64 "\n",
					receive_data->application_data);
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while processing message in __rrr_udpstream_asd_receive_messages_callback return was %i\n",
					ret);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_udpstream_asd_do_receive_tasks (int *receive_count, struct rrr_udpstream_asd *session) {
	int ret = 0;

	struct rrr_asd_receive_messages_callback_data receive_callback_data = {
			session, NULL, 0
	};

	if (RRR_LL_COUNT(&session->release_queue) < RRR_UDPSTREAM_ASD_RELEASE_QUEUE_MAX) {
		if ((ret = rrr_udpstream_do_process_receive_buffers (
				&session->udpstream,
				rrr_socket_common_get_session_target_length_from_message_and_checksum_raw,
				NULL,
				__rrr_udpstream_asd_receive_messages_callback,
				&receive_callback_data
		)) != 0) {
			VL_MSG_ERR("Error from UDP-stream while processing buffers in receive_packets of UDP-stream ASD handle %u\n",
					session->connect_handle);
			ret = 1;
			goto out;
		}
	}
	else {
		VL_DEBUG_MSG_1("UDP-stream ASD handle %u release queue is full\n", session->connect_handle);
	}

	*receive_count = receive_callback_data.count;

	if (*receive_count > 0) {
		VL_DEBUG_MSG_3("UDP-stream ASD handle %u: received %i messages\n",
				session->connect_handle, *receive_count);
	}

	out:
	return ret;
}

int rrr_udpstream_asd_deliver_messages (
		struct rrr_udpstream_asd *session,
		int (*receive_callback)(struct ip_buffer_entry *message, void *arg),
		void *receive_callback_arg
) {
	int ret = 0;

	int delivered_count = 0;

	RRR_LL_ITERATE_BEGIN(&session->release_queue, struct rrr_udpstream_asd_queue_entry);
		if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_RACK) != 0 && node->delivered_grace_counter == 0) {
			if ((node->ack_status_flags & RRR_UDPSTREAM_ASD_ACK_FLAGS_DACK) == 0) {
				VL_BUG("RACK without DACK in rrr_udpstream_asd_deliver_messages\n");
			}

			struct ip_buffer_entry *message = node->message;
			node->message = NULL;

			// !!! Callback MUST take care of message memory also upon errors
			if ((ret = receive_callback(message, receive_callback_arg)) != 0) {
				VL_MSG_ERR("Error from callback in rrr_udpstream_asd_deliver_messages\n");
				ret = 1;
				goto out;
			}

			delivered_count++;

			VL_DEBUG_MSG_3("UDP-stream ASD message %u delivered, grace time started (%i)\n",
					node->message_id, RRR_UDPSTREAM_ASD_DELIVERY_GRACE_COUNTER);

			node->delivered_grace_counter = RRR_UDPSTREAM_ASD_DELIVERY_GRACE_COUNTER;
		}
	RRR_LL_ITERATE_END();

	RRR_LL_ITERATE_BEGIN(&session->release_queue, struct rrr_udpstream_asd_queue_entry);
		if (node->delivered_grace_counter > 0) {
			node->delivered_grace_counter -= delivered_count;
			if (node->delivered_grace_counter <= 0) {
				RRR_LL_ITERATE_SET_DESTROY();
				VL_DEBUG_MSG_3("UDP-stream ASD grace time ended for message %u\n",
						node->message_id);
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->release_queue, __rrr_udpstream_asd_queue_entry_destroy(node));

	out:
	return ret;
}

int rrr_udpstream_asd_buffer_tick (
		int *receive_count,
		int *send_count,
		struct rrr_udpstream_asd *session
) {
	int ret = 0;

	// TODO : Detect exhausted ID etc. and reconnect

	if ((ret = __rrr_udpstream_asd_buffer_connect_if_needed(session)) != 0) {
		if (ret == RRR_UDPSTREAM_ASD_NOT_READY) {
			// Connection not ready yet, this is normal
			goto out_not_ready;
		}
		VL_MSG_ERR("Error from connect_if_needed in ASD connect handle %" PRIu32 "\n", session->connect_handle);
		goto out;
	}

	if ((ret = rrr_udpstream_do_read_tasks(&session->udpstream, __rrr_udpstream_asd_control_frame_listener, session)) != 0) {
		if (ret != RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Error from UDP-stream while reading data in receive_packets of UDP-stream ASD handle %u\n",
					session->connect_handle);
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	if ((ret = __rrr_udpstream_asd_do_send_tasks (session)) != 0) {
		if (ret == RRR_UDPSTREAM_NOT_READY) {
			goto out_not_ready;
		}
		else {
			VL_MSG_ERR("Error from UDP-stream while queuing messages to send of UDP-stream ASD handle %u\n",
					session->connect_handle);
			ret = 1;
		}
		goto out;
	}

	if (rrr_udpstream_do_send_tasks(send_count, &session->udpstream) != 0) {
		VL_MSG_ERR("UDP-stream send tasks failed in send_packets ASD\n");
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_udpstream_asd_do_receive_tasks(receive_count, session)) != 0) {
		VL_MSG_ERR("Error from UDP-stream while receiving packets of UDP-stream ASD handle %u\n",
				session->connect_handle);
		ret = 1;
		goto out;
	}

	out:
	return ret;

	out_not_ready:
	VL_DEBUG_MSG_1("UDP-stream not ready yet for connect handle %" PRIu32 "\n", session->connect_handle);
	return 0;
}
