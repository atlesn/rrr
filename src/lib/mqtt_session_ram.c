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

#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mqtt_session_ram.h"
#include "mqtt_session.h"
#include "mqtt_packet.h"
#include "mqtt_subscription.h"
#include "mqtt_common.h"
#include "vl_time.h"
#include "linked_list.h"
#include "mqtt_id_pool.h"

struct rrr_mqtt_session_collection_ram_data;

/*struct rrr_mqtt_session_ram_stats {
	uint64_t total_p_received_per_type[16];
	uint64_t total_p_sent_per_type[16];
};*/

struct rrr_mqtt_session_ram {
	// MUST be first
	struct rrr_mqtt_session session;

	RRR_LL_NODE(struct rrr_mqtt_session_ram);

	struct rrr_mqtt_session_collection_ram_data *ram_data;

	// When updated, global collection lock must be held
	int users;

	// The queues and id pool have their own locking and the session lock is redundant
	struct rrr_mqtt_p_queue to_remote_queue;
	struct rrr_mqtt_p_queue from_remote_queue;
	struct rrr_mqtt_id_pool id_pool;

	// Deliver PUBLISH locally (and check against subscriptions) or forward to other sessions
	int (*delivery_method)(
			struct rrr_mqtt_session_ram *ram_session,
			struct rrr_mqtt_p_publish *publish
	);

	// These fields must be protected by the session lock
	pthread_mutex_t lock;
	char *client_id;
	uint64_t last_seen;
	struct rrr_mqtt_session_properties session_properties;
	uint64_t retry_interval_usec;
	uint32_t max_in_flight;
	uint32_t complete_publish_grace_time;
	int clean_session;
	struct rrr_mqtt_subscription_collection *subscriptions;
//	struct rrr_mqtt_session_ram_stats stats;
};

struct rrr_mqtt_session_collection_ram_data {
	RRR_MQTT_SESSION_COLLECTION_HEAD;
	pthread_mutex_t lock;
	RRR_LL_HEAD(struct rrr_mqtt_session_ram);
	struct rrr_mqtt_p_queue retain_queue;

	// Packets in this queue are forwarded to sessions with matching subscriptions. If no
	// subscriptions match for a packet, it is deleted. Used by broker program.
	struct rrr_mqtt_p_queue publish_forward_queue;

	// Packets in this queue are stored until read from. Used by client program.
	struct rrr_mqtt_p_queue publish_local_queue;

	// Should be updated using provided functions to avoid difficult to find bugs
	struct rrr_mqtt_session_collection_stats stats;
};

#define SESSION_COLLECTION_RAM_LOCK(data) \
		pthread_mutex_lock(&(data)->lock)

#define SESSION_COLLECTION_RAM_UNLOCK(data) \
		pthread_mutex_unlock(&(data)->lock)

#define SESSION_RAM_INCREF_OR_RETURN() \
	do { \
		struct rrr_mqtt_session_collection_ram_data *ram_data = (struct rrr_mqtt_session_collection_ram_data *)(collection); \
		struct rrr_mqtt_session_ram *ram_session = __rrr_mqtt_session_collection_ram_session_find_and_incref(ram_data, (*session_to_find)); \
		if (ram_session == NULL) { \
			*session_to_find = NULL; \
			return RRR_MQTT_SESSION_DELETED; \
		}

#define SESSION_RAM_DECREF() \
		__rrr_mqtt_session_ram_decref ((ram_data), (ram_session)); \
	} while (0)

#define SESSION_RAM_LOCK(session) \
	do { pthread_mutex_lock(&session->lock)

#define SESSION_RAM_UNLOCK(session) \
	pthread_mutex_unlock(&session->lock); } while(0)

struct rrr_mqtt_session_ram_fifo_write_callback_data {
	struct rrr_mqtt_p *data;
	unsigned long size;
	uint64_t order;
	int do_order;
};

// TODO : We don't properly implement memory fence like FIFO buffer is designed for.
//        A hotfix might be to copy the data. Currently, no implementations of this
//        library is threaded.
static int __rrr_mqtt_session_ram_fifo_write_callback (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_mqtt_session_ram_fifo_write_callback_data *callback_data = arg;

	*data = (char *) callback_data->data;
	*size = callback_data->size;
	*order = callback_data->order;

	callback_data->data = NULL;

	if (callback_data->do_order) {
		return RRR_FIFO_WRITE_ORDERED;
	}

	return RRR_FIFO_OK;
}

static int __rrr_mqtt_session_ram_fifo_write (
		struct rrr_fifo_buffer *buffer,
		struct rrr_mqtt_p *packet,
		unsigned long size,
		uint64_t order,
		int do_order
) {
	struct rrr_mqtt_session_ram_fifo_write_callback_data callback_data = {
		packet,
		size,
		order,
		do_order
	};

	return rrr_fifo_buffer_write (buffer, __rrr_mqtt_session_ram_fifo_write_callback, &callback_data);
}

static int __rrr_mqtt_session_ram_fifo_write_delayed (
		struct rrr_fifo_buffer *buffer,
		struct rrr_mqtt_p *data,
		unsigned long size,
		uint64_t order
) {
	struct rrr_mqtt_session_ram_fifo_write_callback_data callback_data = {
		data,
		size,
		order,
		0
	};

	return rrr_fifo_buffer_write_delayed(buffer, __rrr_mqtt_session_ram_fifo_write_callback, &callback_data);
}

// Session collection lock must be held when using stats data
static inline void __rrr_mqtt_session_collection_ram_stats_notify_create (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.active++;
	data->stats.total_created++;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_delete (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.active--;
	data->stats.total_deleted++;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_forwarded (struct rrr_mqtt_session_collection_ram_data *data, int num) {
	data->stats.total_publish_forwarded += num;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_not_forwarded (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.total_publish_not_forwarded++;
}

static int __rrr_mqtt_session_collection_ram_get_stats (
		struct rrr_mqtt_session_collection_stats *target,
		struct rrr_mqtt_session_collection *collection
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *)(collection);

	struct rrr_fifo_buffer_stats fifo_stats = {0};

	SESSION_COLLECTION_RAM_LOCK(data);

	data->stats.in_memory_sessions = RRR_LL_COUNT(data);

	// We can obtain some statistics from the buffers, hence we don't need to count
	// the following parameters continuously:

	// Remember to use the most logic parameter from fifo (written entries or deleted entries)

	if (rrr_fifo_buffer_get_stats(&fifo_stats, &data->publish_forward_queue.buffer) == 0) {
		data->stats.total_publish_received = fifo_stats.total_entries_written;
	}
	else {
		RRR_MSG_0("Warning: Error while getting stats from fifo publish_forward_queue in __rrr_mqtt_session_collection_ram_get_stats \n");
	}

	if (rrr_fifo_buffer_get_stats(&fifo_stats, &data->publish_local_queue.buffer) == 0) {
		data->stats.total_publish_delivered = fifo_stats.total_entries_deleted;
	}
	else {
		RRR_MSG_0("Warning: Error while getting stats from fifo publish_local_queue in __rrr_mqtt_session_collection_ram_get_stats \n");
	}

	*target = data->stats;

	SESSION_COLLECTION_RAM_UNLOCK(data);

	return 0;
}

static int __rrr_mqtt_session_ram_delivery_forward (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	RRR_MQTT_P_INCREF(publish);
	if (__rrr_mqtt_session_ram_fifo_write(&ram_session->ram_data->publish_forward_queue.buffer, (struct rrr_mqtt_p *) publish, sizeof(*publish), 0 ,0) != 0) {
		RRR_MSG_0("Could not write to publish forward queue in__rrr_mqtt_session_ram_delivery_forward\n");
		RRR_MQTT_P_DECREF(publish);
		return RRR_MQTT_SESSION_INTERNAL_ERROR;
	}
	return RRR_MQTT_SESSION_OK;
}

static int __rrr_mqtt_session_ram_delivery_local (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if ((ret = rrr_mqtt_subscription_collection_match_publish (
			ram_session->subscriptions,
			publish
	)) != RRR_MQTT_SUBSCRIPTION_MATCH) {
		if (ret != RRR_MQTT_SUBSCRIPTION_MISMATCH) {
			RRR_MSG_0("Error while checking PUBLISH against subscriptions in __rrr_mqtt_session_ram_delivery_local\n");
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		}
		goto out; // No match
	}

	RRR_MQTT_P_INCREF(publish);
	if (__rrr_mqtt_session_ram_fifo_write_delayed(&ram_session->ram_data->publish_local_queue.buffer, (struct rrr_mqtt_p *) publish, sizeof(*publish), 0) != 0) {
		RRR_MSG_0("Could not write to publish local queue in __rrr_mqtt_session_ram_delivery_local\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		RRR_MQTT_P_DECREF(publish);
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_collection_ram_create_and_add_session_unlocked (
		struct rrr_mqtt_session_ram **target,
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;
	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;

	result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_session_collection_ram_create_session_unlocked A\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	if (rrr_fifo_buffer_init_custom_free(&result->to_remote_queue.buffer, rrr_mqtt_p_standardized_decref) != 0) {
		RRR_MSG_0("Could not initialize send buffer in _rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_free_result;
	}

	if (rrr_fifo_buffer_init_custom_free(&result->from_remote_queue.buffer, rrr_mqtt_p_standardized_decref) != 0) {
		RRR_MSG_0("Could not initialize send buffer in _rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_to_client_queue;
	}

	result->client_id = malloc(strlen(client_id) + 1);
	if (result->client_id == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_session_collection_ram_create_session_unlocked B\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_from_client_queue;
	}
	strcpy (result->client_id, client_id);

	if ((ret = rrr_mqtt_subscription_collection_new(&result->subscriptions)) != 0) {
		RRR_MSG_0("Could not create subscription collection in __rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_free_client_id;
	}

	if (pthread_mutex_init(&result->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_subscriptions;
	}

	if (rrr_mqtt_id_pool_init(&result->id_pool) != 0) {
		RRR_MSG_0("Could not initialize ID pool in __rrr_mqtt_session_collection_ram_create_and_add_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_lock;
	}

	result->users = 1;
	result->ram_data = data;

	RRR_LL_UNSHIFT(data,result);

	*target = result;

	goto out;

/*	out_destroy_id_pool:
		rrr_mqtt_id_pool_destroy(&result->id_pool);*/
	out_destroy_lock:
		pthread_mutex_destroy(&result->lock);
	out_destroy_subscriptions:
		rrr_mqtt_subscription_collection_destroy(result->subscriptions);
	out_free_client_id:
		free(result->client_id);
	out_destroy_from_client_queue:
		rrr_fifo_buffer_clear(&result->from_remote_queue.buffer);
	out_destroy_to_client_queue:
		rrr_fifo_buffer_clear(&result->to_remote_queue.buffer);
//	TODO : Implement
//	fifo_buffer_destroy(&result->qos_queue.buffer);

	out_free_result:
		if (result != NULL) {
			RRR_FREE_IF_NOT_NULL(result->client_id);
			RRR_FREE_IF_NOT_NULL(result);
		}

	out:
		return ret;
}

static int __rrr_mqtt_session_ram_packet_id_release (struct rrr_mqtt_p *packet) {
	RRR_MQTT_P_CLEAR_POOL_ID(packet);
	return 0;
}

static int __rrr_mqtt_session_ram_packet_id_release_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	(void)(size);
	(void)(arg);

	return (__rrr_mqtt_session_ram_packet_id_release(packet) == 0 ? RRR_FIFO_OK : RRR_FIFO_GLOBAL_ERR);
}

static int __rrr_mqtt_session_ram_decref_unlocked (
		struct rrr_mqtt_session_ram *session
) {
	if (--(session->users) >= 1) {
		return 0;
	}
	if (session->users < 0) {
		RRR_BUG("users was < 0 in __rrr_mqtt_session_ram_destroy_unlocked\n");
	}

	// Remove the packet ID free functions as the packets might call back in the
	// session system to release packet ID when they are destroyed, which cause
	// deadlock with main session collection lock. The whole ID pool is to be
	// destroyed here anyway, not need for the packets to release IDs.
	rrr_fifo_buffer_clear_with_callback(&session->to_remote_queue.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);
	rrr_fifo_buffer_clear_with_callback(&session->from_remote_queue.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);
	//  TODO : Look into proper destruction of the buffer mutexes.
	//	fifo_buffer_destroy(&session->qos_queue.buffer);

	RRR_FREE_IF_NOT_NULL(session->client_id);

	rrr_mqtt_subscription_collection_destroy(session->subscriptions);
	rrr_mqtt_session_properties_destroy(&session->session_properties);
	rrr_mqtt_id_pool_destroy(&session->id_pool);

	pthread_mutex_destroy(&session->lock);

	free(session);

	return 0;
}

static void __rrr_mqtt_session_ram_decref (struct rrr_mqtt_session_collection_ram_data *data, struct rrr_mqtt_session_ram *session) {
	SESSION_COLLECTION_RAM_LOCK(data);
	__rrr_mqtt_session_ram_decref_unlocked (session);
	SESSION_COLLECTION_RAM_UNLOCK(data);
}

static void __rrr_mqtt_session_ram_incref_unlocked (struct rrr_mqtt_session_ram *session) {
	session->users++;
}

static void __rrr_mqtt_session_collection_remove (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session_ram *session
) {
	SESSION_COLLECTION_RAM_LOCK(data);

	RRR_LL_REMOVE_NODE_IF_EXISTS (
			data,
			struct rrr_mqtt_session_ram,
			session,
			__rrr_mqtt_session_ram_decref_unlocked(node)
	);

	SESSION_COLLECTION_RAM_UNLOCK(data);

	if (session != NULL) {
		RRR_BUG("Session not found in __rrr_mqtt_session_collection_remove_unlocked\n");
	}
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_find_session_unlocked (
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;

	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		SESSION_RAM_LOCK(node);
		if (strcmp(node->client_id, client_id) == 0) {
			if (result != NULL) {
				RRR_BUG("Found two equal client ids in __rrr_mqtt_session_collection_ram_find_session_unlocked\n");
			}
			result = node;
		}
		SESSION_RAM_UNLOCK(node);
	RRR_LL_ITERATE_END();


	return result;
}

static void __rrr_mqtt_session_ram_heartbeat_unlocked (
		struct rrr_mqtt_session_ram *ram_session
) {
	ram_session->last_seen = rrr_time_get_64();
}

static int __rrr_mqtt_session_collection_ram_get_session (
		struct rrr_mqtt_session **target,
		struct rrr_mqtt_session_collection *sessions,
		const char *client_id,
		int *session_present,
		int no_creation
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;
	*session_present = 0;

	struct rrr_mqtt_session_ram *result = NULL;

	SESSION_COLLECTION_RAM_LOCK(data);
	result = __rrr_mqtt_session_collection_ram_find_session_unlocked (data, client_id);

	if (result != NULL) {
		*session_present = 1;
	}
	else if (no_creation == 0) {
		ret = __rrr_mqtt_session_collection_ram_create_and_add_session_unlocked (
				&result,
				data,
				client_id
		);
		if (ret != RRR_MQTT_SESSION_OK) {
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out_unlock;
		}

		__rrr_mqtt_session_collection_ram_stats_notify_create(data);

	}

	RRR_DBG_1("Got a session, session present was %i and no creation was %i\n",
			*session_present, no_creation);

	__rrr_mqtt_session_ram_heartbeat_unlocked(result);

	*target = (struct rrr_mqtt_session *) result;

	out_unlock:
	SESSION_COLLECTION_RAM_UNLOCK(data);

	return ret;
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_session_find_and_incref (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session *session
) {
	struct rrr_mqtt_session_ram *found = NULL;

	if (session == NULL) {
		return NULL;
	}

	SESSION_COLLECTION_RAM_LOCK(data);

	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		if ((void*) node == (void*) session) {
			__rrr_mqtt_session_ram_incref_unlocked(node);
			found = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	SESSION_COLLECTION_RAM_UNLOCK(data);

	return found;
}

static int __rrr_mqtt_session_ram_release_packet_id (
		void *arg1,
		void *arg2,
		uint16_t packet_id
) {
	struct rrr_mqtt_session_collection *collection = arg1;
	struct rrr_mqtt_session *session = arg2;
	struct rrr_mqtt_session **session_to_find = &session;
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	rrr_mqtt_id_pool_release_id(&ram_session->id_pool, packet_id);

	SESSION_RAM_DECREF();
	return ret;

}

struct receive_forwarded_publish_data {
	struct rrr_mqtt_session_ram *session;
};

static int __rrr_mqtt_session_ram_receive_forwarded_publish_match_callback (
		const struct rrr_mqtt_p_publish *publish,
		const struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct receive_forwarded_publish_data *callback_data = arg;
	struct rrr_mqtt_session_ram *session = callback_data->session;

	if (session->session_properties.receive_maximum != 0 &&
		publish->received_size > session->session_properties.receive_maximum) {
		RRR_DBG_1("Not forwarding matching PUBLISH to client, packet size exceeds receive maximum %li>%u\n",
				publish->received_size, session->session_properties.receive_maximum);
		return RRR_MQTT_SESSION_OK;
	}

	struct rrr_mqtt_p_publish *new_publish = (struct rrr_mqtt_p_publish *) rrr_mqtt_p_clone((struct rrr_mqtt_p *) publish);
	if (new_publish == NULL) {
		RRR_MSG_0("Could not clone PUBLISH packet in __rrr_mqtt_session_ram_receive_forwarded_publish_match_callback\n");
		return RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	int ret = RRR_MQTT_SESSION_OK;

	RRR_MQTT_P_LOCK(new_publish);

	// We don't set the new packet ID yet in case the client is not currently connected
	// and many packets would exhaust the 16-bit ID field. It is set when iterating the
	// send queue and the zero ID is found.

	new_publish->packet_identifier = 0;
	if (new_publish->qos > subscription->qos_or_reason_v5) {
		new_publish->qos = subscription->qos_or_reason_v5;
	}

	new_publish->dup = 0;
	new_publish->is_outbound = 1;

	RRR_MQTT_P_PUBLISH_UPDATE_TYPE_FLAGS(new_publish);

	RRR_MQTT_P_UNLOCK(new_publish);

	if (__rrr_mqtt_session_ram_fifo_write_delayed(&session->to_remote_queue.buffer, (struct rrr_mqtt_p *) new_publish, sizeof(*new_publish), 0) != 0) {
		RRR_MSG_0("Could not write to to_remote_queue in __rrr_mqtt_session_ram_receive_forwarded_publish_match_callback\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}

	new_publish = NULL;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(new_publish);
	return ret;
}

static int __rrr_mqtt_session_ram_receive_forwarded_publish (
		struct rrr_mqtt_session_ram *ram_session,
		const struct rrr_mqtt_p_publish *publish,
		int *match_count
) {
	int ret = RRR_MQTT_SESSION_OK;

	struct receive_forwarded_publish_data callback_data = { ram_session };

	SESSION_RAM_LOCK(ram_session);

	ret = rrr_mqtt_subscription_collection_match_publish_callback (
			ram_session->subscriptions,
			publish,
			__rrr_mqtt_session_ram_receive_forwarded_publish_match_callback,
			&callback_data,
			match_count
	);

	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error while matching publish packet agains subscriptions in __rrr_mqtt_session_ram_receive_forwarded_publish, return was %i\n",
				ret);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	SESSION_RAM_UNLOCK(ram_session);

	return ret;
}

static int __rrr_mqtt_session_collection_ram_forward_publish_to_clients (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_mqtt_session_collection_ram_data *ram_data = arg;
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) data;

	(void)(size);

	int ret = RRR_FIFO_OK;

	if (publish->retain != 0) {
		RRR_BUG("Retain not supported in __rrr_mqtt_session_collection_ram_forward_publish_to_clients\n");
	}

	SESSION_COLLECTION_RAM_LOCK(ram_data);

	int total_match_count = 0;

	RRR_LL_ITERATE_BEGIN(ram_data, struct rrr_mqtt_session_ram);
		RRR_MQTT_P_INCREF(publish);
		RRR_MQTT_P_LOCK(publish);

		int match_count = 0;
		int ret_tmp = __rrr_mqtt_session_ram_receive_forwarded_publish(node, publish, &match_count);
		total_match_count += match_count;

		if (ret_tmp != RRR_MQTT_SESSION_OK) {
			RRR_MSG_0("Error while receiving forwarded publish message, return was %i\n", ret);
			ret |= RRR_FIFO_GLOBAL_ERR;
			RRR_LL_ITERATE_LAST();
		}

		RRR_MQTT_P_UNLOCK(publish);
		RRR_MQTT_P_DECREF(publish);
	RRR_LL_ITERATE_END_CHECK_DESTROY(
			ram_data,
			__rrr_mqtt_session_ram_decref_unlocked(node)
	);
	// TODO : Probably don't need CHECK_DESTROY here, don't seem to destroy anything anyway


	if (total_match_count == 0) {
		__rrr_mqtt_session_collection_ram_stats_notify_not_forwarded(ram_data);
	}
	else {
		__rrr_mqtt_session_collection_ram_stats_notify_forwarded(ram_data, total_match_count);
	}

	SESSION_COLLECTION_RAM_UNLOCK(ram_data);

	// Remember to always return FREE
	return ret | RRR_FIFO_SEARCH_FREE;
}

struct maintain_queue_callback_data {
	int counter;
	uint64_t complete_publish_grace_time_usec;
	uint64_t retry_interval_usec;
};

static int __rrr_mqtt_session_ram_maintain_queue_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	RRR_MQTT_P_LOCK(packet);

	if (packet->last_attempt == 0) {
		goto out;
	}

	struct maintain_queue_callback_data *queue_callback_data = arg;

	int ack_complete = 0;
	int discard_now = 0;

	// Packets for which we expect ACK are retained in the queue to be matched
	// with their ACKs later
	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

		if ((publish->qos == 0) ||
			(publish->qos == 1 && publish->qos_packets.puback != NULL) ||
			(publish->qos == 2 && publish->qos_packets.pubcomp != NULL)
		) {
			ack_complete = 1;
		}
	}
	else if (
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;
		if (sub_usub->sub_usuback != NULL) {
			ack_complete = 1;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGREQ) {
		struct rrr_mqtt_p_pingreq *pingreq = (struct rrr_mqtt_p_pingreq *) packet;
		if (pingreq->pingresp_received != 0) {
			discard_now = 1;
		}
	}
	else {
		if (packet->last_attempt != 0) {
			discard_now = 1;
		}
	}

	if (discard_now == 1) {
		queue_callback_data->counter++;
		ret = RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
		goto out;
	}
	else if (ack_complete == 1) {
		if (packet->planned_expiry_time == 0) {
			packet->planned_expiry_time = rrr_time_get_64() + (queue_callback_data->complete_publish_grace_time_usec);
			RRR_DBG_3("%s id %u is complete, starting grace time of %" PRIu64 " usecs.\n",
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(packet),
					queue_callback_data->complete_publish_grace_time_usec
			);
		}
		if (packet->planned_expiry_time < rrr_time_get_64()) {
			RRR_DBG_3("%s id %u with is complete, deleting from buffer.\n",
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(packet)
			);
			queue_callback_data->counter++;
			ret = RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
			goto out;
		}
	}
	else if (rrr_time_get_64() - packet->last_attempt > queue_callback_data->retry_interval_usec) {
		packet->last_attempt = 0;
		packet->dup = 1;
	}

	out:
	RRR_MQTT_P_UNLOCK(packet);
	return ret;
}

static int __rrr_mqtt_session_ram_maintain_queue (
		struct rrr_mqtt_p_queue *queue,
		uint32_t complete_publish_grace_time,
		uint32_t retry_interval
) {
	struct maintain_queue_callback_data queue_callback_data = {
		0,
		complete_publish_grace_time * 1000 * 1000,
		retry_interval * 1000 * 1000
	};

	if (queue_callback_data.counter > 0) {
		RRR_DBG_1("Deleted %i entries in __rrr_mqtt_session_ram_maintain_queue\n",
				queue_callback_data.counter);
	}

	return rrr_fifo_buffer_search (
			&queue->buffer,
			__rrr_mqtt_session_ram_maintain_queue_callback,
			&queue_callback_data,
			0
	);
}

static int __rrr_mqtt_session_ram_maintain_queues (struct rrr_mqtt_session_ram *session) {
	int ret = RRR_MQTT_SESSION_OK;

	ret |= __rrr_mqtt_session_ram_maintain_queue(
			&session->to_remote_queue,
			session->complete_publish_grace_time,
			session->retry_interval_usec
	);
	ret |= __rrr_mqtt_session_ram_maintain_queue(
			&session->from_remote_queue,
			session->complete_publish_grace_time,
			session->retry_interval_usec
	);

	return ret;
}

struct iterate_local_delivery_callback_data {
	int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg);
	void *callback_arg;
};

static int __rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_MQTT_SESSION_OK;

	(void)(size);

	struct iterate_local_delivery_callback_data *iterate_callback_data = arg;
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) data;

	if (RRR_MQTT_P_GET_TYPE(publish) != RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("Packet was not publish in __rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback\n");
	}

	ret = iterate_callback_data->callback(publish, iterate_callback_data->callback_arg);
	if (ret != 0) {
		RRR_MSG_0("Error from callback in __rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback\n");
		ret = RRR_FIFO_CALLBACK_ERR | RRR_FIFO_SEARCH_STOP;
	}

	return ret | RRR_FIFO_SEARCH_FREE;
}


static int __rrr_mqtt_session_collection_ram_iterate_and_clear_local_delivery (
		struct rrr_mqtt_session_collection *sessions,
		int (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	struct iterate_local_delivery_callback_data iterate_callback_data = {
			callback,
			callback_arg
	};

	RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_SESSION_ERRORS_GENERAL(
			rrr_fifo_buffer_read_clear_forward(
					&data->publish_local_queue.buffer,
					NULL,
					__rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback,
					&iterate_callback_data,
					0
			),
			goto out,
			" while iterating local delivery queue in __rrr_mqtt_session_collection_iterate_and_clear_local_delivery"
	);

	out:
	return ret;
}

static int __rrr_mqtt_session_collection_ram_maintain (
		struct rrr_mqtt_session_collection *sessions
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	uint64_t time_now = rrr_time_get_64();

	// FORWARD NEW PUBLISH MESSAGES TO CLIENTS AND ERASE QUEUE
	ret = rrr_fifo_buffer_read_clear_forward (
			&data->publish_forward_queue.buffer,
			NULL,
			__rrr_mqtt_session_collection_ram_forward_publish_to_clients,
			data,
			0
	);
	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Critical error from publish queue buffer in __rrr_mqtt_session_collection_ram_maintain\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_unlock;
	}
	ret = RRR_MQTT_SESSION_OK;

	// CHECK FOR EXPIRED SESSIONS AND LOOP ACK NOTIFY QUEUES
	SESSION_COLLECTION_RAM_LOCK(data);
	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		uint64_t time_diff = 0;
		uint32_t session_expiry = 0;

		SESSION_RAM_LOCK(node);
		time_diff = time_now - node->last_seen;
		session_expiry = node->session_properties.session_expiry;
		SESSION_RAM_UNLOCK(node);

		if (session_expiry != 0 &&
			session_expiry != 0xffffffff &&
			time_diff > (uint64_t) session_expiry * 1000000
		) {
			SESSION_RAM_LOCK(node);
			RRR_DBG_1("Session expired for client '%s' in __rrr_mqtt_session_collection_ram_maintain\n",
					node->client_id);
			SESSION_RAM_UNLOCK(node);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY (
			data,
			__rrr_mqtt_session_ram_decref_unlocked(node)
	);

	out_unlock:
	SESSION_COLLECTION_RAM_UNLOCK(data);

	return ret;
}

static void __rrr_mqtt_session_collection_ram_destroy (struct rrr_mqtt_session_collection *sessions) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	SESSION_COLLECTION_RAM_LOCK(data);
	rrr_fifo_buffer_clear(&data->retain_queue.buffer);
	rrr_fifo_buffer_clear(&data->publish_forward_queue.buffer);
	rrr_fifo_buffer_clear(&data->publish_local_queue.buffer);

	// TODO : implement destroy
	// fifo_buffer_destroy(&data->retain_queue);
	RRR_LL_DESTROY (
			data,
			struct rrr_mqtt_session_ram,
			__rrr_mqtt_session_ram_decref_unlocked(node)
	);
	SESSION_COLLECTION_RAM_UNLOCK(data);

	pthread_mutex_destroy(&data->lock);

	rrr_mqtt_session_collection_destroy(sessions);

	free(sessions);
}

struct preserve_publish_list {
	RRR_LL_HEAD(struct rrr_mqtt_p);
	int error_in_callback;
};

static int __rrr_mqtt_session_ram_clean_preserve_publish_and_release_id_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) data;
	struct preserve_publish_list *preserve_data = arg;

	// Upon errors, the generated linked list must be cleared by caller

	RRR_MQTT_P_INCREF(packet);
	RRR_MQTT_P_LOCK(packet);

	(void)(size);

	// We need to check for all possible complete states, just like when housekeeping
	// the queue. Complete packets are not preserved.
	if (	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH &&
			packet->planned_expiry_time == 0 &&
			(
					(publish->qos == 1 && publish->qos_packets.puback == NULL) ||
					(publish->qos == 2 && publish->qos_packets.pubcomp == NULL)
			)
	) {
		RRR_DBG_1("Preserving outbound PUBLISH id %u when cleaning session. ID will be reset.\n", packet->packet_identifier);

		// In case anybody else holds reference to the packet, we clone it. The payload
		// is not cloned, but it is INCREF'ed by the clone function.
		struct rrr_mqtt_p *packet_new = rrr_mqtt_p_clone(packet);
		if (packet_new == NULL) {
			RRR_MSG_0("Could not clone PUBLISH in __rrr_mqtt_session_ram_clean_preserve_publish_callback\n");
			preserve_data->error_in_callback = 1;
			goto out;
		}

		if (rrr_mqtt_p_standardized_get_refcount(packet_new) != 1) {
			RRR_BUG("Usercount was not 1 in __rrr_mqtt_session_ram_clean_preserve_publish_callback\n");
		}

		RRR_LL_APPEND(preserve_data, packet_new);
	}

	if (__rrr_mqtt_session_ram_packet_id_release(packet) != 0) {
		RRR_BUG("Error while releasing packet ID in __rrr_mqtt_session_ram_clean_preserve_publish_callback\n");
	}

	out:

	RRR_MQTT_P_UNLOCK(packet);
	RRR_MQTT_P_DECREF(packet);

	// We are not allowed to return anything but zero
	return RRR_FIFO_OK;
}

static int __rrr_mqtt_session_ram_clean_unlocked (struct rrr_mqtt_session_ram *ram_session) {
	int ret = 0;

	struct preserve_publish_list preserve_data = {0};

	// Remove the packet ID free functions as the packets might call back in the
	// session system to release packet ID when they are destroyed, which cause
	// deadlock with ram session lock. We also preserve the outbound PUBLISH packets
	// by re-queing them after the list is emptied (QOS0 are deleted, QOS1-2 are preserved).
	rrr_fifo_buffer_clear_with_callback (
			&ram_session->to_remote_queue.buffer,
			__rrr_mqtt_session_ram_clean_preserve_publish_and_release_id_callback,
			&preserve_data
	);

	if (preserve_data.error_in_callback != 0) {
		RRR_MSG_0("Error from callback while clearing to_remote-buffer and preserving PUBLISH white cleaning ram session\n");
		ret = 1;
		goto out;
	}

	// Add PUBLISH-packets to preserve back to buffer. The list is finally cleared further down.
	RRR_LL_ITERATE_BEGIN(&preserve_data, struct rrr_mqtt_p);
		// INCREF before adding to buffer
		RRR_MQTT_P_INCREF(node);

		RRR_MQTT_P_LOCK(node);
		// ID should already be zero, but hey
		node->packet_identifier = 0;
		// All PUBLISH packets will appear to be new packets
		node->dup = 0;
		RRR_MQTT_P_UNLOCK(node);

		if (__rrr_mqtt_session_ram_fifo_write(&ram_session->to_remote_queue.buffer, node, sizeof(*node), 0, 0) != 0) {
			RRR_MSG_0("Could not write to to_remote_queue in __rrr_mqtt_session_ram_clean_unlocked\n");
			RRR_MQTT_P_DECREF(node);
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	RRR_LL_ITERATE_END();

	rrr_fifo_buffer_clear_with_callback (
			&ram_session->from_remote_queue.buffer,
			__rrr_mqtt_session_ram_packet_id_release_callback,
			NULL
	);

	out:
	RRR_LL_DESTROY(&preserve_data, struct rrr_mqtt_p, rrr_mqtt_p_standardized_decref(node));
	rrr_mqtt_subscription_collection_clear(ram_session->subscriptions);
	rrr_mqtt_id_pool_clear(&ram_session->id_pool);

	return ret;
}

static int __rrr_mqtt_session_ram_init (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		const struct rrr_mqtt_session_properties *session_properties,
		uint64_t retry_interval_usec,
		uint32_t max_in_flight,
		uint32_t complete_publish_grace_time,
		int clean_session,
		int local_delivery,
		int *session_was_present
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	SESSION_RAM_LOCK(ram_session);

	ret = rrr_mqtt_session_properties_clone(&ram_session->session_properties, session_properties);
	if (ret != 0) {
		RRR_MSG_0("Could not clone properties in __rrr_mqtt_session_ram_init\n");
		goto out_unlock;
	}

	ram_session->retry_interval_usec = retry_interval_usec;
	ram_session->max_in_flight = max_in_flight;
	ram_session->last_seen = rrr_time_get_64();
	ram_session->clean_session = clean_session;
	ram_session->complete_publish_grace_time = complete_publish_grace_time;

	if (clean_session == 1) {
		*session_was_present = 0;
		__rrr_mqtt_session_ram_clean_unlocked(ram_session);
	}


	ram_session->delivery_method = (local_delivery != 0
			? __rrr_mqtt_session_ram_delivery_local
			: __rrr_mqtt_session_ram_delivery_forward
	);


	RRR_DBG_1("Init session expiry interval: %" PRIu32 "\n",
			ram_session->session_properties.session_expiry);

	out_unlock:
	SESSION_RAM_UNLOCK(ram_session);
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_clean (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	SESSION_RAM_LOCK(ram_session);

	__rrr_mqtt_session_ram_clean_unlocked(ram_session);

	SESSION_RAM_UNLOCK(ram_session);
	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_reset_properties (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		const struct rrr_mqtt_session_properties *session_properties
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	SESSION_RAM_LOCK(ram_session);

	rrr_mqtt_session_properties_destroy(&ram_session->session_properties);
	ret = rrr_mqtt_session_properties_clone(&ram_session->session_properties, session_properties);
	if (ret != 0) {
		RRR_MSG_0("Could not clone properties in __rrr_mqtt_session_reset_properties\n");
		goto out_unlock;
	}

	out_unlock:
	SESSION_RAM_UNLOCK(ram_session);
	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_heartbeat (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	SESSION_RAM_LOCK(ram_session);

	__rrr_mqtt_session_ram_heartbeat_unlocked(ram_session);

	SESSION_RAM_UNLOCK(ram_session);

	// TODO : Maybe not do this all the time
	if (__rrr_mqtt_session_ram_maintain_queues(ram_session) != 0) {
		RRR_MSG_0("Error in __rrr_mqtt_session_ram_heartbeat while maintaining session\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	SESSION_RAM_DECREF();

	return ret;
}

struct ram_process_ack_callback_data {
	struct rrr_mqtt_p *ack_packet;
	unsigned int found;
	struct rrr_mqtt_session_ram *ram_session;
};

static int __rrr_mqtt_session_ram_process_ack_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct ram_process_ack_callback_data *ack_callback_data = arg;
	struct rrr_mqtt_session_ram *ram_session = ack_callback_data->ram_session;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;
	struct rrr_mqtt_p *ack_packet = ack_callback_data->ack_packet;

	if (packet == ack_packet) {
		RRR_BUG("An ACK packet existed bare in a queue without being part of the original packet in __rrr_mqtt_session_ram_process_ack_callback\n");
	}

	RRR_MQTT_P_LOCK(packet);

	// INCREF first because the packet we are processing possibly already is
	// held by the PUBLISH packet with user count 1, and we DECREF this pointer
	// if a QoS packet field is already filled
	RRR_MQTT_P_INCREF(ack_packet);

	if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PINGRESP && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGREQ) {
		struct rrr_mqtt_p_pingreq *pingreq = (struct rrr_mqtt_p_pingreq *) packet;
		pingreq->pingresp_received = 1;
		goto out_increment_found;
	}

	if (RRR_MQTT_P_GET_IDENTIFIER(packet) != RRR_MQTT_P_GET_IDENTIFIER(ack_packet)) {
		goto out;
	}

	if ((RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBACK ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP
		) && RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_PUBLISH
	) {
		RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
				"but %s was found with matching packet ID %u\n",
				RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_PUBLISH),
				RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
				RRR_MQTT_P_GET_TYPE_NAME(packet),
				RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
		);
	}
	else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_SUBACK &&
			RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_SUBSCRIBE
	) {
		RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
				"but %s was found with matching packet ID %u\n",
				RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_SUBACK),
				RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
				RRR_MQTT_P_GET_TYPE_NAME(packet),
				RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
		);
	}
	else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_UNSUBACK &&
			RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
				"but %s was found with matching packet ID %u\n",
				RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_UNSUBACK),
				RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
				RRR_MQTT_P_GET_TYPE_NAME(packet),
				RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
		);
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

		if ((RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL) && (
				publish->qos != 2
			)
		) {
			RRR_MSG_0("Received %s for PUBLISH packet id %u which was not QoS2 in __rrr_mqtt_session_ram_process_ack_callback\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet), RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}

		ret = RRR_FIFO_SEARCH_STOP;

		if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBACK) {
			if (publish->qos != 1) {
				RRR_MSG_0("Received PUBACK for PUBLISH packet which was not QoS1 id %u in __rrr_mqtt_session_ram_process_ack_callback\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			if (publish->qos_packets.puback != NULL) {
				RRR_DBG_1("Received duplicate PUBACK for PUBLISH id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.puback);
				publish->qos_packets.puback = NULL;
			}
			else if (publish->is_outbound == 0) {
				if (ram_session->delivery_method(ram_session, publish) != RRR_MQTT_SESSION_OK) {
					RRR_MSG_0("Error while delivering PUBLISH in __rrr_mqtt_session_ram_process_ack_callback A\n");
					ret = RRR_FIFO_GLOBAL_ERR;
					goto out;
				}
			}
			publish->qos_packets.puback = (struct rrr_mqtt_p_puback *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP) {
			if (publish->qos_packets.pubcomp != NULL) {
				RRR_DBG_1("Received duplicate PUBCOMP for PUBLISH id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.pubcomp);
				publish->qos_packets.pubcomp = NULL;
			}
			if (publish->qos_packets.pubrel == NULL || publish->qos_packets.pubrec == NULL) {
				RRR_MSG_0("Received premature PUBCOMP for PUBLISH id %u, PUBREC and PUBREL not complete yet\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			publish->qos_packets.pubcomp = (struct rrr_mqtt_p_pubcomp *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC) {
			if (publish->qos_packets.pubrec != NULL) {
				RRR_DBG_1("Received duplicate PUBREC for PUBLISH with id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.pubrec);
				publish->qos_packets.pubrec = NULL;
			}
			publish->qos_packets.pubrec = (struct rrr_mqtt_p_pubrec *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL) {
			if (publish->qos_packets.pubrec == NULL) {
				RRR_MSG_0("Received premature PUBREL for PUBLISH id %u, PUBREC not yet complete\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			if (publish->qos_packets.pubrel != NULL) {
				RRR_DBG_1("Received duplicate PUBREL for PUBLISH with id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.pubrel);
				publish->qos_packets.pubrel = NULL;
				// NOTE !!!! DO NOT RELEASE QOS2 PACKET AGAIN !!!!
			}
			else if (publish->is_outbound == 0) {
				if (ram_session->delivery_method(ram_session, publish) != RRR_MQTT_SESSION_OK) {
					RRR_MSG_0("Error while delivering PUBLISH in __rrr_mqtt_session_ram_process_ack_callback B\n");
					ret = RRR_FIFO_GLOBAL_ERR;
					goto out;
				}
			}
			publish->qos_packets.pubrel = (struct rrr_mqtt_p_pubrel *) ack_packet;
			ack_packet = NULL;
		}
		else {
			RRR_MSG_0("Received unknown ACK packet type %s for PUBLISH with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet), RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}
	}
	else if (
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		if (	(	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE &&
				 	RRR_MQTT_P_GET_TYPE(ack_packet) != RRR_MQTT_P_TYPE_SUBACK
				) ||
				(	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE &&
					RRR_MQTT_P_GET_TYPE(ack_packet) != RRR_MQTT_P_TYPE_UNSUBACK
				)
		) {
			RRR_MSG_0("Received unknown ACK packet type %s for %s with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
			);
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}

		struct rrr_mqtt_p_suback_unsuback *sub_usuback = (struct rrr_mqtt_p_suback_unsuback *) ack_packet;
		struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;
		if (sub_usub->sub_usuback != NULL) {
			RRR_DBG_1("Received duplicate %s for %s with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
			if (sub_usuback->dup == 0) {
				RRR_MSG_0("Duplicate %s did not have DUP flag set\n", RRR_MQTT_P_GET_TYPE_NAME(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			RRR_MQTT_P_DECREF(sub_usub->sub_usuback);
			sub_usub->sub_usuback = NULL;
		}

		sub_usuback->orig_sub_usub = sub_usub;
		sub_usub->sub_usuback = sub_usuback;
		ack_packet = NULL;
	}
	else {
		RRR_BUG("Unknown packet type in __rrr_mqtt_session_ram_process_ack_callback\n");
	}

	out_increment_found:
	ack_callback_data->found++;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(ack_packet);
	RRR_MQTT_P_UNLOCK(packet);
	return ret;
}

static int __rrr_mqtt_session_ram_process_iterate_ack (
		unsigned int *match_count,
		struct rrr_mqtt_p_queue *queue,
		struct rrr_mqtt_p *packet,
		struct rrr_mqtt_session_ram *ram_session
) {
	int ret = RRR_MQTT_SESSION_OK;

	struct ram_process_ack_callback_data callback_data = {
			packet,
			0, // Initialize found counter
			ram_session
	};

	ret = rrr_fifo_buffer_read (
			&queue->buffer,
			__rrr_mqtt_session_ram_process_ack_callback,
			&callback_data,
			0
	);

	// We must always return match count also on errors
	*match_count = callback_data.found;

	if (ret != RRR_FIFO_OK) {
		if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
			RRR_MSG_0("Internal error while searching send buffer in __rrr_mqtt_session_ram_process_iterate_ack\n");
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
		RRR_MSG_0("Soft error while searching send buffer in __rrr_mqtt_session_ram_process_iterate_ack return was %i\n", ret);
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_add_subscriptions (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_subscribe *subscribe
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_LOCK(ram_session);

	ret = rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
			ram_session->subscriptions,
			subscribe->subscriptions,
			0 // <-- Don't include subscriptions with errors (QoS > 2)
	);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not add subscriptions to session in __rrr_mqtt_session_ram_add_subscriptions\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	if (RRR_DEBUGLEVEL_1) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	SESSION_RAM_UNLOCK(ram_session);

	return ret;
}

static int __rrr_mqtt_session_ram_remove_subscriptions (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_unsubscribe *unsubscribe
) {
	int ret = RRR_MQTT_SESSION_OK;

	int removed_count = 0;

	SESSION_RAM_LOCK(ram_session);

	ret = rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
			ram_session->subscriptions,
			unsubscribe->subscriptions,
			&removed_count
	);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not remove subscriptions from session in __rrr_mqtt_session_ram_add_subscriptions\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	if (RRR_DEBUGLEVEL_1) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	// Don't goto and jump over this
	SESSION_RAM_UNLOCK(ram_session);

	if (RRR_LL_COUNT(unsubscribe->subscriptions) != removed_count) {
		RRR_MSG_0("MQTT %i of %i subscriptions were not removed from the session as requested\n",
				RRR_LL_COUNT(unsubscribe->subscriptions) - removed_count,
				RRR_LL_COUNT(unsubscribe->subscriptions)
		);
	}

	return ret;
}

static int __rrr_mqtt_session_ram_receive_suback (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_suback *suback
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (suback->orig_subscribe == NULL) {
		RRR_BUG("orig_subscribe not set for SUBACK in __rrr_mqtt_session_ram_receive_suback\n");
	}

	int orig_count = rrr_mqtt_subscription_collection_count(suback->orig_subscribe->subscriptions);
	int new_count = suback->acknowledgements_size;

	if (orig_count != new_count) {
		RRR_MSG_0("Topic count in received SUBACK did not match the original SUBSCRIBE, broker error\n");
		return 1;
	}

	SESSION_RAM_LOCK(ram_session);

	for (int i = 0; i < new_count; i++) {
		const struct rrr_mqtt_subscription *subscription;
		subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
				suback->orig_subscribe->subscriptions,
				i
		);

		if (suback->acknowledgements[i] <= 2) {
			continue;
		}

		int did_remove = 0;
		if (rrr_mqtt_subscription_collection_remove_topic (
				&did_remove,
				ram_session->subscriptions,
				subscription->topic_filter
		) != 0) {
			RRR_MSG_0("Error while removing subscription from collection in __rrr_mqtt_session_ram_remove_subscriptions_with_errors\n");
			return 1;
		}

		if (did_remove == 1) {
			RRR_DBG_1("Removed topic '%s' from session subscription collection as it was rejected by the broker\n",
					subscription->topic_filter);
		}
		else {
			RRR_MSG_0("Tried to remove non-existent topic '%s' from collection in __rrr_mqtt_session_ram_remove_subscriptions_with_errors\n",
					subscription->topic_filter);
			return 1;
		}

	}

	SESSION_RAM_UNLOCK(ram_session);

	if (ret != 0) {
		RRR_MSG_0("Error while iterating subscriptions in __rrr_mqtt_session_ram_receive_suback\n");
		ret = RRR_MQTT_SESSION_ERROR;
	}

	return ret;
}


static int __rrr_mqtt_session_ram_receive_unsuback (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_unsuback *unsuback
) {
	int ret = RRR_MQTT_SESSION_OK;

	int removed_count = 0;

	if (unsuback->orig_unsubscribe == NULL) {
		RRR_BUG("orig_unsubscribe not set for UNSUBACK in __rrr_mqtt_session_ram_receive_unsuback\n");
	}

	// Needs to be copied due to const
	struct rrr_mqtt_subscription_collection *orig_collection = NULL;
	if (rrr_mqtt_subscription_collection_clone(&orig_collection, unsuback->orig_unsubscribe->subscriptions) != 0) {
		RRR_MSG_0("Could not clone subscription collection in __rrr_mqtt_session_ram_receive_unsuback\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}

	int orig_count = rrr_mqtt_subscription_collection_count(orig_collection);
	int new_count = unsuback->acknowledgements_size;

	if (RRR_MQTT_P_IS_V5(unsuback) && orig_count != new_count) {
		RRR_MSG_0("Topic count in received SUBACK did not match the original SUBSCRIBE, broker error\n");
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	SESSION_RAM_LOCK(ram_session);

	if (RRR_MQTT_P_IS_V5(unsuback)) {
		for (int i = 0; i < unsuback->acknowledgements_size; i++) {
			const struct rrr_mqtt_subscription *subscription;
			subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
					orig_collection,
					i
			);

			if (unsuback->acknowledgements[i] == RRR_MQTT_P_5_REASON_OK) {
				int did_remove = 0;
				if (rrr_mqtt_subscription_collection_remove_topic (
						&did_remove,
						ram_session->subscriptions,
						subscription->topic_filter
				) != 0) {
					RRR_MSG_0("Error while removing subscription from collection in __rrr_mqtt_session_ram_receive_unsuback\n");
					ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
					goto out_unlock;
				}

				if (did_remove != 1) {
					RRR_MSG_0("Tried to remove non-existent topic '%s' from collection in __rrr_mqtt_session_ram_receive_unsuback\n",
							subscription->topic_filter);
					ret = RRR_MQTT_SESSION_ERROR;
					goto out_unlock;
				}

				removed_count++;
			}
			else {
				RRR_DBG_1("MQTT unsubscription of topic '%s' failed as it was rejected by the broker with reason %u\n",
						subscription->topic_filter, unsuback->acknowledgements[i]);
			}
		}
	}
	else {
		// For version 3.1 we just have to assume that all subscriptions were removed at broker
		// as no success messages are returned in the ACK
		ret = rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
				ram_session->subscriptions,
				orig_collection,
				&removed_count
		);

		if (ret != 0) {
			goto out_unlock;
		}
	}

	if (RRR_DEBUGLEVEL_1) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	if (RRR_LL_COUNT(orig_collection) != removed_count) {
		RRR_MSG_0("Warning: Removed subscription count upon UNSUBACK did not match topic count in UNSUBSCRIBE\n");
	}

	out_unlock:
	SESSION_RAM_UNLOCK(ram_session);

	out:
	if (orig_collection != NULL) {
		rrr_mqtt_subscription_collection_destroy(orig_collection);
	}
	return ret;
}

static int __rrr_mqtt_session_ram_process_ack (
		unsigned int *match_count,
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p *packet,
		int packet_was_outbound
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (!RRR_MQTT_P_IS_ACK(packet)) {
		RRR_BUG("Received non-ACK packet in __rrr_mqtt_session_ram_process_ack\n");
	}

	RRR_DBG_3("Process ACK packet %p id %u type %s in send queue, was outbound: %i\n",
			packet,
			RRR_MQTT_P_GET_IDENTIFIER(packet),
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			packet_was_outbound
	);

	if ((ret = __rrr_mqtt_session_ram_process_iterate_ack (
			match_count,
			(packet_was_outbound ? &ram_session->to_remote_queue : &ram_session->from_remote_queue),
			packet,
			ram_session
	)) != 0) {
		RRR_MSG_0("Error while iterating send queue in __rrr_mqtt_session_ram_process_ack\n");
		goto out;
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGRESP) {
		// Everything goes
	}
	else if (*match_count > 1) {
		RRR_BUG("Two packets with the same identifier %u matched while processing in __rrr_mqtt_session_ram_process_ack\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet));
	}
	else if (*match_count == 0) {
		RRR_DBG_1("No packet with identifier %u matched while processing ACK packet of type %s, maybe we have forgotten about a QoS2 handshake which the remote still remembers\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

		if (packet_was_outbound == 0 && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL) {
			// Duplicate PUBREL packet. New PUBCOMP is to be sent, this is OK.
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBCOMP) {
			// Duplicate PUBCOMP packet is OK
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
			// Duplicate SUBACK packet is OK
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
			// Duplicate UNSUBACK packet is OK
		}
		else {
			RRR_MSG_0("Packet identifier %u missing for ACK of type %s for packet which originated from us, this is a session error\n",
					RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));
			ret = RRR_MQTT_SESSION_ERROR;
		}
		goto out;
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
		if (packet_was_outbound == 0) {
			RRR_BUG("packet_was_outbound was zero for SUBACK in __rrr_mqtt_session_ram_process_ack\n");
		}
		if (__rrr_mqtt_session_ram_receive_suback(ram_session, (struct rrr_mqtt_p_suback *) packet) != 0) {
			RRR_MSG_0("Error while handling SUBACK packet in __rrr_mqtt_session_ram_process_ack\n");
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
		if (packet_was_outbound == 0) {
			RRR_BUG("packet_was_outbound was zero for UNSUBACK in __rrr_mqtt_session_ram_process_ack\n");
		}
		if (__rrr_mqtt_session_ram_receive_unsuback(ram_session, (struct rrr_mqtt_p_unsuback *) packet) != 0) {
			RRR_MSG_0("Error while handling UNSUBACK packet in __rrr_mqtt_session_ram_process_ack\n");
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

struct find_qos2_publish_data {
	struct rrr_mqtt_p_publish *publish;
	struct rrr_mqtt_p_publish *publish_in_buffer;
	uint16_t prev_packet_id;
};

static int __rrr_mqtt_session_ram_find_qos2_publish_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct find_qos2_publish_data *qos2_publish_data = arg;
	struct rrr_mqtt_p_publish *publish_in_buffer = (struct rrr_mqtt_p_publish *) data;
	struct rrr_mqtt_p_publish *publish_received = qos2_publish_data->publish;

	RRR_MQTT_P_LOCK(publish_in_buffer);

	if (qos2_publish_data->prev_packet_id == publish_in_buffer->packet_identifier) {
		RRR_BUG("Two equal packet IDs in buffer __rrr_mqtt_session_ram_find_qos2_publish_callback\n");
	}
	if (qos2_publish_data->prev_packet_id > publish_in_buffer->packet_identifier) {
		RRR_BUG("Wrong order of elements in buffer in __rrr_mqtt_session_ram_find_qos2_publish_callback\n");
	}
	if (publish_in_buffer->packet_identifier == 0) {
		RRR_BUG("Packet ID was zero in __rrr_mqtt_session_ram_find_qos2_publish_callback\n");
	}
	if (RRR_MQTT_P_GET_TYPE(publish_in_buffer) != RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("Non-PUBLISH packet %s in qos2 buffer in __rrr_mqtt_session_ram_find_qos2_publish_callback\n",
				RRR_MQTT_P_GET_TYPE_NAME(publish_in_buffer));
	}

	if (publish_in_buffer->packet_identifier == publish_received->packet_identifier) {
		RRR_MQTT_P_INCREF(publish_in_buffer);
		qos2_publish_data->publish_in_buffer = publish_in_buffer;
		ret = RRR_FIFO_SEARCH_STOP;
		goto out;
	}
	else if (publish_in_buffer->packet_identifier > publish_received->packet_identifier) {
		ret = RRR_FIFO_SEARCH_STOP;
		goto out;
	}

	qos2_publish_data->prev_packet_id = publish_in_buffer->packet_identifier;

	out:
		RRR_MQTT_P_UNLOCK(publish_in_buffer);
		return ret;

}

static int __rrr_mqtt_session_ram_receive_publish (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (publish->qos > 2) {
		RRR_BUG("Invalid QoS %u in __rrr_mqtt_session_ram_receive_publish\n", publish->qos);
	}

	// Make sure newly generated ACKs aren't re-sent immediately when the queues are maintained
	publish->last_attempt = rrr_time_get_64();

	if (publish->qos == 0) {
		// QOS 0 packets are released immediately

		RRR_DBG_3("Receive PUBLISH QOS 0 packet %p with id %u add directly to publish queue\n",
				publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

		RRR_MQTT_P_INCREF(publish);
		ram_session->delivery_method(ram_session, publish);
		RRR_MQTT_P_DECREF(publish);
	}
	else if (publish->qos == 1) {
		// QOS 1 packets are released when we send PUBACK

		RRR_DBG_3("Receive PUBLISH QOS 1 packet %p with id %u add to QoS 1/2 queue\n",
				publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

		RRR_MQTT_P_INCREF(publish);
		if (__rrr_mqtt_session_ram_fifo_write(
				&ram_session->from_remote_queue.buffer,
				(struct rrr_mqtt_p *) publish,
				sizeof(*publish),
				publish->packet_identifier,
				1
		) != 0) {
			RRR_MSG_0("Could not write to from_remote_queue in __rrr_mqtt_session_ram_receive_publish\n");
			ret = RRR_MQTT_SESSION_ERROR;
			RRR_MQTT_P_DECREF(publish);
			goto out;
		}
	}
	else if (publish->qos == 2) {
		// QOS 2 packets are released when we send PUBCOMP

		struct find_qos2_publish_data callback_data = {
				publish,
				NULL,
				0
		};

		// Callback will INCREF the packet it finds
		int ret_tmp = rrr_fifo_buffer_read_minimum (
				&ram_session->from_remote_queue.buffer,
				NULL,
				__rrr_mqtt_session_ram_find_qos2_publish_callback,
				&callback_data,
				publish->packet_identifier - 1,
				0
		);
		if (ret_tmp != 0) {
			if ((ret_tmp & RRR_FIFO_CALLBACK_ERR) != 0) {
				RRR_MSG_0("Soft error while iterating QoS2 publish queue in __rrr_mqtt_session_ram_receive_publish\n");
				ret |= RRR_MQTT_SESSION_ERROR;
				ret_tmp = ret_tmp & ~(RRR_FIFO_CALLBACK_ERR);
			}
			if (ret_tmp != 0) {
				RRR_MSG_0("Internal error in __rrr_mqtt_session_ram_receive_publish while iterating QoS2 publish queue\n");
				ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			}
			goto out;
		}

		struct rrr_mqtt_p_publish *publish_in_buffer = callback_data.publish_in_buffer;

		if (publish_in_buffer == NULL) {
			if (publish->dup != 0) {
				RRR_MSG_0("Received a new QoS2 PUBLISH packet which had DUP flag set\n");
				ret = RRR_MQTT_SESSION_ERROR;
				goto out;
			}

			RRR_DBG_3("Receive PUBLISH packet %p with id %u add to QoS2 queue\n",
					publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

			RRR_MQTT_P_INCREF(publish);
			if (__rrr_mqtt_session_ram_fifo_write(
					&ram_session->from_remote_queue.buffer,
					(struct rrr_mqtt_p *) publish,
					sizeof(*publish),
					publish->packet_identifier,
					1
			) != 0) {
				RRR_MSG_0("Could not write to from_remote_queue in __rrr_mqtt_session_ram_receive_publish\n");
				ret = RRR_MQTT_SESSION_ERROR;
				RRR_MQTT_P_DECREF(publish);
				goto out;
			}
		}
		else {
			RRR_DBG_3("Receive duplicate PUBLISH packet %p with id %u, already in QoS2 queue\n",
					publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

			RRR_MQTT_P_LOCK(publish_in_buffer);

			if (publish_in_buffer->payload != NULL) {
				RRR_MQTT_P_LOCK(publish_in_buffer->payload);
			}
			if (publish->payload != NULL) {
				RRR_MQTT_P_LOCK(publish->payload);
			}

			if ((((publish_in_buffer->payload != NULL) ^ (publish->payload != NULL)) == 1) ||
				(publish_in_buffer->payload != NULL && (publish_in_buffer->payload->length != publish->payload->length))
			) {
				RRR_MSG_0("Received a QoS2 PUBLISH packet with equal id to another packet of different size\n");
				ret = RRR_MQTT_SESSION_ERROR;
				goto unlock_payload;
			}
			if (publish->dup != 1) {
				RRR_MSG_0("Received a re-sent QoS2 PUBLISH packet which did not have DUP flag set\n");
				ret = RRR_MQTT_SESSION_ERROR;
				goto unlock_payload;
			}

			unlock_payload:
			if (publish_in_buffer->payload != NULL) {
				RRR_MQTT_P_UNLOCK(publish_in_buffer->payload);
			}
			if (publish->payload != NULL) {
				RRR_MQTT_P_UNLOCK(publish->payload);
			}

			RRR_MQTT_P_UNLOCK(publish_in_buffer);
			RRR_MQTT_P_DECREF(publish_in_buffer);

			goto out;
		}
	}
	else {
		RRR_BUG("Invalid QOS in __rrr_mqtt_session_ram_receive_publish");
	}

	out:
	return ret;
}

struct iterate_send_queue_callback_data {
	int (*callback)(struct rrr_mqtt_p *packet, void *arg);
	void *callback_arg;
	unsigned int max_count;
	unsigned int counter;
	struct rrr_mqtt_session_collection_ram_data *ram_data;
	struct rrr_mqtt_session_ram *ram_session;
};

static int __rrr_mqtt_session_ram_iterate_send_queue_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	// context is fifo_search

	(void)(size);

	struct iterate_send_queue_callback_data *iterate_callback_data = arg;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	RRR_MQTT_P_LOCK(packet);

	if (packet->packet_identifier == 0) {
		if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
		) {
			uint16_t packet_identifier = rrr_mqtt_id_pool_get_id(&iterate_callback_data->ram_session->id_pool);
			if (packet_identifier == 0) {
				RRR_DBG_1("ID pool exhausted in __rrr_mqtt_session_ram_iterate_send_queue_callback, must wait until more packets are sent to remote\n");
				// Retry immediately
				packet->last_attempt = 0;
				goto out_unlock;
			}

			RRR_DBG_3("Setting new packet identifier %u for packet type %s while iterating send queue\n",
					packet_identifier, RRR_MQTT_P_GET_TYPE_NAME(packet));

			RRR_MQTT_P_SET_PACKET_ID_WITH_RELEASER (
					packet,
					packet_identifier,
					__rrr_mqtt_session_ram_release_packet_id,
					iterate_callback_data->ram_data,
					iterate_callback_data->ram_session
			);
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBACK ||
				RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREC ||
				RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL ||
				RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBCOMP ||
				RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK ||
				RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK
		) {
			RRR_BUG("Message ID was zero for %s packet in __rrr_mqtt_session_ram_iterate_send_queue_callback",
					RRR_MQTT_P_GET_TYPE_NAME(packet));
		}
	}

	if (packet->last_attempt != 0) {
		goto out_unlock;
	}

	struct rrr_mqtt_p *packet_to_transmit = NULL;

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;
		if (publish->qos_packets.puback != NULL ||
			publish->qos_packets.pubcomp != NULL) {
			// Nothing more to do for this QoS handshake
			goto out_unlock;
		}

		// NOTE ! This functions handles packets in both directions. For a given PUBLISH packet,
		//        the most recent ACK not acknowledged by remote will be sent.

		if ((publish->qos == 0 || publish->qos == 1) && publish->is_outbound == 1) {
			packet_to_transmit = packet;
		}
		else if (publish->qos == 2) {
			if (publish->is_outbound == 1) {
				// PUBCOMP not yet received for transmitted PUBREL
				if (publish->qos_packets.pubcomp == NULL && publish->qos_packets.pubrel != NULL) {
					packet_to_transmit = (struct rrr_mqtt_p *) publish->qos_packets.pubrel;
				}
				else if (publish->qos_packets.pubrec == NULL) {
					packet_to_transmit = packet;
				}
			}
			else {
				// PUBREL not yet received for transmitted PUBREC
				if (publish->qos_packets.pubrel == NULL && publish->qos_packets.pubrec != NULL) {
					packet_to_transmit = (struct rrr_mqtt_p *) publish->qos_packets.pubrec;
				}
			}
		}
	}
	else if (
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;
		if (sub_usub->sub_usuback != NULL) {
			goto out_unlock;
		}
		packet_to_transmit = packet;
	}
	else {
		packet_to_transmit = packet;
	}

	if (packet_to_transmit == NULL) {
		goto out_unlock;
	}

	if (++iterate_callback_data->counter > iterate_callback_data->max_count) {
		ret = RRR_FIFO_SEARCH_STOP;
		goto out_unlock;
	}

	if (packet->dup != 0) {
		RRR_DBG_1("!! Retransmit !! Packet of type %s id %u\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet_to_transmit), RRR_MQTT_P_GET_IDENTIFIER(packet_to_transmit));
	}

	RRR_DBG_3 ("Transmission of %s %p identifier %u last attempt %" PRIu64 " holder packet is %p\n",
			RRR_MQTT_P_GET_TYPE_NAME(packet_to_transmit), packet_to_transmit, packet_to_transmit->packet_identifier, packet->last_attempt, packet);

	ret = iterate_callback_data->callback (
			packet_to_transmit,
			iterate_callback_data->callback_arg
	);

	// Set the last attempt of the original packet, as packet_to transmit
	// might be store inside another packet
	packet->last_attempt = rrr_time_get_64();

	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Internal error from callback in __rrr_mqtt_session_ram_iterate_send_queue_callback, return was %i\n", ret);
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out_unlock;
	}
	else if (ret == RRR_FIFO_SEARCH_STOP) {
		// Callback wants to stop (with no CALLBACK_ERR set), this is OK
		goto out_unlock;
	}
	else if (ret != 0) {
		RRR_MSG_0("Soft error from callback in __rrr_mqtt_session_ram_iterate_send_queue_callback, return was %i\n", ret);
		ret = RRR_FIFO_CALLBACK_ERR|RRR_FIFO_SEARCH_STOP;
		goto out_unlock;
	}
	else {
		ret = RRR_FIFO_OK;
	}

	out_unlock:
		RRR_MQTT_P_UNLOCK(packet);

	return ret;
}

static int __rrr_mqtt_session_ram_iterate_send_queue (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		int (*callback)(struct rrr_mqtt_p *packet, void *arg),
		void *callback_arg,
		unsigned int max_count
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	struct iterate_send_queue_callback_data callback_data = {
			callback,
			callback_arg,
			max_count,
			0,
			ram_data,
			ram_session
	};

	// (RE)TRANSMIT PACKETS IN WHICH PUBLISH ORIGINATIED FROM US
	ret = rrr_fifo_buffer_read (
			&ram_session->to_remote_queue.buffer,
			__rrr_mqtt_session_ram_iterate_send_queue_callback,
			&callback_data,
			0
	);

	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Internal error in __rrr_mqtt_session_ram_iterate_send_queue while iterating buffer A\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}
	else if ((ret & RRR_FIFO_CALLBACK_ERR) != 0) {
		RRR_MSG_0("Soft error in __rrr_mqtt_session_ram_iterate_send_queue while iterating buffer A\n");
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	callback_data.counter = 0;

	// RETRANSMIT PACKETS IN WHICH PUBLISH ORIGINATIED FROM REMOTE
	ret = rrr_fifo_buffer_read (
			&ram_session->from_remote_queue.buffer,
			__rrr_mqtt_session_ram_iterate_send_queue_callback,
			&callback_data,
			0
	);

	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Internal error in __rrr_mqtt_session_ram_iterate_send_queue while iterating buffer B\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}
	else if ((ret & RRR_FIFO_CALLBACK_ERR) != 0) {
		RRR_MSG_0("Soft error in __rrr_mqtt_session_ram_iterate_send_queue while iterating buffer B\n");
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	out:
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_notify_disconnect (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		uint8_t reason_v5
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	SESSION_RAM_LOCK(ram_session);

	RRR_DBG_1("Session notify disconnect expiry interval: %" PRIu32 " clean session: %i reason: %u\n",
			ram_session->session_properties.session_expiry,
			ram_session->clean_session,
			reason_v5
	);

	if (reason_v5 == RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER) {
		RRR_DBG_1("Session notify disconnect no deletion due to session take-over\n");
		goto no_delete;
	}

 	if (ram_session->clean_session == 1) {
		RRR_DBG_1("Destroying session which had clean session set upon disconnect\n");
		ret = RRR_MQTT_SESSION_DELETED;
	}
	else if (ram_session->session_properties.session_expiry == 0) {
		RRR_DBG_1("Destroying session with zero session expiry upon disconnect\n");
		ret = RRR_MQTT_SESSION_DELETED;
	}

	if (ret == RRR_MQTT_SESSION_DELETED) {
		__rrr_mqtt_session_collection_remove (
				ram_data,
				ram_session
		);
		*session_to_find = NULL;

		SESSION_COLLECTION_RAM_LOCK(ram_data);
		__rrr_mqtt_session_collection_ram_stats_notify_delete(ram_data);
		SESSION_COLLECTION_RAM_UNLOCK(ram_data);
	}

	no_delete:
	SESSION_RAM_UNLOCK(ram_session);
	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_send_packet (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	RRR_MQTT_P_LOCK(packet);

	// TODO : Re-order based on probability
	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE) {
		if ((ret = __rrr_mqtt_session_ram_add_subscriptions(
				ram_session,
				(struct rrr_mqtt_p_subscribe *) packet)
		) != RRR_MQTT_SESSION_OK) {
			goto out_unlock;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE) {
		// Changes take effect when we receive UNSUBACK
		goto out_write_to_buffer;
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;
		publish->packet_identifier = 0;
		publish->is_outbound = 1;
		RRR_DBG_3("Send new PUBLISH packet with topic '%s'\n", publish->topic);
	}
	else if (RRR_MQTT_P_IS_ACK(packet)) {
		RRR_DBG_3("Send ACK packet %p with identifier %u of type %s\n",
				packet, RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

		int packet_was_outbound = 0;
		switch (RRR_MQTT_P_GET_TYPE(packet)) {
			case RRR_MQTT_P_TYPE_PUBACK:
			case RRR_MQTT_P_TYPE_PUBREC:
			case RRR_MQTT_P_TYPE_PUBCOMP:
				break;
			case RRR_MQTT_P_TYPE_SUBACK:
			case RRR_MQTT_P_TYPE_UNSUBACK:
				goto out_write_to_buffer;
				break;
			case RRR_MQTT_P_TYPE_PUBREL:
				packet_was_outbound = 1;
				break;
			default:
				RRR_BUG("Unknown ACK packet %u in __rrr_mqtt_session_ram_send_packet\n",
						RRR_MQTT_P_GET_TYPE(packet));
		};

		// Incref, make sure nothing bad happens
		RRR_MQTT_P_INCREF(packet);
		unsigned int match_count = 0;
		ret = __rrr_mqtt_session_ram_process_ack(&match_count, ram_session, packet, packet_was_outbound);
		RRR_MQTT_P_DECREF(packet);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGREQ) {
		goto out_write_to_buffer;
	}
	else {
		RRR_BUG("Unknown packet type %u in __rrr_mqtt_session_ram_send_packet\n",
				RRR_MQTT_P_GET_TYPE(packet));
	}

	out_write_to_buffer:
	RRR_MQTT_P_UNLOCK(packet);

	RRR_MQTT_P_INCREF(packet);
	if (__rrr_mqtt_session_ram_fifo_write(&ram_session->to_remote_queue.buffer, packet, sizeof(*packet), 0, 1) != 0) {
		RRR_MSG_0("Could not write to to_remote_queue in __rrr_mqtt_session_ram_send_packet\n");
		ret = 1;
		RRR_MQTT_P_DECREF(packet);
	}

	RRR_MQTT_P_LOCK(packet);

	out_unlock:
	RRR_MQTT_P_UNLOCK(packet);
	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_receive_packet (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet,
		unsigned int *ack_match_count
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		RRR_BUG("BUG: Packet was not locked in __rrr_mqtt_session_ram_receive_packet\n");
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		ret = __rrr_mqtt_session_ram_receive_publish(ram_session, (struct rrr_mqtt_p_publish *) packet);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE) {
		// The packet handler for SUBSCRIBE (in broker) is responsible for setting
		// error flag on invalid subscriptions in the packet. These are not added
		// to the session.
		ret = __rrr_mqtt_session_ram_add_subscriptions(ram_session, (struct rrr_mqtt_p_subscribe *) packet);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE) {
		ret = __rrr_mqtt_session_ram_remove_subscriptions(ram_session, (struct rrr_mqtt_p_unsubscribe *) packet);
	}
	else if (RRR_MQTT_P_IS_ACK(packet)) {
		RRR_DBG_3("Receive ACK packet %p with identifier %u of type %s\n",
			packet, RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

		int packet_was_outbound = 0;
		switch (RRR_MQTT_P_GET_TYPE(packet)) {
			case RRR_MQTT_P_TYPE_PUBACK:
			case RRR_MQTT_P_TYPE_PUBREC:
			case RRR_MQTT_P_TYPE_PUBCOMP:
			case RRR_MQTT_P_TYPE_SUBACK:
			case RRR_MQTT_P_TYPE_UNSUBACK:
			case RRR_MQTT_P_TYPE_PINGRESP:
				packet_was_outbound = 1;
				break;
			case RRR_MQTT_P_TYPE_PUBREL:
				break;
			default:
				RRR_BUG("Unknown ACK packet %u in __rrr_mqtt_session_ram_receive_packet\n",
						RRR_MQTT_P_GET_TYPE(packet));
		};

		// Incref, make sure nothing bad happens
		RRR_MQTT_P_INCREF(packet);
		ret = __rrr_mqtt_session_ram_process_ack(ack_match_count, ram_session, packet, packet_was_outbound);
		RRR_MQTT_P_DECREF(packet);
	}
	else {
		RRR_BUG("Unknown packet type %u in __rrr_mqtt_session_ram_handle_packet\n",
				RRR_MQTT_P_GET_TYPE(packet));
	}

	SESSION_RAM_DECREF();

	return ret;
}

const struct rrr_mqtt_session_collection_methods methods = {
		__rrr_mqtt_session_collection_ram_get_stats,
		__rrr_mqtt_session_collection_ram_iterate_and_clear_local_delivery,
		__rrr_mqtt_session_collection_ram_maintain,
		__rrr_mqtt_session_collection_ram_destroy,
		__rrr_mqtt_session_collection_ram_get_session,
		__rrr_mqtt_session_ram_init,
		__rrr_mqtt_session_ram_clean,
		__rrr_mqtt_session_ram_reset_properties,
		__rrr_mqtt_session_ram_heartbeat,
		__rrr_mqtt_session_ram_iterate_send_queue,
		__rrr_mqtt_session_ram_notify_disconnect,
		__rrr_mqtt_session_ram_send_packet,
		__rrr_mqtt_session_ram_receive_packet
};

int rrr_mqtt_session_collection_ram_new (struct rrr_mqtt_session_collection **sessions, void *arg) {
	int ret = 0;

	if (arg != NULL) {
		RRR_BUG("arg was not NULL in rrr_mqtt_session_collection_ram_new\n");
	}

	struct rrr_mqtt_session_collection_ram_data *ram_data = malloc(sizeof(*ram_data));
	if (ram_data == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out;
	}

	memset (ram_data, '\0', sizeof(*ram_data));

	if (rrr_mqtt_session_collection_init (
			(struct rrr_mqtt_session_collection *) ram_data,
			&methods
	) != 0) {
		RRR_MSG_0("Could not initialize session collection in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out_destroy_ram_data;
	}

	if (pthread_mutex_init(&ram_data->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out_destroy_collection;
	}

	if (rrr_fifo_buffer_init_custom_free(&ram_data->retain_queue.buffer, rrr_mqtt_p_standardized_decref) != 0) {
		RRR_MSG_0("Could not initialize buffer in rrr_mqtt_session_collection_ram_new\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_mutex;
	}

	if (rrr_fifo_buffer_init_custom_free(&ram_data->publish_forward_queue.buffer, rrr_mqtt_p_standardized_decref) != 0) {
		RRR_MSG_0("Could not initialize buffer in rrr_mqtt_session_collection_ram_new\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_retain_queue;
	}

	if (rrr_fifo_buffer_init_custom_free(&ram_data->publish_local_queue.buffer, rrr_mqtt_p_standardized_decref) != 0) {
		RRR_MSG_0("Could not initialize buffer in rrr_mqtt_session_collection_ram_new\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_publish_queue;
	}

	*sessions = (struct rrr_mqtt_session_collection *) ram_data;

	goto out;

/*	out_destroy_local_delivery_queue:
		fifo_buffer_invalidate(&ram_data->local_delivery_queue.buffer);*/
	out_destroy_publish_queue:
		rrr_fifo_buffer_clear(&ram_data->publish_forward_queue.buffer);
	out_destroy_retain_queue:
		rrr_fifo_buffer_clear(&ram_data->retain_queue.buffer);
		// TODO : Implement destroy
		//fifo_buffer_destroy(&ram_data->retain_queue);
	out_destroy_mutex:
		pthread_mutex_destroy(&ram_data->lock);
	out_destroy_collection:
		rrr_mqtt_session_collection_destroy((struct rrr_mqtt_session_collection *)ram_data);
	out_destroy_ram_data:
		free(ram_data);

	out:
	return ret;
}
