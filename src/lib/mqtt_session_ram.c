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

#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "mqtt_session_ram.h"
#include "mqtt_session.h"
#include "mqtt_packet.h"
#include "mqtt_subscription.h"
#include "vl_time.h"
#include "linked_list.h"

struct rrr_mqtt_session_ram {
	// MUST be first
	struct rrr_mqtt_session session;

	RRR_LINKED_LIST_NODE(struct rrr_mqtt_session_ram);

	// When updated, global collection lock must be held
	int users;
	pthread_mutex_t lock;

	struct rrr_mqtt_p_queue send_queue;

	char *client_id;

	uint64_t last_seen;

	uint32_t session_expiry;
	uint32_t retry_interval;
	uint32_t max_in_flight;
	int clean_session;

	struct rrr_mqtt_subscription_collection *subscriptions;
};

struct rrr_mqtt_session_collection_ram_data {
	pthread_mutex_t lock;
	RRR_LINKED_LIST_HEAD(struct rrr_mqtt_session_ram);
	struct rrr_mqtt_p_queue retain_queue;
};

int __rrr_mqtt_session_collection_ram_create_and_add_session_unlocked (
		struct rrr_mqtt_session_ram **target,
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;
	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;

	result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_session_collection_ram_create_session_unlocked A\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	if (fifo_buffer_init_custom_free(&result->send_queue.buffer, rrr_mqtt_p_decref) != 0) {
		VL_MSG_ERR("Could not initialize buffer in _rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_free_result;
	}

	result->client_id = malloc(strlen(client_id) + 1);
	if (result->client_id == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_session_collection_ram_create_session_unlocked B\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_buffer;
	}
	strcpy (result->client_id, client_id);

	if ((ret = rrr_mqtt_subscription_collection_new(&result->subscriptions)) != 0) {
		VL_MSG_ERR("Could not create subscription collection in __rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_free_client_id;
	}

	if (pthread_mutex_init(&result->lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize lock in __rrr_mqtt_session_collection_ram_create_session_unlocked\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_subscriptions;
	}

	result->users = 1;

	RRR_LINKED_LIST_PUSH(data,result);

	*target = result;

	goto out;

	out_destroy_subscriptions:
		rrr_mqtt_subscription_collection_destroy(result->subscriptions);

	out_free_client_id:
		free(result->client_id);

	out_destroy_buffer:
		fifo_buffer_invalidate(&result->send_queue.buffer);
//	TODO : Implement
//	fifo_buffer_destroy(&result->send_queue.buffer);

	out_free_result:
		if (result != NULL) {
			RRR_FREE_IF_NOT_NULL(result->client_id);
			RRR_FREE_IF_NOT_NULL(result);
		}

	out:
		return ret;
}

static int __rrr_mqtt_session_ram_decref_unlocked (struct rrr_mqtt_session_ram *session) {
	if (--(session->users) >= 1) {
		return 0;
	}
	if (session->users < 0) {
		VL_BUG("users was < 0 in __rrr_mqtt_session_ram_destroy_unlocked\n");
	}
	pthread_mutex_destroy(&session->lock);
	rrr_mqtt_subscription_collection_destroy(session->subscriptions);
	RRR_FREE_IF_NOT_NULL(session->client_id);
	fifo_buffer_invalidate(&session->send_queue.buffer);
//  TODO : Look into proper destruction of the buffer mutexes.
//	fifo_buffer_destroy(&session->send_queue.buffer);
	free(session);
	return 0;
}


static void __rrr_mqtt_session_ram_decref (struct rrr_mqtt_session_collection_ram_data *data, struct rrr_mqtt_session_ram *session) {
	pthread_mutex_lock(&data->lock);
	__rrr_mqtt_session_ram_decref_unlocked (session);
	pthread_mutex_unlock(&data->lock);
}

static void __rrr_mqtt_session_ram_incref_unlocked (struct rrr_mqtt_session_ram *session) {
	session->users++;
}

static int __rrr_mqtt_session_collection_ram_maintain (struct rrr_mqtt_session_collection *sessions) {
	struct rrr_mqtt_session_collection_ram_data *data = sessions->private_data;

	pthread_mutex_lock(&data->lock);
	uint64_t time_now = time_get_64();

	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		uint64_t time_diff = time_now - node->last_seen;

//		printf ("Expire check: %" PRIu64 " > %" PRIu64 "\n", time_diff, (uint64_t) test->session_expiry * 1000000);
		if (time_diff > (uint64_t) node->session_expiry * 1000000) {
			VL_DEBUG_MSG_1("Session expired for client '%s' in __rrr_mqtt_session_collection_ram_maintain\n",
					node->client_id);
			RRR_LINKED_LIST_SET_DESTROY();
		}
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(data, __rrr_mqtt_session_ram_decref_unlocked(node));

	pthread_mutex_unlock(&data->lock);

	return 0;
}

static void __rrr_mqtt_session_collection_ram_destroy (struct rrr_mqtt_session_collection *sessions) {
	struct rrr_mqtt_session_collection_ram_data *data = sessions->private_data;

	pthread_mutex_lock(&data->lock);
	fifo_buffer_invalidate(&data->retain_queue.buffer);
	// TODO : implement destroy
	// fifo_buffer_destroy(&data->retain_queue);
	RRR_LINKED_LIST_DESTROY(data, struct rrr_mqtt_session_ram, __rrr_mqtt_session_ram_decref_unlocked(node));
	pthread_mutex_unlock(&data->lock);

	pthread_mutex_destroy(&data->lock);

	RRR_FREE_IF_NOT_NULL(sessions->private_data);

	rrr_mqtt_session_collection_destroy(sessions);
}

static void __rrr_mqtt_session_collection_remove (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session_ram *session
) {
	pthread_mutex_lock(&data->lock);

	RRR_LINKED_LIST_REMOVE_NODE(
			data,
			struct rrr_mqtt_session_ram,
			session,
			__rrr_mqtt_session_ram_decref_unlocked(node)
	);

	pthread_mutex_unlock(&data->lock);

	if (session != NULL) {
		VL_BUG("Session not found in __rrr_mqtt_session_collection_remove_unlocked\n");
	}
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_find_session_unlocked (
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;

	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		if (strcmp(node->client_id, client_id) == 0) {
			if (result != NULL) {
				VL_BUG("Found two equal client ids in __rrr_mqtt_session_collection_ram_find_session_unlocked\n");
			}
			result = node;
		}
	RRR_LINKED_LIST_ITERATE_END();


	return result;
}

static void __rrr_mqtt_session_ram_heartbeat_unlocked (
		struct rrr_mqtt_session_ram *ram_session
) {
	ram_session->last_seen = time_get_64();
}

static int __rrr_mqtt_session_collection_ram_get_session (
		struct rrr_mqtt_session **target,
		struct rrr_mqtt_session_collection *sessions,
		const char *client_id,
		int *session_present,
		int no_creation
) {
	struct rrr_mqtt_session_collection_ram_data *data = sessions->private_data;

	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;
	*session_present = 0;

	struct rrr_mqtt_session_ram *result = NULL;

	pthread_mutex_lock(&data->lock);
	result = __rrr_mqtt_session_collection_ram_find_session_unlocked (data, client_id);

	if (result != NULL) {
		*session_present = 1;
	}
	else if (no_creation == 0) {
		ret = __rrr_mqtt_session_collection_ram_create_and_add_session_unlocked (&result, data, client_id);
		if (ret != RRR_MQTT_SESSION_OK) {
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out_unlock;
		}
	}

	VL_DEBUG_MSG_1("Got a session, session present was %i and no creation was %i\n",
			*session_present, no_creation);

	__rrr_mqtt_session_ram_heartbeat_unlocked(result);

	*target = (struct rrr_mqtt_session *) result;

	out_unlock:
	pthread_mutex_unlock(&data->lock);

	return ret;
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_session_find_and_incref (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session *session
) {
	struct rrr_mqtt_session_ram *found = NULL;

	pthread_mutex_lock(&data->lock);

	RRR_LINKED_LIST_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		if ((void*) node == (void*) session) {
			__rrr_mqtt_session_ram_incref_unlocked(node);
			found = node;
			RRR_LINKED_LIST_SET_STOP();
		}
	RRR_LINKED_LIST_ITERATE_END();

	pthread_mutex_unlock(&data->lock);

	return found;
}

#define SESSION_FUNCTION_INCREF_OR_RETURN() \
	do { \
		struct rrr_mqtt_session_collection_ram_data *ram_data = (collection)->private_data; \
		struct rrr_mqtt_session_ram *ram_session = __rrr_mqtt_session_collection_ram_session_find_and_incref(ram_data, (*session_to_find)); \
		if (ram_session == NULL) { \
			*session_to_find = NULL; \
			return RRR_MQTT_SESSION_DELETED; \
		}

#define SESSION_FUNCTION_DECREF() \
		__rrr_mqtt_session_ram_decref ((ram_data), (ram_session)); \
	} while (0)

#define SESSION_LOCK() \
	do { pthread_mutex_lock(&ram_session->lock)

#define SESSION_UNLOCK() \
	pthread_mutex_unlock(&ram_session->lock); } while(0)

static int __rrr_mqtt_session_ram_init (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		uint32_t session_expiry,
		uint32_t retry_interval,
		uint32_t max_in_flight,
		int clean_session,
		int *session_was_present
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();
	SESSION_LOCK();

	ram_session->session_expiry = session_expiry;
	ram_session->retry_interval = retry_interval;
	ram_session->max_in_flight = max_in_flight;
	ram_session->last_seen = time_get_64();
	ram_session->clean_session = clean_session;

	if (clean_session == 1) {
		*session_was_present = 0;
		if (fifo_buffer_clear(&ram_session->send_queue.buffer) != 0) {
			VL_BUG("Buffer was invalid in __rrr_mqtt_session_ram_init\n");
		}
	}

	SESSION_UNLOCK();
	SESSION_FUNCTION_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_heartbeat (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();
	SESSION_LOCK();

	__rrr_mqtt_session_ram_heartbeat_unlocked(ram_session);

	SESSION_UNLOCK();
	SESSION_FUNCTION_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_push_send_queue (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();

	fifo_buffer_write (&ram_session->send_queue.buffer, (char*) packet, RRR_MQTT_P_GET_SIZE(packet));

	SESSION_FUNCTION_DECREF();
	return ret;
}

struct ram_process_ack_callback_data {
	struct rrr_mqtt_p *ack_packet;
	uint8_t find_packet_type;
	int found;
};

static int __rrr_mqtt_session_ram_process_ack_callback (FIFO_CALLBACK_ARGS) {
	int ret = FIFO_OK;

	(void)(size);

	struct ram_process_ack_callback_data *ack_callback_data = callback_data->private_data;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	if (	(RRR_MQTT_P_GET_TYPE(packet) == ack_callback_data->find_packet_type) &&
			(RRR_MQTT_P_GET_IDENTIFIER(packet) == RRR_MQTT_P_GET_IDENTIFIER(ack_callback_data->ack_packet))
	) {
		ret = FIFO_SEARCH_GIVE|FIFO_SEARCH_FREE;
		ack_callback_data->found++;
	}

	return ret;
}

static int __rrr_mqtt_session_ram_process_ack (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();

	if (!RRR_MQTT_P_IS_ACK(packet)) {
		VL_BUG("Received non-ACK packet in __rrr_mqtt_session_ram_process_ack\n");
	}

	printf("Processing ACK packet with idientifier %u of type %s\n",
			RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

	struct ram_process_ack_callback_data callback_data = {
			packet,
			RRR_MQTT_P_GET_COMPLEMENTARY(packet),
			0
	};
	struct fifo_callback_args fifo_callback_data = {NULL, &callback_data, 0};

	ret = fifo_search (
			&ram_session->send_queue.buffer,
			__rrr_mqtt_session_ram_process_ack_callback,
			&fifo_callback_data,
			0
	);

	if (ret != FIFO_OK) {
		if (ret == FIFO_GLOBAL_ERR) {
			VL_MSG_ERR("Internal error while searching send buffer in __rrr_mqtt_session_ram_process_ack\n");
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
		VL_MSG_ERR("Soft error while searching send buffer in __rrr_mqtt_session_ram_process_ack\n");
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	if (callback_data.found > 1) {
		VL_BUG("Two packets with the same identifier %u matched while processing in __rrr_mqtt_session_ram_process_ack\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet));
	}
	else if (callback_data.found == 0) {
		VL_MSG_ERR("No packet with identifier %u matched while processing ACK packet of type %s\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	out:
	SESSION_FUNCTION_DECREF();
	return ret;
}

struct iterate_retries_callback_data {
	int (*callback)(struct rrr_mqtt_p *packet, void *arg);
	void *callback_arg;
	int force;
	uint64_t retry_interval_millis;
	int callback_return;
};

static int __rrr_mqtt_session_ram_iterate_retries_callback (FIFO_CALLBACK_ARGS) {
	int ret = FIFO_OK;

	(void)(size);

	struct iterate_retries_callback_data *retries_callback_data = callback_data->private_data;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	RRR_MQTT_P_LOCK(packet);

	if (	retries_callback_data->force == 1 ||
			time_get_64() - packet->last_attempt > retries_callback_data->retry_interval_millis
	) {
		RRR_MQTT_P_UNLOCK(packet);
		ret = retries_callback_data->callback(packet, retries_callback_data->callback_arg);
		if (ret != 0) {
			retries_callback_data->callback_return = ret;
			ret = FIFO_CALLBACK_ERR|FIFO_SEARCH_STOP;
			goto out_nolock;
		}
		RRR_MQTT_P_LOCK(packet);
		packet->last_attempt = time_get_64();
	}

	RRR_MQTT_P_UNLOCK(packet);

	out_nolock:
	return ret;
}

static int __rrr_mqtt_session_ram_iterate_retries (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		int (*callback)(struct rrr_mqtt_p *packet, void *arg),
		void *callback_arg,
		int force
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();

	struct iterate_retries_callback_data callback_data = {
			callback,
			callback_arg,
			force,
			ram_session->retry_interval * 1000,
			RRR_MQTT_SESSION_OK
	};

	struct fifo_callback_args fifo_callback_args = {NULL, &callback_data, 0};

	ret = fifo_search (
			&ram_session->send_queue.buffer,
			__rrr_mqtt_session_ram_iterate_retries_callback,
			&fifo_callback_args,
			0
	);

	if (ret == FIFO_GLOBAL_ERR) {
		VL_MSG_ERR("Buffer error in __rrr_mqtt_session_ram_iterate_retries\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}
	if (callback_data.callback_return != RRR_MQTT_SESSION_OK) {
		ret = 0;

		if ((callback_data.callback_return & RRR_MQTT_SESSION_ERROR) != 0) {
			callback_data.callback_return = callback_data.callback_return & ~RRR_MQTT_SESSION_ERROR;
			VL_MSG_ERR("Session error while iterating retries in __rrr_mqtt_session_ram_iterate_retries\n");
		}
		if (callback_data.callback_return != 0) {
			VL_MSG_ERR("Internal error in __rrr_mqtt_session_ram_iterate_retries\n");
			ret |= RRR_MQTT_SESSION_INTERNAL_ERROR;
		}

		ret |= RRR_MQTT_SESSION_ERROR;
	}

	SESSION_FUNCTION_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_notify_disconnect (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;
	SESSION_FUNCTION_INCREF_OR_RETURN();
	SESSION_LOCK();

	if (ram_session->clean_session == 1) {
		VL_DEBUG_MSG_1("Destroying session which had clean session set upon disconnect\n");
		__rrr_mqtt_session_collection_remove (
				ram_data,
				ram_session
		);
		*session_to_find = NULL;
		ret = RRR_MQTT_SESSION_DELETED;
	}

	SESSION_UNLOCK();
	SESSION_FUNCTION_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_add_subscriptions (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		const struct rrr_mqtt_subscription_collection *subscriptions
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();
	SESSION_LOCK();

	ret = rrr_mqtt_subscription_collection_append_unique_copy_from_collection(ram_session->subscriptions, subscriptions);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		VL_MSG_ERR("Could not add subscriptions to session in __rrr_mqtt_session_ram_add_subscriptions\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	SESSION_UNLOCK();
	SESSION_FUNCTION_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_receive_publish (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_FUNCTION_INCREF_OR_RETURN();
	SESSION_LOCK();



	SESSION_UNLOCK();
	SESSION_FUNCTION_DECREF();

	return ret;
}

const struct rrr_mqtt_session_collection_methods methods = {
		__rrr_mqtt_session_collection_ram_maintain,
		__rrr_mqtt_session_collection_ram_destroy,
		__rrr_mqtt_session_collection_ram_get_session,
		__rrr_mqtt_session_ram_init,
		__rrr_mqtt_session_ram_heartbeat,
		__rrr_mqtt_session_ram_push_send_queue,
		__rrr_mqtt_session_ram_process_ack,
		__rrr_mqtt_session_ram_iterate_retries,
		__rrr_mqtt_session_ram_notify_disconnect,
		__rrr_mqtt_session_ram_add_subscriptions,
		__rrr_mqtt_session_ram_receive_publish
};

int rrr_mqtt_session_collection_ram_new (struct rrr_mqtt_session_collection **sessions, void *arg) {
	int ret = 0;

	if (arg != NULL) {
		VL_BUG("arg was not NULL in rrr_mqtt_session_collection_ram_new\n");
	}

	struct rrr_mqtt_session_collection *res = NULL;
	if (rrr_mqtt_session_collection_new (
			&res,
			&methods
	) != 0) {
		VL_MSG_ERR("Could not create session collection in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out;
	}

	struct rrr_mqtt_session_collection_ram_data *ram_data = malloc(sizeof(*ram_data));
	if (ram_data == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out_destroy_collection;
	}

	memset (ram_data, '\0', sizeof(*ram_data));

	if (pthread_mutex_init(&ram_data->lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize mutex in rrr_mqtt_session_collection_ram_new\n");
		ret = 1;
		goto out_destroy_ram_data;
	}

	if (fifo_buffer_init_custom_free(&ram_data->retain_queue.buffer, rrr_mqtt_p_decref) != 0) {
		VL_MSG_ERR("Could not initialize buffer in rrr_mqtt_session_collection_ram_new\n");
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_mutex;
	}

	res->private_data = ram_data;

	*sessions = res;

	goto out;

	out_destroy_mutex:
		pthread_mutex_destroy(&ram_data->lock);

	out_destroy_ram_data:
		free(ram_data);

	out_destroy_collection:
		rrr_mqtt_session_collection_destroy(res);

	out:
	return ret;
}
