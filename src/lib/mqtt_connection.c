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

#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "ip.h"
#include "buffer.h"
#include "vl_time.h"
#include "../global.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_packet.h"
#include "mqtt_parse.h"
#include "mqtt_assemble.h"

int __rrr_mqtt_connection_collection_read_lock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}
	pthread_mutex_unlock(&connections->lock);

	int pass = 0;
	while (pass != 1) {
		pthread_mutex_lock(&connections->lock);
		if (connections->writers_waiting == 0 && connections->write_locked == 0) {
			connections->readers++;
			pass = 1;
		}
		pthread_mutex_unlock(&connections->lock);
	}

	out:
	return ret;
}

int __rrr_mqtt_connection_collection_read_unlock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}
	if (connections->readers == 0) {
		VL_BUG("__rrr_mqtt_connection_collection_read_unlock double-called, no read lock held\n");
	}
	connections->readers--;
	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

int __rrr_mqtt_connection_collection_write_lock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	/* This blocks new readers */
	connections->writers_waiting++;

	pthread_mutex_unlock(&connections->lock);

	int pass = 0;
	while (pass != 1) {
		pthread_mutex_lock(&connections->lock);
		if (connections->readers == 0 && connections->write_locked == 0) {
			connections->write_locked = 1;
			connections->writers_waiting--;
			pass = 1;
		}
		pthread_mutex_unlock(&connections->lock);
	}

	out:
	return ret;
}

int __rrr_mqtt_connection_collection_write_unlock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}
	if (connections->write_locked != 1) {
		VL_BUG("__rrr_mqtt_connection_collection_write_unlock double-called, no write lock held\n");
	}
	connections->write_locked = 0;
	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

/* Reader which converts to write lock has priority over other writers */
int __rrr_mqtt_connection_collection_read_to_write_lock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	if (connections->readers == 0) {
		VL_BUG("__rrr_mqtt_connection_collection_read_write_to_lock called with no read lock held\n");
	}
	if (connections->write_locked != 0) {
		VL_BUG("write_locked was not 0 in __rrr_mqtt_connection_collection_read_write_to_lock\n");
	}

	/* This blocks new readers */
	connections->writers_waiting++;

	pthread_mutex_unlock(&connections->lock);

	int pass = 0;
	while (pass != 1) {
		pthread_mutex_lock(&connections->lock);
		if (connections->readers == 1) {
			connections->write_locked = 1;
			connections->readers--;
			connections->writers_waiting--;
			pass = 1;
		}
		pthread_mutex_unlock(&connections->lock);
	}

	out:
	return ret;
}

int __rrr_mqtt_connection_collection_write_to_read_lock (struct rrr_mqtt_connection_collection *connections) {
	int ret = RRR_MQTT_CONNECTION_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	if (connections->readers != 0) {
		VL_BUG("__rrr_mqtt_connection_collection_read_write_to_lock readers was not zero\n");
	}
	if (connections->write_locked != 1) {
		VL_BUG("write_locked was not 1 in __rrr_mqtt_connection_collection_write_to_read_lock\n");
	}

	connections->readers++;
	connections->write_locked = 0;

	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

static int __rrr_mqtt_connection_call_event_handler (struct rrr_mqtt_connection *connection, int event, int no_repeat) {
	int ret = RRR_MQTT_CONNECTION_OK;

	if (no_repeat == 0 || connection->last_event != event) {
		ret = connection->collection->event_handler (
				connection,
				event,
				connection->collection->event_handler_arg
		);
		connection->last_event = event;
	}

	return ret;
}

#define CALL_EVENT_HANDLER(event) \
		__rrr_mqtt_connection_call_event_handler(connection, event, 0)

#define CALL_EVENT_HANDLER_NO_REPEAT(event)	\
		__rrr_mqtt_connection_call_event_handler(connection, event, 1)

int rrr_mqtt_connection_iterator_ctx_send_disconnect (
		struct rrr_mqtt_connection *connection,
		uint8_t reason
) {
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_send_disconnect_iterator_ctx\n");
	}

	int ret = RRR_MQTT_CONNECTION_OK;

	// Check if CONNECT is not yet received
	if (connection->protocol_version == NULL) {
		goto out_nolock;
	}

	struct rrr_mqtt_p_packet_disconnect *disconnect = (struct rrr_mqtt_p_packet_disconnect *) rrr_mqtt_p_allocate (
			RRR_MQTT_P_TYPE_DISCONNECT,
			connection->protocol_version
	);
	if (disconnect == NULL) {
		VL_MSG_ERR("Could not allocate DISCONNECT packet in rrr_mqtt_connection_send_disconnect_unlocked\n");
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out_nolock;
	}

	RRR_MQTT_P_LOCK(disconnect);

	disconnect->disconnect_reason_code = reason;

	// If a CONNACK is sent, we must not sent DISCONNECT packet
	if (RRR_MQTT_CONNECTION_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		if ((ret = rrr_mqtt_connection_iterator_ctx_send_packet (
				connection,
				(struct rrr_mqtt_p_packet *) disconnect
		)) != RRR_MQTT_CONNECTION_OK) {
			ret = ret & ~RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			if (ret != RRR_MQTT_CONNECTION_OK) {
				VL_MSG_ERR("Error while queuing outbound DISCONNECT packet in rrr_mqtt_connection_send_disconnect_and_close_unlocked\n");
				goto send_disconnect_out;
			}
			ret |= RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		}

		send_disconnect_out:
		if (ret != RRR_MQTT_CONNECTION_OK) {
			goto out;
		}
	}

	out:
	RRR_MQTT_P_UNLOCK(disconnect);
	RRR_MQTT_P_DECREF(disconnect);

	out_nolock:
	// Force state transition even when sending disconnect packet fails
	if (!RRR_MQTT_CONNECTION_STATE_IS_DISCONNECT_WAIT(connection)) {
		VL_DEBUG_MSG_1 ("Sending disconnect packet failed, force state transition to DISCONNECT WAIT\n");
		connection->state_flags = RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT;
	}
	return ret;
}

static void __rrr_mqtt_connection_read_session_init (
		struct rrr_mqtt_connection_read_session *read_session
) {
	memset(read_session, '\0', sizeof(*read_session));
}

static void __rrr_mqtt_connection_read_session_destroy (
		struct rrr_mqtt_connection_read_session *read_session
) {
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf);
}

static void __rrr_mqtt_connection_close (
		struct rrr_mqtt_connection *connection
) {
	if (connection->ip_data.fd == 0) {
		VL_BUG("FD was zero in __rrr_mqtt_connection_destroy\n");
	}

	ip_close(&connection->ip_data);
	RRR_MQTT_CONNECTION_STATE_SET(connection, RRR_MQTT_CONNECTION_STATE_CLOSED);
}


static void __rrr_mqtt_connection_destroy (struct rrr_mqtt_connection *connection) {
	if (connection == NULL) {
		VL_BUG("NULL pointer in __rrr_mqtt_connection_destroy\n");
	}

	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in __rrr_mqtt_connection_destroy");
	}

	if (!RRR_MQTT_CONNECTION_STATE_IS_CLOSED(connection)) {
		__rrr_mqtt_connection_close (connection);
	}

	fifo_buffer_invalidate(&connection->receive_queue.buffer);
	fifo_buffer_invalidate(&connection->send_queue.buffer);

	__rrr_mqtt_connection_read_session_destroy(&connection->read_session);
	rrr_mqtt_parse_session_destroy(&connection->parse_session);

	if (connection->client_id != NULL) {
		free(connection->client_id);
	}

	RRR_MQTT_CONNECTION_UNLOCK(connection);
	pthread_mutex_destroy (&connection->lock);

	free(connection);
}

static void __rrr_mqtt_connection_lock_and_destroy (struct rrr_mqtt_connection *connection) {
	pthread_mutex_lock(&connection->lock);
	__rrr_mqtt_connection_destroy(connection);
}

static int __rrr_mqtt_connection_new (
		struct rrr_mqtt_connection **connection,
		const struct ip_data *ip_data,
		const struct sockaddr *remote_addr,
		uint64_t close_wait_time_usec,
		struct rrr_mqtt_connection_collection *collection
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	*connection = NULL;
	struct rrr_mqtt_connection *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = pthread_mutex_init (&res->lock, 0)) != 0) {
		VL_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_new\n");
		goto out_free;
	}
	RRR_MQTT_CONNECTION_LOCK(res);

	ret |= fifo_buffer_init_custom_free(&res->receive_queue.buffer,		rrr_mqtt_p_decref);
	ret |= fifo_buffer_init_custom_free(&res->send_queue.buffer,		rrr_mqtt_p_decref);

	if (ret != 0) {
		VL_MSG_ERR("Could not initialize buffers in __rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out_destroy_mutex;
	}

	res->ip_data = *ip_data;
	res->connect_time = res->last_seen_time = time_get_64();
	res->close_wait_time_usec = close_wait_time_usec;
	res->collection = collection;

	__rrr_mqtt_connection_read_session_init(&res->read_session);
	rrr_mqtt_parse_session_init(&res->parse_session);

	switch (remote_addr->sa_family) {
		case AF_INET: {
			res->type = RRR_MQTT_CONNECTION_TYPE_IPV4;
			res->remote_in = *((const struct sockaddr_in *) remote_addr);
			inet_ntop(AF_INET, &res->remote_in.sin_addr, res->ip, sizeof(res->ip));
			break;
		}
		case AF_INET6: {
			res->type = RRR_MQTT_CONNECTION_TYPE_IPV6;
			res->remote_in6 = *((const struct sockaddr_in6 *) remote_addr);
			inet_ntop(AF_INET6, &res->remote_in6.sin6_addr, res->ip, sizeof(res->ip));
			break;
		}
		default: {
			VL_BUG("Received non INET/INET6 sockaddr struct in __rrr_mqtt_connection_new\n");
		}
	}

	*connection = res;
	RRR_MQTT_CONNECTION_UNLOCK(res);

	goto out;

	out_destroy_mutex:
		RRR_MQTT_CONNECTION_UNLOCK(res);
		pthread_mutex_destroy(&res->lock);

	out_free:
		free(res);

	out:
		return ret;
}

void rrr_mqtt_connection_collection_destroy (struct rrr_mqtt_connection_collection *connections) {
	if (connections == NULL) {
		return;
	}

	pthread_mutex_lock (&connections->lock);
	if (connections->readers != 0 || connections->write_locked != 0 || connections->writers_waiting != 0) {
		VL_BUG("rrr_mqtt_connection_collection_destroy called while users were active\n");
	}
	pthread_mutex_unlock (&connections->lock);

	RRR_LINKED_LIST_DESTROY(
			connections,
			struct rrr_mqtt_connection,
			__rrr_mqtt_connection_lock_and_destroy(node)
	);

	connections->invalid = 1;

	pthread_mutex_destroy (&connections->lock);
}

int rrr_mqtt_connection_collection_init (
		struct rrr_mqtt_connection_collection *connections,
		int max_connections,
		int (*event_handler)(struct rrr_mqtt_connection *connection, int event, void *arg),
		void *event_handler_arg
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	memset (connections, '\0', sizeof(*connections));

	connections->invalid = 1;
	connections->writers_waiting = 0;
	connections->readers = 0;
	connections->write_locked = 0;
	connections->event_handler = event_handler;
	connections->event_handler_arg = event_handler_arg;
	connections->max = max_connections;

	if ((ret = pthread_mutex_init (&connections->lock, 0)) != 0) {
		VL_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_collection_new\n");
		goto out;
	}

	out:
	if (ret != 0) {
		rrr_mqtt_connection_collection_destroy(connections);
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
	}
	else {
		connections->invalid = 0;
	}

	return ret;
}

int rrr_mqtt_connection_collection_new_connection (
		struct rrr_mqtt_connection **connection,
		struct rrr_mqtt_connection_collection *connections,
		const struct ip_data *ip_data,
		const struct sockaddr *remote_addr,
		uint64_t close_wait_time_usec
) {
	int ret = RRR_MQTT_CONNECTION_OK;
	struct rrr_mqtt_connection *res = NULL;

	*connection = NULL;

	if (connections->invalid == 1) {
		VL_BUG("rrr_mqtt_connection_collection_new_connection called with invalid set to 1\n");
	}

	if (ip_data->fd < 1) {
		VL_BUG("FD was < 1 in rrr_mqtt_connection_collection_new_connection\n");
	}

	if (connections->node_count >= connections->max) {
		VL_MSG_ERR("Max number of connections (%i) reached in rrr_mqtt_connection_collection_new_connection\n",
				connections->max);
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_nolock;
	}

	if ((ret = __rrr_mqtt_connection_new (
			&res,
			ip_data,
			remote_addr,
			close_wait_time_usec,
			connections
	)) != RRR_MQTT_CONNECTION_OK) {
		VL_MSG_ERR("Could not create new connection in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	if ((ret = __rrr_mqtt_connection_collection_write_lock(connections)) != RRR_MQTT_CONNECTION_OK) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	RRR_LINKED_LIST_PUSH(connections, res);

	if ((ret = __rrr_mqtt_connection_collection_write_unlock(connections)) != RRR_MQTT_CONNECTION_OK) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	*connection = res;

	out_nolock:
	return ret;
}

int rrr_mqtt_connection_collection_iterate_reenter_read_to_write (
		struct rrr_mqtt_connection_collection *connections,
		int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_CONNECTION_OK;
	int callback_ret = 0;

	if ((ret = __rrr_mqtt_connection_collection_read_to_write_lock(connections)) != 0) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		goto out;
	}

	RRR_LINKED_LIST_ITERATE_BEGIN(connections, struct rrr_mqtt_connection);
		int ret_tmp = callback(node, callback_arg);
		if (ret_tmp != RRR_MQTT_CONNECTION_OK) {
			if ((ret_tmp & RRR_MQTT_CONNECTION_DESTROY_CONNECTION) != 0) {
				VL_BUG("Destroy connection flag not allowed in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
			}
			if ((ret_tmp & RRR_MQTT_CONNECTION_INTERNAL_ERROR) != 0) {
				VL_MSG_ERR("Internal error returned from callback in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
				callback_ret |= ret_tmp;
				break;
			}
			if ((ret_tmp & RRR_MQTT_CONNECTION_ITERATE_STOP) != 0) {
				callback_ret |= ret_tmp;
				break;
			}

			VL_MSG_ERR("Soft error returned from callback in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		}

	RRR_LINKED_LIST_ITERATE_END();

	if ((ret = __rrr_mqtt_connection_collection_write_to_read_lock(connections)) != 0) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		goto out;
	}

	out:
	return (ret | callback_ret);
}

static int __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy (
		struct rrr_mqtt_connection *connection
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	RRR_MQTT_CONNECTION_LOCK(connection);

	if (RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED(connection)) {
		VL_BUG("Connection state was already DISCONNECTED in __rrr_mqtt_connection_collection_in_iterator_destroy_connection\n");
	}

	// Upon some errors, connection state will not yet have transitioned into DISCONNECT WAIT.
	if (!RRR_MQTT_CONNECTION_STATE_IS_DISCONNECT_WAIT(connection)) {
		ret = rrr_mqtt_connection_iterator_ctx_send_disconnect(connection, connection->disconnect_reason_v5);
		if ((ret & RRR_MQTT_CONNECTION_INTERNAL_ERROR) != 0) {
			VL_MSG_ERR("Internal error sending disconnect packet in __rrr_mqtt_connection_collection_in_iterator_destroy_connection\n");
			goto out_unlock;
		}
		// Ignore soft errors when sending DISCONNECT packet here.
		ret = 0;
	}

	if (connection->close_wait_time_usec > 0) {
		uint64_t time_now = time_get_64();
		if (connection->close_wait_start == 0) {
			connection->close_wait_start = time_now;
			VL_DEBUG_MSG_1("Destroying connection in __rrr_mqtt_connection_collection_in_iterator_destroy_connection, starting timer\n");
		}
		if (time_now - connection->close_wait_start < connection->close_wait_time_usec) {
/*			printf ("Connection is not to be closed closed yet, waiting %" PRIu64 " usecs\n",
					(*cur)->close_wait_time_usec - (time_now - (*cur)->close_wait_start));*/
			ret = RRR_LINKED_LIST_DIDNT_DESTROY;
			goto out_unlock;
		}
		VL_DEBUG_MSG_1("Destroying connection in __rrr_mqtt_connection_collection_in_iterator_destroy_connection, timer done\n");
	}

	// Clear DESTROY flag, it is normal for the event handler to return this upon disconnect notification
	if ((ret = (CALL_EVENT_HANDLER_NO_REPEAT(RRR_MQTT_CONNECTION_EVENT_DISCONNECT) & ~RRR_MQTT_CONNECTION_DESTROY_CONNECTION)) != RRR_MQTT_CONNECTION_OK) {
		VL_MSG_ERR("Error from event handler in rrr_mqtt_connection_iterator_ctx_disconnect, return was %i. ", ret);
		if ((ret & RRR_MQTT_CONNECTION_INTERNAL_ERROR) != 0) {
			VL_MSG_ERR("Error was critical.\n");
			goto out_unlock;
		}
		VL_MSG_ERR("Error was non-critical, proceeding with destroy.\n");
		ret = RRR_MQTT_CONNECTION_OK;
	}

	__rrr_mqtt_connection_destroy(connection);
	connection = NULL;

	out_unlock:
	if (connection != NULL) {
		RRR_MQTT_CONNECTION_UNLOCK(connection);
	}

	return ret;
}

int rrr_mqtt_connection_collection_iterate (
	struct rrr_mqtt_connection_collection *connections,
	int (*callback)(struct rrr_mqtt_connection *connection, void *callback_arg),
	void *callback_arg
) {
	int ret = 0;
	int callback_ret = 0;

	if ((ret = __rrr_mqtt_connection_collection_read_lock(connections)) != 0) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate\n");
		goto out;
	}

	RRR_LINKED_LIST_ITERATE_BEGIN(connections, struct rrr_mqtt_connection);
		int ret_tmp = callback(node, callback_arg);
		if (ret_tmp != RRR_MQTT_CONNECTION_OK) {
			if ((ret_tmp & RRR_MQTT_CONNECTION_SOFT_ERROR) != 0) {
				VL_MSG_ERR("Soft error returned from callback in rrr_mqtt_connection_collection_iterate\n");
				callback_ret |= RRR_MQTT_CONNECTION_SOFT_ERROR;
				ret_tmp = ret_tmp & ~RRR_MQTT_CONNECTION_SOFT_ERROR;

				// Always destroy connection upon soft error and set non-zero
				// reason if not already set
				if (node->disconnect_reason_v5 == 0) {
					node->disconnect_reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
				}
				ret_tmp |= RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			}

			if ((ret_tmp & RRR_MQTT_CONNECTION_DESTROY_CONNECTION) != 0) {
//				VL_DEBUG_MSG_1("Destroying connection in rrr_mqtt_connection_collection_iterate\n");
				RRR_LINKED_LIST_SET_DESTROY();
				ret_tmp = ret_tmp & ~RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			}

			if ((ret_tmp & RRR_MQTT_CONNECTION_BUSY) != 0) {
				ret_tmp = ret_tmp & ~RRR_MQTT_CONNECTION_BUSY;
			}

			if ((ret_tmp & RRR_MQTT_CONNECTION_ITERATE_STOP) != 0) {
				callback_ret |= RRR_MQTT_CONNECTION_ITERATE_STOP;
				ret_tmp = ret_tmp & ~RRR_MQTT_CONNECTION_ITERATE_STOP;
			}

			if (ret_tmp != 0) {
				VL_MSG_ERR("Internal error returned from callback in rrr_mqtt_connection_collection_iterate return was %i\n", ret_tmp);
				callback_ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
				break;
			}

			if ((callback_ret & RRR_MQTT_CONNECTION_ITERATE_STOP) != 0) {
				break;
			}
		}

#define LOCK_ERR																									\
			VL_MSG_ERR("Lock error in __rrr_mqtt_connection_collection_in_iterator_destroy_connection\n");			\
			ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR; \
			goto out

#define DESTROY_ERR \
			VL_MSG_ERR("Internal error while destroying connection in rrr_mqtt_connection_collection_iterate\n");	\
			callback_ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;														\
			break

	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY_WRAP_LOCK (
			connections,
			__rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy(node),
			DESTROY_ERR,
			ret = __rrr_mqtt_connection_collection_read_to_write_lock(connections),
			ret = __rrr_mqtt_connection_collection_write_to_read_lock(connections),
			LOCK_ERR
	);

	if ((ret = __rrr_mqtt_connection_collection_read_unlock(connections)) != 0) {
		VL_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate\n");
		goto out;
	}

	out:
	return (ret | callback_ret);
}

struct connection_with_iterator_ctx_do_callback_data {
	struct rrr_mqtt_connection *connection;
	struct rrr_mqtt_p_packet *packet;
	int (*callback)(struct rrr_mqtt_connection *connection, struct rrr_mqtt_p_packet *packet);
	int connection_found;
};

static int __rrr_mqtt_connection_with_iterator_ctx_do_callback (struct rrr_mqtt_connection *connection, void *callback_arg) {
	int ret = RRR_MQTT_CONNECTION_OK;

	struct connection_with_iterator_ctx_do_callback_data *callback_data = callback_arg;

	if (connection == callback_data->connection) {
		callback_data->connection_found = 1;
		return callback_data->callback(connection, callback_data->packet);
	}

	return ret;
}

int rrr_mqtt_connection_with_iterator_ctx_do (
		struct rrr_mqtt_connection_collection *connections,
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet,
		int (*callback)(struct rrr_mqtt_connection *connection, struct rrr_mqtt_p_packet *packet)
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	struct connection_with_iterator_ctx_do_callback_data callback_data = {
			connection,
			packet,
			callback,
			0
	};

	ret = rrr_mqtt_connection_collection_iterate (
			connections,
			__rrr_mqtt_connection_with_iterator_ctx_do_callback,
			&callback_data
	);

	if (callback_data.connection_found != 1) {
		VL_BUG("Connection not found in rrr_mqtt_connection_with_iterator_ctx_do\n");
	}

	return ret;
}

void __rrr_mqtt_connection_update_last_seen (struct rrr_mqtt_connection *connection) {
	connection->last_seen_time = time_get_64();
}

int rrr_mqtt_connection_iterator_ctx_read (
		struct rrr_mqtt_connection *connection,
		int read_step_max_size
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	/* There can be multiple read threads, make sure we do not block */
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_nolock;
	}

	struct rrr_mqtt_connection_read_session *read_session = &connection->read_session;

	if (connection->read_complete == 1) {
		if (read_session->rx_buf_wpos != read_session->target_size) {
			VL_BUG("packet complete was 1 but read size was not target size in rrr_mqtt_connection_read\n");
		}
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_unlock;
	}

	if (read_session->rx_buf_wpos > read_session->target_size && read_session->target_size > 0) {
		VL_MSG_ERR("Invalid message: Actual size of message exceeds stated size in rrr_mqtt_connection_read %li > %li (when starting read tick)\n",
				read_session->rx_buf_wpos, read_session->target_size);
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR;
		goto out_unlock;
	}

	struct pollfd pollfd = { connection->ip_data.fd, POLLIN, 0 };
	ssize_t bytes = 0;
	ssize_t items = 0;
	int bytes_int = 0;

	poll_retry:

	items = poll(&pollfd, 1, 0);
	if (items == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = RRR_MQTT_CONNECTION_BUSY;
			goto out_unlock;
		}
		else if (errno == EINTR) {
			goto poll_retry;
		}
		VL_MSG_ERR("Poll error in rrr_mqtt_connection_read\n");
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR | RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out_unlock;
	}
	else if ((pollfd.revents & (POLLERR|POLLNVAL)) != 0) {
		VL_MSG_ERR("Poll error in rrr_mqtt_connection_read\n");
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR | RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out_unlock;
	}
	else if (items == 0) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_unlock;
	}

	if (ioctl (connection->ip_data.fd, FIONREAD, &bytes_int) != 0) {
		VL_MSG_ERR("Error from ioctl in rrr_mqtt_connection_read: %s\n", strerror(errno));
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR | RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out_unlock;
	}

	bytes = bytes_int;

	if (bytes == 0) {
		goto out_unlock;
	}

	/* Check for new read session */
	if (read_session->rx_buf == NULL) {
		if (bytes < 2) {
			VL_MSG_ERR("Received less than 2 bytes in first packet on connection\n");
			ret = RRR_MQTT_CONNECTION_SOFT_ERROR | RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			goto out_unlock;
		}
		read_session->rx_buf = malloc(bytes > read_step_max_size ? bytes : read_step_max_size);
		if (read_session->rx_buf == NULL) {
			VL_MSG_ERR("Could not allocate memory in rrr_mqtt_connection_read\n");
			ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
			goto out_unlock;
		}
		read_session->rx_buf_size = read_step_max_size;
		read_session->rx_buf_wpos = 0;
		read_session->step_size_limit = read_step_max_size;

		/* This number will change after the fixed header is parsed. The first round we can
		 * only read 2 bytes to make sure we don't read in many packets at a time. */
		read_session->target_size = 0;
	}

	/* Check for expansion of buffer */
	if (bytes + read_session->rx_buf_wpos > read_session->rx_buf_size) {
		ssize_t new_size = read_session->rx_buf_size + (bytes > read_step_max_size ? bytes : read_step_max_size);
		char *new_buf = realloc(read_session->rx_buf, new_size);
		if (new_buf == NULL) {
			VL_MSG_ERR("Could not re-allocate memory in rrr_mqtt_connection_read\n");
			ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
			goto out_unlock;
		}
		read_session->rx_buf = new_buf;
		read_session->rx_buf_size = new_size;
	}

	int is_first_read = 0;
	int to_read_bytes = 0;

	/* Make sure we do not read past the current message */
	if (read_session->target_size == 0) {
		to_read_bytes = 2;
		is_first_read = 1;
	}
	else {
		to_read_bytes = (read_session->target_size < read_session->rx_buf_size
				? read_session->target_size - read_session->rx_buf_wpos
				: read_session->rx_buf_size - read_session->rx_buf_wpos
		);
	}

	if (to_read_bytes < 0) {
		VL_BUG("to_read_bytes was < 0 in rrr_mqtt_connection_read\n");
	}

	if (connection->read_complete == 1 && to_read_bytes != 0) {
		VL_BUG("packet_complete was 1 but to_read_bytes was not zero\n");
	}

	/*
	 * When a message is completely received, we do not read any more data
	 * until somebody else has reset the receive buffer
	 */
	if (to_read_bytes == 0) {
		connection->read_complete = 1;
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_unlock;
	}

	// TODO
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	// XXX                REMOVE STRESS TEST                   XXX
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX

	/* Stress test parsers, only read X bytes at a time */
	/*if (to_read_bytes > 3) {
		to_read_bytes = 3;
	}*/

	/* Read */
	read_retry:
	bytes = read (
			connection->ip_data.fd,
			read_session->rx_buf + read_session->rx_buf_wpos,
			to_read_bytes
	);

	if (bytes == -1) {
		if (errno == EINTR) {
			goto read_retry;
		}
		VL_MSG_ERR("Error from read in rrr_mqtt_connection_read: %s\n", strerror(errno));
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out_unlock;
	}

	if (bytes == 0) {
		VL_MSG_ERR("Bytes was 0 after read in rrr_mqtt_connection_read, despite polling first\n");
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR | RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out_unlock;
	}

	read_session->rx_buf_wpos += bytes;
	read_session->step_size_limit -= bytes;

	if (read_session->rx_buf_wpos > read_session->target_size && read_session->target_size > 0) {
		VL_BUG("rx_buf_wpos was > target_size in rrr_mqtt_connection_read\n");
	}

	if (read_session->rx_buf_wpos == read_session->target_size && read_session->target_size > 0) {
		connection->read_complete = 1;
	}

	if (read_session->step_size_limit < 0) {
		ret = RRR_MQTT_CONNECTION_STEP_LIMIT;
		read_session->step_size_limit = read_step_max_size;
	}

	// In the first read, we take a sneak peak at the first byte of the remaining length
	// variable int field and read some more data if it's non-zero.
	if (is_first_read == 1) {
		const struct rrr_mqtt_p_header *header = (const struct rrr_mqtt_p_header *) read_session->rx_buf;
		// Remember to mask away first bit
		uint8_t remaining_length_first = header->length[0] & 0x7F;
		if (remaining_length_first > 0) {
			to_read_bytes = remaining_length_first;
			is_first_read = 0;
			goto read_retry;
		}
	}

	__rrr_mqtt_connection_update_last_seen (connection);

	out_unlock:
	RRR_MQTT_CONNECTION_UNLOCK(connection);

	out_nolock:
	return ret;
}

int rrr_mqtt_connection_iterator_ctx_parse (
		struct rrr_mqtt_connection *connection
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_nolock;
	}

	if (connection->read_session.rx_buf == NULL) {
		goto out_unlock;
	}

	// Read function might do realloc which means we must update our pointer
	rrr_mqtt_parse_session_update (
			&connection->parse_session,
			connection->read_session.rx_buf,
			connection->read_session.rx_buf_wpos,
			connection->protocol_version
	);

	ret = rrr_mqtt_packet_parse (&connection->parse_session);
	if (RRR_MQTT_PARSE_IS_ERR(&connection->parse_session)) {
		/* Error which was the remote's fault, close connection */
		ret = RRR_MQTT_CONNECTION_SOFT_ERROR|RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out_unlock;
	}

	if (RRR_MQTT_PARSE_FIXED_HEADER_IS_DONE(&connection->parse_session)) {
		connection->read_session.target_size = connection->parse_session.target_size;
		if (connection->read_session.rx_buf_wpos == connection->read_session.target_size) {
			connection->read_complete = 1;
		}
		else if (connection->read_session.rx_buf_wpos > connection->read_session.target_size) {
			VL_MSG_ERR("Invalid message: Actual size of message exceeds stated size in rrr_mqtt_connection_parse %li > %li (after fixed header is done)\n",
					connection->read_session.rx_buf_wpos, connection->read_session.target_size);
			ret = RRR_MQTT_CONNECTION_SOFT_ERROR;
			goto out_unlock;
		}
	}

	if (RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		if (RRR_MQTT_PARSE_STATUS_IS_MOVE_PAYLOAD_TO_PACKET(&connection->parse_session)) {
			if (connection->parse_session.packet->_assembled_data != NULL) {
				VL_BUG("assembled data was not NULL in rrr_mqtt_connection_iterator_ctx_parse while moving payload\n");
			}
			connection->parse_session.packet->_assembled_data =
					connection->read_session.rx_buf;

			connection->parse_session.packet->assembled_data_size =
					connection->parse_session.payload_pos;

			connection->parse_session.packet->payload_pointer =
					connection->parse_session.packet->_assembled_data + connection->parse_session.payload_pos;

			connection->parse_session.packet->payload_size =
					connection->read_session.rx_buf_wpos - connection->parse_session.payload_pos;

		}

		connection->parse_complete = 1;

		__rrr_mqtt_connection_read_session_destroy(&connection->read_session);
		__rrr_mqtt_connection_read_session_init(&connection->read_session);

		if ((ret = CALL_EVENT_HANDLER(RRR_MQTT_CONNECTION_EVENT_PACKET_PARSED)) != 0) {
			VL_MSG_ERR("Error from event handler in rrr_mqtt_connection_iterator_ctx_parse, return was %i\n", ret);
			goto out_unlock;
		}
	}

	out_unlock:
	RRR_MQTT_CONNECTION_UNLOCK(connection);

	out_nolock:
	return ret;
}

int rrr_mqtt_connection_iterator_ctx_check_finalize (
		struct rrr_mqtt_connection *connection
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONNECTION_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_nolock;
	}

	if (connection->read_complete == 1) {
		if (connection->parse_complete != 1) {
			VL_MSG_ERR("Reading is done for a packet but parsing did not complete. Closing connection.\n");
			ret = RRR_MQTT_CONNECTION_DESTROY_CONNECTION|RRR_MQTT_CONNECTION_SOFT_ERROR;
			goto out_unlock;
		}

		struct rrr_mqtt_p_packet *packet;
		ret = rrr_mqtt_packet_parse_finalize(&packet, &connection->parse_session);
		if (rrr_mqtt_p_get_refcount(packet) != 1) {
			VL_BUG("Refcount was not 1 while finalizing mqtt packet and adding to receive buffer\n");
		}

		fifo_buffer_write(&connection->receive_queue.buffer, (char*) packet, RRR_MQTT_P_GET_SIZE(packet));

		rrr_mqtt_parse_session_destroy(&connection->parse_session);
		rrr_mqtt_parse_session_init(&connection->parse_session);

		connection->read_complete = 0;
		connection->parse_complete = 0;
	}

	out_unlock:
		RRR_MQTT_CONNECTION_UNLOCK(connection);

	out_nolock:
		return ret;
}

int rrr_mqtt_connection_iterator_ctx_housekeeping (
		struct rrr_mqtt_connection *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out_nolock;
	}

	(void)(arg);

//	struct rrr_mqtt_data *data = arg;

	if (RRR_MQTT_CONNECTION_STATE_IS_DISCONNECT_WAIT(connection)) {
//		VL_DEBUG_MSG_1("Cleaning up connection which is to be closed\n");
		ret = RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		goto out;
	}

	if (connection->keep_alive > 0) {
		uint64_t limit = (double) connection->keep_alive * 1.5;
		limit *= 1000000;
		if (connection->last_seen_time + limit < time_get_64()) {
			VL_DEBUG_MSG_1("Keep-alive exceeded for connection\n");
			ret = RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			goto out;
		}
	}

	out:
	RRR_MQTT_CONNECTION_UNLOCK(connection);

	out_nolock:
	return ret;
}

static int __rrr_mqtt_connection_write (struct rrr_mqtt_connection *connection, const char *data, ssize_t data_size) {
	int ret = 0;
	ssize_t bytes = 0;

	retry:
	bytes = write (connection->ip_data.fd, data, data_size);
//	printf ("Write %li bytes\n", bytes);
	if (bytes != data_size) {
		if (bytes == -1) {
			if (errno == EINTR) {
				goto retry;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = RRR_MQTT_CONNECTION_BUSY;
				goto out;
			}
			VL_MSG_ERR("Error while sending packet in __rrr_mqtt_connection_write: %s\n",
					strerror(errno));
			ret = RRR_MQTT_CONNECTION_SOFT_ERROR;
		}
		else if (bytes != data_size) {
			VL_MSG_ERR("Error while sending packet in __rrr_mqtt_connection_write, only %li of %li bytes were sent\n",
					bytes, data_size);
			ret = RRR_MQTT_CONNECTION_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_mqtt_connection_iterator_ctx_send_packet (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
) {
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		VL_BUG("Packet lock was not held in rrr_mqtt_connection_iterator_ctx_send_packet\n");
	}
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_iterator_ctx_send_packet\n");
	}

	int ret = RRR_MQTT_CONNECTION_OK;
	int ret_destroy = 0;

	char *network_data = NULL;
	ssize_t network_size = 0;

	// We do not re-send packets here, that is done during housekeeping
	if (packet->last_attempt != 0) {
		goto out;
	}

	if (packet->_assembled_data == NULL) {
		int ret_tmp = RRR_MQTT_P_GET_ASSEMBLER(packet) (
				&network_data,
				&network_size,
				packet
		);

		packet->_assembled_data = network_data;
		packet->assembled_data_size = network_size;

		if (network_data == NULL) {
			VL_BUG("Assembled packet of type %s was NULL in __rrr_mqtt_connection_send_packets_callback\n",
					RRR_MQTT_P_GET_TYPE_NAME(packet));
		}
		if (network_size < 2) {
			VL_BUG("Assembled packet size of type %s was <2 in __rrr_mqtt_connection_send_packets_callback\n",
					RRR_MQTT_P_GET_TYPE_NAME(packet));
		}

		network_data = NULL;

		if ((ret_tmp & RRR_MQTT_ASSEMBLE_DESTROY_CONNECTION) != 0) {
			ret_tmp = ret_tmp & ~RRR_MQTT_ASSEMBLE_DESTROY_CONNECTION;
			ret_destroy |= RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
		}

		if (ret_tmp != RRR_MQTT_ASSEMBLE_OK) {
			VL_MSG_ERR("Error while assembling packet in __rrr_mqtt_connection_send_packets_callback\n");
			ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
			goto out;
		}
	}

	// It is possible here to actually send a packet which is not allowed in the current
	// connection state, but in that case, the program will crash after the write when updating
	// the state. It is a bug to call this function with a non-timely packet.

	if ((ret = __rrr_mqtt_connection_write (connection, packet->_assembled_data, packet->assembled_data_size)) != 0) {
		VL_MSG_ERR("Error while sending assembled data in __rrr_mqtt_connection_send_packets_callback\n");
		goto out;
	}

	if (packet->payload_pointer != NULL) {
		if (packet->payload_size == 0) {
			VL_BUG("Payload size was 0 but payload pointer was not NULL in __rrr_mqtt_connection_send_packets_callback\n");
		}
		if ((ret = __rrr_mqtt_connection_write (connection, packet->payload_pointer, packet->payload_size)) != 0) {
			VL_MSG_ERR("Error while sending payload data in __rrr_mqtt_connection_send_packets_callback\n");
			goto out;
		}
	}
	else if (packet->payload_size != 0) {
		VL_BUG("Payload pointer was NULL but payload size was not 0 in __rrr_mqtt_connection_send_packets_callback\n");
	}

	ret = rrr_mqtt_connection_iterator_ctx_update_state (
			connection,
			packet,
			RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT
	);
	if (ret != RRR_MQTT_CONNECTION_OK) {
		VL_MSG_ERR("Could not update connection state in rrr_mqtt_connection_iterator_ctx_send_packet\n");
		goto out;
	}

	packet->last_attempt = time_get_64();

	out:
	RRR_FREE_IF_NOT_NULL(network_data);
	return ret | ret_destroy;
}

struct send_packets_callback_data {
	struct rrr_mqtt_connection *connection;
};

static int __rrr_mqtt_connection_send_packets_callback (FIFO_CALLBACK_ARGS) {
	struct send_packets_callback_data *packets_callback_data = callback_data->private_data;
	struct rrr_mqtt_p_packet *packet = (struct rrr_mqtt_p_packet *) data;
	struct rrr_mqtt_connection *connection = packets_callback_data->connection;

	(void)(size);

	int ret = FIFO_OK;

	RRR_MQTT_P_LOCK(packet);

	int ret_tmp = rrr_mqtt_connection_iterator_ctx_send_packet (connection, packet);

	if (ret_tmp != RRR_MQTT_CONNECTION_OK) {
		if ((ret_tmp & RRR_MQTT_CONNECTION_SOFT_ERROR) != 0) {
			VL_MSG_ERR("Soft error while sending packet in __rrr_mqtt_connection_send_packets_callback\n");
			ret_tmp = ret_tmp & ~RRR_MQTT_CONNECTION_SOFT_ERROR;
			ret |= FIFO_CALLBACK_ERR;
		}
		if (ret_tmp != 0) {
			VL_MSG_ERR("Internal error while sending packet in __rrr_mqtt_connection_send_packets_callback\n");
			ret = FIFO_GLOBAL_ERR;
		}
		goto out;
	}

	out:
	RRR_MQTT_P_UNLOCK(packet);

	return ret;
}

int rrr_mqtt_connection_iterator_ctx_send_packets (
		struct rrr_mqtt_connection *connection
) {
	int ret = RRR_MQTT_CONNECTION_OK;

	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_iterator_ctx_send_packet\n");
	}
	if (!RRR_MQTT_CONNECTION_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		ret = RRR_MQTT_CONNECTION_BUSY;
		goto out;
	}

	struct send_packets_callback_data callback_data = { connection };
	struct fifo_callback_args fifo_callback_args = { NULL, &callback_data, 0 };

	// We use fifo_read because it only holds read-lock on the buffer. We do not immediately delete sent
	// packets, and it is also not possible while traversing with fifo_read. Sent packets are deleted
	// while doing housekeeping. We only send packets which previously has not been attempted sent.
	ret = fifo_read(&connection->send_queue.buffer, __rrr_mqtt_connection_send_packets_callback, &fifo_callback_args, 0);
	if (ret != FIFO_OK) {
		if (ret == FIFO_CALLBACK_ERR) {
			VL_MSG_ERR("Soft error while handling send queue in __rrr_mqtt_common_send_packets\n");
			ret = RRR_MQTT_CONNECTION_SOFT_ERROR|RRR_MQTT_CONNECTION_DESTROY_CONNECTION;
			goto out;
		}
		VL_MSG_ERR("Internal error while handling send queue in __rrr_mqtt_common_send_packets\n");
		ret = RRR_MQTT_CONNECTION_INTERNAL_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_mqtt_connection_iterator_ctx_queue_outbound_packet (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
) {
	if (rrr_mqtt_p_get_refcount(packet) < 2) {
		VL_BUG("Refcount for packet too small to proceed safely in rrr_mqtt_connection_queue_outbound_packet_iterator_ctx\n");
	}
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		VL_BUG("Packet lock was not held in rrr_mqtt_connection_queue_outbound_packet_iterator_ctx\n");
	}
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_queue_outbound_packet_iterator_ctx\n");
	}

	fifo_buffer_delayed_write(&connection->send_queue.buffer, (char*) packet, RRR_MQTT_P_GET_SIZE(packet));
	return RRR_MQTT_CONNECTION_OK;
}

int rrr_mqtt_connection_iterator_ctx_set_protocol_version_and_keep_alive (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet
) {
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		VL_BUG("Packet lock was not held in rrr_mqtt_connection_iterator_ctx_set_protocol_version_and_keep_alive\n");
	}
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_set_protocol_version_iterator_ctx\n");
	}

	if (RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_CONNECT) {
		VL_BUG("Tried to set protocol version with non-CONNECT packet of type %s in rrr_mqtt_connection_set_protocol_version_iterator_ctx\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet));
	}
	if (connection->protocol_version != NULL) {
		VL_BUG("Tried to set protocol version two times in rrr_mqtt_connection_set_protocol_version_iterator_ctx\n");
	}

	struct rrr_mqtt_p_packet_connect *connect = (struct rrr_mqtt_p_packet_connect *) packet;

	connection->protocol_version = connect->protocol_version;
	connection->keep_alive = connect->keep_alive;

	return RRR_MQTT_CONNECTION_OK;
}

int rrr_mqtt_connection_iterator_ctx_update_state (
		struct rrr_mqtt_connection *connection,
		struct rrr_mqtt_p_packet *packet,
		int direction
) {
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		VL_BUG("Packet lock was not held in rrr_mqtt_connection_update_state_iterator_ctx\n");
	}
	if (RRR_MQTT_CONNECTION_TRYLOCK(connection) == 0) {
		VL_BUG("Connection lock was not held in rrr_mqtt_connection_update_state_iterator_ctx\n");
	}

	uint8_t packet_type = RRR_MQTT_P_GET_TYPE(packet);

	// Shortcut for normal operation. It is not our job to check
	// if we are allowed to send the normal packets, other functions
	// do that.
	if (	packet_type > RRR_MQTT_P_TYPE_CONNACK &&
			packet_type < RRR_MQTT_P_TYPE_DISCONNECT
	) {
		return RRR_MQTT_CONNECTION_OK;
	}

	if (packet_type == RRR_MQTT_P_TYPE_CONNECT) {
		if (!RRR_MQTT_CONNECTION_STATE_CONNECT_ALLOWED(connection)) {
			if (direction == RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT) {
				VL_BUG("This CONNECT packet was outbound, it's a bug\n");
			}
			VL_MSG_ERR("Tried to process a CONNECT while not allowed\n");
			return RRR_MQTT_CONNECTION_SOFT_ERROR;
		}

		RRR_MQTT_CONNECTION_STATE_SET (connection,
				direction == RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT
					? RRR_MQTT_CONNECTION_STATE_SEND_ANY_ALLOWED | RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_ALLOWED
					: RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_ALLOWED
		);
	}
	else if (packet_type == RRR_MQTT_P_TYPE_CONNACK) {
		if (direction == RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT) {
			if (!RRR_MQTT_CONNECTION_STATE_SEND_CONNACK_IS_ALLOWED(connection)) {
				VL_BUG("Tried to send CONNACK while not allowed\n");
			}
		}
		else if (!RRR_MQTT_CONNECTION_STATE_RECEIVE_CONNACK_IS_ALLOWED(connection)) {
			VL_MSG_ERR("Received CONNACK while not allowed\n");
			return RRR_MQTT_CONNECTION_SOFT_ERROR;
		}

		RRR_MQTT_CONNECTION_STATE_SET (connection,
				RRR_MQTT_P_CONNACK_GET_REASON_V5(packet) == RRR_MQTT_P_5_REASON_OK
					? RRR_MQTT_CONNECTION_STATE_SEND_ANY_ALLOWED | RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_ALLOWED
					: RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT
		);
	}
	else if (packet_type == RRR_MQTT_P_TYPE_DISCONNECT) {
		if (direction == RRR_MQTT_CONNECTION_UPDATE_STATE_DIRECTION_OUT) {
			if (!RRR_MQTT_CONNECTION_STATE_SEND_ANY_IS_ALLOWED(connection)) {
				VL_BUG("Tried to send DISCONNECT while not allowed");
			}
		}
		else if (!RRR_MQTT_CONNECTION_STATE_RECEIVE_ANY_IS_ALLOWED(connection)) {
			VL_MSG_ERR("Received DISCONNECT while not allowed\n");
			return RRR_MQTT_CONNECTION_SOFT_ERROR;
		}
		RRR_MQTT_CONNECTION_STATE_SET (connection, RRR_MQTT_CONNECTION_STATE_DISCONNECT_WAIT);
	}
	else {
		VL_BUG("Unknown control packet %u in rrr_mqtt_connection_update_state_iterator_ctx\n", packet_type);
	}

	return RRR_MQTT_CONNECTION_OK;
}
