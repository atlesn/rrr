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

int __rrr_mqtt_connection_collection_read_lock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
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

int __rrr_mqtt_connection_collection_read_unlock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}
	if (connections->readers == 0) {
		RRR_BUG("__rrr_mqtt_connection_collection_read_unlock double-called, no read lock held\n");
	}
	connections->readers--;
	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

int __rrr_mqtt_connection_collection_write_lock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
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

int __rrr_mqtt_connection_collection_write_unlock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}
	if (connections->write_locked != 1) {
		RRR_BUG("__rrr_mqtt_connection_collection_write_unlock double-called, no write lock held\n");
	}
	connections->write_locked = 0;
	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

/* Reader which converts to write lock has priority over other writers */
int __rrr_mqtt_connection_collection_read_to_write_lock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	if (connections->readers == 0) {
		RRR_BUG("__rrr_mqtt_connection_collection_read_write_to_lock called with no read lock held\n");
	}
	if (connections->write_locked != 0) {
		RRR_BUG("write_locked was not 0 in __rrr_mqtt_connection_collection_read_write_to_lock\n");
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

int __rrr_mqtt_connection_collection_write_to_read_lock (struct rrr_mqtt_conn_collection *connections) {
	int ret = RRR_MQTT_CONN_OK;

	pthread_mutex_lock(&connections->lock);
	if (connections->invalid != 0) {
		pthread_mutex_unlock(&connections->lock);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	if (connections->readers != 0) {
		RRR_BUG("__rrr_mqtt_connection_collection_read_write_to_lock readers was not zero\n");
	}
	if (connections->write_locked != 1) {
		RRR_BUG("write_locked was not 1 in __rrr_mqtt_connection_collection_write_to_read_lock\n");
	}

	connections->readers++;
	connections->write_locked = 0;

	pthread_mutex_unlock(&connections->lock);

	out:
	return ret;
}

static int __rrr_mqtt_connection_call_event_handler (struct rrr_mqtt_conn *connection, int event, int no_repeat, void *arg) {
	int ret = RRR_MQTT_CONN_OK;

	if (no_repeat == 0 || connection->last_event != event) {
		ret = connection->collection->event_handler (
				connection,
				event,
				connection->collection->event_handler_static_arg,
				arg
		);
		connection->last_event = event;
	}

	return ret;
}

#define CALL_EVENT_HANDLER_ARG(event, arg) \
		__rrr_mqtt_connection_call_event_handler(connection, event, 0, arg)

#define CALL_EVENT_HANDLER(event) \
		__rrr_mqtt_connection_call_event_handler(connection, event, 0, NULL)

#define CALL_EVENT_HANDLER_NO_REPEAT(event)	\
		__rrr_mqtt_connection_call_event_handler(connection, event, 1, NULL)

int rrr_mqtt_conn_iterator_ctx_send_disconnect (
		struct rrr_mqtt_conn *connection
) {
	if (RRR_MQTT_CONN_TRYLOCK(connection) == 0) {
		RRR_BUG("Connection lock was not held in rrr_mqtt_conn_iterator_ctx_send_disconnect\n");
	}

	int ret = RRR_MQTT_CONN_OK;

	// Check if CONNECT is not yet received
	if (connection->protocol_version == NULL) {
		goto out_nolock;
	}

	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) rrr_mqtt_p_allocate (
			RRR_MQTT_P_TYPE_DISCONNECT,
			connection->protocol_version
	);
	if (disconnect == NULL) {
		RRR_MSG_ERR("Could not allocate DISCONNECT packet in rrr_mqtt_conn_iterator_ctx_send_disconnect\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out_nolock;
	}

	RRR_MQTT_P_LOCK(disconnect);

	disconnect->reason_v5 = connection->disconnect_reason_v5_;

	// If a CONNACK is sent, we must not sent DISCONNECT packet
	if (RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet (
				connection,
				(struct rrr_mqtt_p *) disconnect
		)) != RRR_MQTT_CONN_OK) {
			ret = ret & ~RRR_MQTT_CONN_DESTROY_CONNECTION;
			if (ret != RRR_MQTT_CONN_OK) {
				RRR_MSG_ERR("Error while queuing outbound DISCONNECT packet in rrr_mqtt_conn_iterator_ctx_send_disconnect return was %i\n",
						ret);
				goto send_disconnect_out;
			}
			ret |= RRR_MQTT_CONN_DESTROY_CONNECTION;
		}

		send_disconnect_out:
		if (ret != RRR_MQTT_CONN_OK) {
			goto out;
		}
	}

	out:
	RRR_MQTT_P_UNLOCK(disconnect);
	RRR_MQTT_P_DECREF(disconnect);

	out_nolock:
	// Force state transition even when sending disconnect packet fails
	if (!RRR_MQTT_CONN_STATE_IS_DISCONNECT_WAIT(connection)) {
		RRR_DBG_1 ("Sending disconnect packet failed, force state transition to DISCONNECT WAIT\n");
		connection->state_flags = RRR_MQTT_CONN_STATE_DISCONNECT_WAIT;
	}
	return ret;
}

static void __rrr_mqtt_connection_read_session_init (
		struct rrr_mqtt_conn_read_session *read_session
) {
	memset(read_session, '\0', sizeof(*read_session));
}

static void __rrr_mqtt_connection_read_session_destroy (
		struct rrr_mqtt_conn_read_session *read_session
) {
	RRR_FREE_IF_NOT_NULL(read_session->rx_buf);
}

static void __rrr_mqtt_connection_close (
		struct rrr_mqtt_conn *connection
) {
	if (connection->ip_data.fd == 0) {
		RRR_BUG("FD was zero in __rrr_mqtt_connection_destroy\n");
	}

	rrr_ip_close(&connection->ip_data);
	RRR_MQTT_CONN_STATE_SET(connection, RRR_MQTT_CONN_STATE_CLOSED);
}


static void __rrr_mqtt_connection_destroy (struct rrr_mqtt_conn *connection) {
	if (connection == NULL) {
		RRR_BUG("NULL pointer in __rrr_mqtt_connection_destroy\n");
	}

	if (RRR_MQTT_CONN_TRYLOCK(connection) == 0) {
		RRR_BUG("Connection lock was not held in __rrr_mqtt_connection_destroy");
	}

	if (!RRR_MQTT_CONN_STATE_IS_CLOSED(connection)) {
		__rrr_mqtt_connection_close (connection);
	}

	rrr_fifo_buffer_invalidate(&connection->receive_queue.buffer);

	__rrr_mqtt_connection_read_session_destroy(&connection->read_session);
	rrr_mqtt_parse_session_destroy(&connection->parse_session);

	if (connection->client_id != NULL) {
		free(connection->client_id);
	}

	RRR_MQTT_CONN_UNLOCK(connection);
	pthread_mutex_destroy (&connection->lock);

	free(connection);
}

static void __rrr_mqtt_connection_lock_and_destroy (struct rrr_mqtt_conn *connection) {
	RRR_MQTT_CONN_LOCK(connection);
	__rrr_mqtt_connection_destroy(connection);
}

static int __rrr_mqtt_connection_new (
		struct rrr_mqtt_conn **connection,
		const struct rrr_ip_data *ip_data,
		const struct sockaddr *remote_addr,
		uint64_t close_wait_time_usec,
		struct rrr_mqtt_conn_collection *collection
) {
	int ret = RRR_MQTT_CONN_OK;

	*connection = NULL;
	struct rrr_mqtt_conn *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = pthread_mutex_init (&res->lock, 0)) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_new\n");
		goto out_free;
	}
	RRR_MQTT_CONN_LOCK(res);

	ret |= rrr_fifo_buffer_init_custom_free(&res->receive_queue.buffer,		rrr_mqtt_p_standardized_decref);
//	ret |= fifo_buffer_init_custom_free(&res->send_queue.buffer,		rrr_mqtt_p_standardized_decref);

	if (ret != 0) {
		RRR_MSG_ERR("Could not initialize buffers in __rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
		goto out_destroy_mutex;
	}

	res->ip_data = *ip_data;
	res->connect_time = res->last_seen_time = rrr_time_get_64();
	res->close_wait_time_usec = close_wait_time_usec;
	res->collection = collection;

	__rrr_mqtt_connection_read_session_init(&res->read_session);
	rrr_mqtt_parse_session_init(&res->parse_session);

	switch (remote_addr->sa_family) {
		case AF_INET: {
			res->type = RRR_MQTT_CONN_TYPE_IPV4;
			res->remote_in = *((const struct sockaddr_in *) remote_addr);
			inet_ntop(AF_INET, &res->remote_in.sin_addr, res->ip, sizeof(res->ip));
			break;
		}
		case AF_INET6: {
			res->type = RRR_MQTT_CONN_TYPE_IPV6;
			res->remote_in6 = *((const struct sockaddr_in6 *) remote_addr);
			inet_ntop(AF_INET6, &res->remote_in6.sin6_addr, res->ip, sizeof(res->ip));
			break;
		}
		default: {
			RRR_BUG("Received non INET/INET6 sockaddr struct in __rrr_mqtt_connection_new\n");
		}
	}

	*connection = res;
	RRR_MQTT_CONN_UNLOCK(res);

	goto out;

	out_destroy_mutex:
		RRR_MQTT_CONN_UNLOCK(res);
		pthread_mutex_destroy(&res->lock);

	out_free:
		free(res);

	out:
		return ret;
}

void rrr_mqtt_conn_collection_destroy (struct rrr_mqtt_conn_collection *connections) {
	if (connections == NULL) {
		return;
	}

	pthread_mutex_lock (&connections->lock);
	if (connections->readers != 0 || connections->write_locked != 0 || connections->writers_waiting != 0) {
		RRR_BUG("rrr_mqtt_connection_collection_destroy called while users were active\n");
	}
	pthread_mutex_unlock (&connections->lock);

	RRR_LL_DESTROY(
			connections,
			struct rrr_mqtt_conn,
			__rrr_mqtt_connection_lock_and_destroy(node)
	);

	connections->invalid = 1;

	pthread_mutex_destroy (&connections->lock);
}

int rrr_mqtt_conn_collection_init (
		struct rrr_mqtt_conn_collection *connections,
		unsigned int max_connections,
		uint64_t close_wait_time_usec,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_arg
) {
	int ret = RRR_MQTT_CONN_OK;

	memset (connections, '\0', sizeof(*connections));

	connections->invalid = 1;
	connections->writers_waiting = 0;
	connections->readers = 0;
	connections->write_locked = 0;
	connections->event_handler = event_handler;
	connections->event_handler_static_arg = event_handler_arg;
	connections->max = max_connections;
	connections->close_wait_time_usec = close_wait_time_usec;

	if ((ret = pthread_mutex_init (&connections->lock, 0)) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_collection_new\n");
		goto out;
	}

	out:
	if (ret != 0) {
		rrr_mqtt_conn_collection_destroy(connections);
		ret = RRR_MQTT_CONN_INTERNAL_ERROR;
	}
	else {
		connections->invalid = 0;
	}

	return ret;
}

static int __rrr_mqtt_conn_collection_new_connection (
		struct rrr_mqtt_conn **connection,
		struct rrr_mqtt_conn_collection *connections,
		const struct rrr_ip_accept_data *accept_data
) {
	int ret = RRR_MQTT_CONN_OK;
	struct rrr_mqtt_conn *res = NULL;

	*connection = NULL;

	if (connections->invalid == 1) {
		RRR_BUG("rrr_mqtt_connection_collection_new_connection called with invalid set to 1\n");
	}

	if (accept_data->ip_data.fd < 1) {
		RRR_BUG("FD was < 1 in rrr_mqtt_connection_collection_new_connection\n");
	}

	if (connections->node_count >= connections->max) {
		RRR_MSG_ERR("Max number of connections (%li) reached in rrr_mqtt_connection_collection_new_connection\n",
				connections->max);
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	if ((ret = __rrr_mqtt_connection_new (
			&res,
			&accept_data->ip_data,
			&accept_data->addr,
			connections->close_wait_time_usec,
			connections
	)) != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Could not create new connection in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	if ((ret = __rrr_mqtt_connection_collection_write_lock(connections)) != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	RRR_LL_PUSH(connections, res);

	if ((ret = __rrr_mqtt_connection_collection_write_unlock(connections)) != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	*connection = res;

	out_nolock:
	return ret;
}

int rrr_mqtt_conn_collection_connect (
		struct rrr_mqtt_conn **connection,
		struct rrr_mqtt_conn_collection *connections,
		unsigned int port,
		const char *host
) {
	int ret = RRR_MQTT_CONN_OK;

	*connection = NULL;
	struct rrr_ip_accept_data *accept_data = NULL;

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6 (&accept_data, port, host) != 0) {
		RRR_MSG_ERR("Could not connect to mqtt server '%s'\n", host);
		ret = 1;
		goto out;
	}

	if (accept_data != NULL) {
		if ((ret = __rrr_mqtt_conn_collection_new_connection(connection, connections, accept_data)) != RRR_MQTT_CONN_OK) {
			goto out_disconnect;
		}
	}

	goto out;
	out_disconnect:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

int rrr_mqtt_conn_collection_accept (
		struct rrr_mqtt_conn **connection,
		struct rrr_mqtt_conn_collection *connections,
		struct rrr_ip_data *ip,
		const char *creator
) {
	int ret = RRR_MQTT_CONN_OK;

	*connection = NULL;
	struct rrr_ip_accept_data *accept_data = NULL;

	if ((ret = rrr_ip_accept(&accept_data, ip, creator, 0)) != 0) {
		RRR_MSG_ERR("Error from ip_accept in rrr_mqtt_conn_collection_accept\n");
		goto out;
	}

	if (accept_data != NULL) {
		if ((ret = __rrr_mqtt_conn_collection_new_connection(connection, connections, accept_data)) != RRR_MQTT_CONN_OK) {
			goto out_disconnect;
		}
	}

	goto out;
	out_disconnect:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

int rrr_mqtt_conn_collection_iterate_reenter_read_to_write (
		struct rrr_mqtt_conn_collection *connections,
		int (*callback)(struct rrr_mqtt_conn *connection, void *callback_arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_CONN_OK;
	int callback_ret = 0;

	if ((ret = __rrr_mqtt_connection_collection_read_to_write_lock(connections)) != 0) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(connections, struct rrr_mqtt_conn);
		int ret_tmp = callback(node, callback_arg);
		if (ret_tmp != RRR_MQTT_CONN_OK) {
			if ((ret_tmp & RRR_MQTT_CONN_DESTROY_CONNECTION) != 0) {
				RRR_BUG("Destroy connection flag not allowed in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
			}
			if ((ret_tmp & RRR_MQTT_CONN_INTERNAL_ERROR) != 0) {
				RRR_MSG_ERR("Internal error returned from callback in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
				callback_ret |= ret_tmp;
				RRR_LL_ITERATE_BREAK();
			}
			if ((ret_tmp & RRR_MQTT_CONN_ITERATE_STOP) != 0) {
				callback_ret |= ret_tmp;
				RRR_LL_ITERATE_BREAK();
			}

			RRR_MSG_ERR("Soft error returned from callback in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		}
	RRR_LL_ITERATE_END(connections);

	if ((ret = __rrr_mqtt_connection_collection_write_to_read_lock(connections)) != 0) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate_reenter_read_to_write\n");
		goto out;
	}

	out:
	return (ret | callback_ret);
}

static int __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy (
		struct rrr_mqtt_conn *connection
) {
	int ret = RRR_MQTT_CONN_OK;

	RRR_MQTT_CONN_LOCK(connection);

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED(connection)) {
		RRR_BUG("Connection state was already DISCONNECTED in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy\n");
	}

	// Upon some errors, connection state will not yet have transitioned into DISCONNECT WAIT.
	if (!RRR_MQTT_CONN_STATE_IS_DISCONNECT_WAIT(connection)) {
		ret = rrr_mqtt_conn_iterator_ctx_send_disconnect(connection);
		if ((ret & RRR_MQTT_CONN_INTERNAL_ERROR) != 0) {
			RRR_MSG_ERR("Internal error sending disconnect packet in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy\n");
			goto out_unlock;
		}
		// Ignore soft errors when sending DISCONNECT packet here.
		ret = 0;
	}

	if (connection->close_wait_time_usec > 0) {
		uint64_t time_now = rrr_time_get_64();
		if (connection->close_wait_start == 0) {
			connection->close_wait_start = time_now;
			RRR_DBG_1("Destroying connection in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy reason %u, starting timer\n",
					connection->disconnect_reason_v5_);
		}
		if (time_now - connection->close_wait_start < connection->close_wait_time_usec) {
/*			printf ("Connection is not to be closed closed yet, waiting %" PRIu64 " usecs\n",
					(*cur)->close_wait_time_usec - (time_now - (*cur)->close_wait_start));*/
			ret = RRR_LL_DIDNT_DESTROY;
			goto out_unlock;
		}
		RRR_DBG_1("Destroying connection in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy reason %u, timer done\n",
				connection->disconnect_reason_v5_);
	}

	// Clear DESTROY flag, it is normal for the event handler to return this upon disconnect notification
	if ((ret = (CALL_EVENT_HANDLER_NO_REPEAT(RRR_MQTT_CONN_EVENT_DISCONNECT) & ~RRR_MQTT_CONN_DESTROY_CONNECTION)) != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Error from event handler in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy, return was %i. ", ret);
		if ((ret & RRR_MQTT_CONN_INTERNAL_ERROR) != 0) {
			RRR_MSG_ERR("Error was critical.\n");
			goto out_unlock;
		}
		RRR_MSG_ERR("Error was non-critical, proceeding with destroy.\n");
		ret = RRR_MQTT_CONN_OK;
	}

	__rrr_mqtt_connection_destroy(connection);
	connection = NULL;

	out_unlock:
	if (connection != NULL) {
		RRR_MQTT_CONN_UNLOCK(connection);
	}

	return ret;
}

int rrr_mqtt_conn_collection_iterate (
	struct rrr_mqtt_conn_collection *connections,
	int (*callback)(struct rrr_mqtt_conn *connection, void *callback_arg),
	void *callback_arg
) {
	int ret = 0;
	int callback_ret = 0;

	if ((ret = __rrr_mqtt_connection_collection_read_lock(connections)) != 0) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate\n");
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(connections, struct rrr_mqtt_conn);
		int ret_tmp = callback(node, callback_arg);
		if (ret_tmp != RRR_MQTT_CONN_OK) {
			if ((ret_tmp & RRR_MQTT_CONN_SOFT_ERROR) != 0) {
				RRR_DBG_1("Soft error returned from callback in rrr_mqtt_connection_collection_iterate, setting disconnect reason to 0x80\n");
				callback_ret |= RRR_MQTT_CONN_SOFT_ERROR;
				ret_tmp = ret_tmp & ~RRR_MQTT_CONN_SOFT_ERROR;

				// Always destroy connection upon soft error and set non-zero
				// reason if not already set
				if (node->disconnect_reason_v5_ == 0) {
					RRR_MQTT_CONN_SET_DISCONNECT_REASON_V5(node, RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR);
				}
				callback_ret |= RRR_MQTT_CONN_DESTROY_CONNECTION;
			}

			if ((ret_tmp & RRR_MQTT_CONN_DESTROY_CONNECTION) != 0) {
//				VL_DEBUG_MSG_1("Destroying connection in rrr_mqtt_connection_collection_iterate\n");
				RRR_LL_ITERATE_SET_DESTROY();
				ret_tmp = ret_tmp & ~RRR_MQTT_CONN_DESTROY_CONNECTION;
				// Do not let DESTROY_CONNECTION propogate through the iterator since we handle it here
			}

			if ((ret_tmp & RRR_MQTT_CONN_BUSY) != 0) {
				ret_tmp = ret_tmp & ~RRR_MQTT_CONN_BUSY;
			}

			if ((ret_tmp & RRR_MQTT_CONN_ITERATE_STOP) != 0) {
				callback_ret |= RRR_MQTT_CONN_ITERATE_STOP;
				ret_tmp = ret_tmp & ~RRR_MQTT_CONN_ITERATE_STOP;
			}

			if (ret_tmp != 0) {
				RRR_MSG_ERR("Internal error returned from callback in rrr_mqtt_connection_collection_iterate return was %i\n", ret_tmp);
				callback_ret = RRR_MQTT_CONN_INTERNAL_ERROR;
				RRR_LL_ITERATE_BREAK();
			}

			if ((callback_ret & RRR_MQTT_CONN_ITERATE_STOP) != 0) {
				RRR_LL_ITERATE_BREAK();
			}
		}

#define LOCK_ERR \
			RRR_MSG_ERR("Lock error in __rrr_mqtt_connection_collection_in_iterator_destroy_connection\n");			\
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;																		\
			goto out

#define DESTROY_ERR \
			RRR_MSG_ERR("Internal error while destroying connection in rrr_mqtt_connection_collection_iterate\n");	\
			callback_ret = RRR_MQTT_CONN_INTERNAL_ERROR;															\
			RRR_LL_ITERATE_BREAK()

	RRR_LL_ITERATE_END_CHECK_DESTROY_WRAP_LOCK (
			connections,
			__rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy(node),
			DESTROY_ERR,
			ret = __rrr_mqtt_connection_collection_read_to_write_lock(connections),
			ret = __rrr_mqtt_connection_collection_write_to_read_lock(connections),
			LOCK_ERR
	);

	if ((ret = __rrr_mqtt_connection_collection_read_unlock(connections)) != 0) {
		RRR_MSG_ERR("Lock error in rrr_mqtt_connection_collection_iterate\n");
		goto out;
	}

	out:
	return (ret | callback_ret);
}

struct connection_with_iterator_ctx_do_custom_callback_data {
		const struct rrr_mqtt_conn *connection;
		int (*callback)(struct rrr_mqtt_conn *connection, void *arg);
		void *callback_arg;
		int connection_found;
};

static int __rrr_mqtt_connection_with_iterator_ctx_do_custom_callback (struct rrr_mqtt_conn *connection, void *callback_arg) {
	int ret = RRR_MQTT_CONN_OK;

	struct connection_with_iterator_ctx_do_custom_callback_data *callback_data = callback_arg;

	if (connection == callback_data->connection) {
		callback_data->connection_found = 1;
		RRR_MQTT_CONN_LOCK(connection);
		ret = callback_data->callback(connection, callback_data->callback_arg);
		RRR_MQTT_CONN_UNLOCK(connection);
	}

	return ret;
}

int rrr_mqtt_conn_with_iterator_ctx_do_custom (
		struct rrr_mqtt_conn_collection *connections,
		const struct rrr_mqtt_conn *connection,
		int (*callback)(struct rrr_mqtt_conn *connection, void *arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_CONN_OK;

	struct connection_with_iterator_ctx_do_custom_callback_data callback_data = {
			connection,
			callback,
			callback_arg,
			0
	};

	ret = rrr_mqtt_conn_collection_iterate (
			connections,
			__rrr_mqtt_connection_with_iterator_ctx_do_custom_callback,
			&callback_data
	);

	if (callback_data.connection_found != 1) {
		RRR_MSG_ERR("Connection not found in rrr_mqtt_connection_with_iterator_ctx_do\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR;
	}

	return ret;
}

struct connection_with_iterator_ctx_do_callback_data {
	const struct rrr_mqtt_conn *connection;
	struct rrr_mqtt_p *packet;
	int (*callback)(struct rrr_mqtt_conn *connection, struct rrr_mqtt_p *packet);
};

static int __rrr_mqtt_connection_with_iterator_ctx_do_callback (struct rrr_mqtt_conn *connection, void *callback_arg) {
	int ret = RRR_MQTT_CONN_OK;

	struct connection_with_iterator_ctx_do_callback_data *callback_data = callback_arg;
	ret = callback_data->callback(connection, callback_data->packet);

	return ret;
}

int rrr_mqtt_conn_with_iterator_ctx_do (
		struct rrr_mqtt_conn_collection *connections,
		const struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		int (*callback)(struct rrr_mqtt_conn *connection, struct rrr_mqtt_p *packet)
) {
	int ret = RRR_MQTT_CONN_OK;

	struct connection_with_iterator_ctx_do_callback_data callback_data = {
			connection,
			packet,
			callback
	};

	ret = rrr_mqtt_conn_with_iterator_ctx_do_custom (
			connections,
			connection,
			__rrr_mqtt_connection_with_iterator_ctx_do_callback,
			&callback_data
	);

	return ret;
}

struct check_alive_callback_data {
	int alive;
	int send_allowed;
};

int __rrr_mqtt_conn_iterator_ctx_check_alive_callback (
		struct rrr_mqtt_conn *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONN_OK;

	struct check_alive_callback_data *callback_data = arg;
	callback_data->alive = 1;

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection) ||
		RRR_MQTT_CONN_STATE_IS_CLOSED(connection) ||
		connection->session == NULL
	) {
		callback_data->alive = 0;
	}

	if (RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		callback_data->send_allowed = 1;
	}

	return ret;
}

int rrr_mqtt_conn_check_alive (
		int *alive,
		int *send_allowed,
		struct rrr_mqtt_conn_collection *connections,
		struct rrr_mqtt_conn *connection
) {
	int ret = RRR_MQTT_CONN_OK;

	*alive = 0;
	*send_allowed = 0;

	struct check_alive_callback_data callback_data = {
		0, 0
	};

	ret = rrr_mqtt_conn_with_iterator_ctx_do_custom (
			connections,
			connection,
			__rrr_mqtt_conn_iterator_ctx_check_alive_callback,
			&callback_data
	);

	// Clear all errors (BUSY, SOFT ERROR) except INTERNAL ERROR
	ret = ret & RRR_MQTT_CONN_INTERNAL_ERROR;

	if (ret != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Internal error while checking keep-alive for connection in rrr_mqtt_check_alive\n");
		goto out;
	}

	*alive = callback_data.alive;
	*send_allowed = callback_data.send_allowed;

	out:
	return ret;
}

void __rrr_mqtt_connection_update_last_seen_unlocked (struct rrr_mqtt_conn *connection) {
	connection->last_seen_time = rrr_time_get_64();
}

// TODO : Convert to use rrr_socket_read_message

int rrr_mqtt_conn_iterator_ctx_read (
		struct rrr_mqtt_conn *connection,
		int read_step_max_size
) {
	int ret = RRR_MQTT_CONN_OK;

	/* There can be multiple read threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_nolock;
	}

	struct rrr_mqtt_conn_read_session *read_session = &connection->read_session;

	if (connection->read_complete == 1) {
		if (read_session->rx_buf_wpos != read_session->target_size) {
			RRR_BUG("packet complete was 1 but read size was not target size in rrr_mqtt_connection_read\n");
		}
		ret = RRR_MQTT_CONN_BUSY;
		goto out_unlock;
	}

	if (read_session->rx_buf_wpos > read_session->target_size && read_session->target_size > 0) {
		RRR_MSG_ERR("Invalid message: Actual size of message exceeds stated size in rrr_mqtt_connection_read %li > %li (when starting read tick)\n",
				read_session->rx_buf_wpos, read_session->target_size);
		ret = RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION;
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
			ret = RRR_MQTT_CONN_BUSY;
			goto out_unlock;
		}
		else if (errno == EINTR) {
			goto poll_retry;
		}
		RRR_MSG_ERR("Poll error in rrr_mqtt_connection_read\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_unlock;
	}
	else if ((pollfd.revents & (POLLERR|POLLNVAL)) != 0) {
		RRR_MSG_ERR("Poll error in rrr_mqtt_connection_read\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_unlock;
	}
	else if (items == 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_unlock;
	}

	if (ioctl (connection->ip_data.fd, FIONREAD, &bytes_int) != 0) {
		RRR_MSG_ERR("Error from ioctl in rrr_mqtt_connection_read: %s\n", strerror(errno));
		ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_unlock;
	}

	bytes = bytes_int;

	if (bytes == 0) {
		goto out_unlock;
	}

	/* Check for new read session */
	if (read_session->rx_buf == NULL) {
		if (bytes < 2) {
			RRR_MSG_ERR("Received less than 2 bytes in first packet on connection\n");
			ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
			goto out_unlock;
		}
		read_session->rx_buf = malloc(bytes > read_step_max_size ? bytes : read_step_max_size);
		if (read_session->rx_buf == NULL) {
			RRR_MSG_ERR("Could not allocate memory in rrr_mqtt_connection_read\n");
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
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
			RRR_MSG_ERR("Could not re-allocate memory in rrr_mqtt_connection_read\n");
			ret = RRR_MQTT_CONN_INTERNAL_ERROR;
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
		RRR_BUG("to_read_bytes was < 0 in rrr_mqtt_connection_read\n");
	}

	if (connection->read_complete == 1 && to_read_bytes != 0) {
		RRR_BUG("packet_complete was 1 but to_read_bytes was not zero\n");
	}

	/*
	 * When a message is completely received, we do not read any more data
	 * until somebody else has reset the receive buffer
	 */
	if (to_read_bytes == 0) {
		connection->read_complete = 1;
		ret = RRR_MQTT_CONN_BUSY;
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
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto out_unlock;
		}
		RRR_MSG_ERR("Error from read in rrr_mqtt_connection_read: %s\n", strerror(errno));
		ret = RRR_MQTT_CONN_SOFT_ERROR;
		goto out_unlock;
	}

	if (bytes == 0) {
		RRR_MSG_ERR("Bytes was 0 after read in rrr_mqtt_connection_read, despite polling first\n");
		ret = RRR_MQTT_CONN_SOFT_ERROR | RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_unlock;
	}

	read_session->rx_buf_wpos += bytes;
	read_session->step_size_limit -= bytes;

	if (read_session->rx_buf_wpos > read_session->target_size && read_session->target_size > 0) {
		RRR_BUG("rx_buf_wpos was > target_size in rrr_mqtt_connection_read\n");
	}

	if (read_session->rx_buf_wpos == read_session->target_size && read_session->target_size > 0) {
		connection->read_complete = 1;
	}

	if (read_session->step_size_limit < 0) {
		ret = RRR_MQTT_CONN_STEP_LIMIT;
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

	__rrr_mqtt_connection_update_last_seen_unlocked (connection);

	out_unlock:
	RRR_MQTT_CONN_UNLOCK(connection);

	out_nolock:
	return ret;
}

int rrr_mqtt_conn_iterator_ctx_parse (
		struct rrr_mqtt_conn *connection
) {
	int ret = RRR_MQTT_CONN_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
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
		ret = RRR_MQTT_CONN_SOFT_ERROR|RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out_unlock;
	}

	if (RRR_MQTT_PARSE_FIXED_HEADER_IS_DONE(&connection->parse_session)) {
		connection->read_session.target_size = connection->parse_session.target_size;
		if (connection->read_session.rx_buf_wpos == connection->read_session.target_size) {
			connection->read_complete = 1;
		}
		else if (connection->read_session.rx_buf_wpos > connection->read_session.target_size) {
			RRR_MSG_ERR("Invalid message: Actual size of message exceeds stated size in rrr_mqtt_connection_parse %li > %li (after fixed header is done)\n",
					connection->read_session.rx_buf_wpos, connection->read_session.target_size);
			ret = RRR_MQTT_CONN_SOFT_ERROR;
			goto out_unlock;
		}
	}

	if (RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		if (RRR_MQTT_PARSE_STATUS_IS_MOVE_PAYLOAD_TO_PACKET(&connection->parse_session)) {
			if (connection->parse_session.packet->payload != NULL) {
				RRR_BUG("payload data was not NULL in rrr_mqtt_connection_iterator_ctx_parse while moving payload\n");
			}

			ret = rrr_mqtt_p_payload_new_with_allocated_payload (
					&connection->parse_session.packet->payload,
					connection->read_session.rx_buf,
					connection->read_session.rx_buf + connection->parse_session.payload_pos,
					connection->read_session.rx_buf_wpos - connection->parse_session.payload_pos
			);
			if (ret != 0) {
				RRR_MSG_ERR("Could not move payload to packet in rrr_mqtt_conn_iterator_ctx_parse\n");
				goto out_unlock;
			}

			connection->read_session.rx_buf = NULL;
			connection->read_session.rx_buf_wpos = 0;
		}

		connection->parse_complete = 1;

		__rrr_mqtt_connection_read_session_destroy(&connection->read_session);
		__rrr_mqtt_connection_read_session_init(&connection->read_session);

		if ((ret = CALL_EVENT_HANDLER(RRR_MQTT_CONN_EVENT_PACKET_PARSED)) != 0) {
			RRR_MSG_ERR("Error from event handler in rrr_mqtt_connection_iterator_ctx_parse, return was %i\n", ret);
			goto out_unlock;
		}
	}

	out_unlock:
	RRR_MQTT_CONN_UNLOCK(connection);

	out_nolock:
	return ret;
}

int rrr_mqtt_conn_iterator_ctx_check_parse_finalize (
		struct rrr_mqtt_conn *connection
) {
	int ret = RRR_MQTT_CONN_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED_OR_DISCONNECT_WAIT(connection)) {
		goto out_nolock;
	}

	if (connection->read_complete == 1) {
		if (connection->parse_complete != 1) {
			RRR_MSG_ERR("Reading is done for a packet but parsing did not complete. Closing connection.\n");
			ret = RRR_MQTT_CONN_DESTROY_CONNECTION|RRR_MQTT_CONN_SOFT_ERROR;
			goto out_unlock;
		}

		struct rrr_mqtt_p *packet;
		ret = rrr_mqtt_packet_parse_finalize(&packet, &connection->parse_session);
		if (rrr_mqtt_p_standardized_get_refcount(packet) != 1) {
			RRR_BUG("Refcount was not 1 while finalizing mqtt packet and adding to receive buffer\n");
		}

		rrr_fifo_buffer_write(&connection->receive_queue.buffer, (char*) packet, RRR_MQTT_P_GET_SIZE(packet));

		rrr_mqtt_parse_session_destroy(&connection->parse_session);
		rrr_mqtt_parse_session_init(&connection->parse_session);

		connection->read_complete = 0;
		connection->parse_complete = 0;
	}

	out_unlock:
		RRR_MQTT_CONN_UNLOCK(connection);

	out_nolock:
		return ret;
}

int rrr_mqtt_conn_iterator_ctx_housekeeping (
		struct rrr_mqtt_conn *connection,
		void *arg
) {
	int ret = RRR_MQTT_CONN_OK;

	/* There can be multiple parse threads, make sure we do not block */
	if (RRR_MQTT_CONN_TRYLOCK(connection) != 0) {
		ret = RRR_MQTT_CONN_BUSY;
		goto out_nolock;
	}

	struct rrr_mqtt_conn_iterator_ctx_housekeeping_callback_data *callback_data = arg;

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECT_WAIT(connection)) {
		ret = RRR_MQTT_CONN_DESTROY_CONNECTION;
		goto out;
	}

	if (connection->keep_alive > 0) {
		uint64_t limit_ping = (double) connection->keep_alive;
		uint64_t limit = (double) connection->keep_alive * 1.5;
		limit_ping *= 1000000;
		limit *= 1000000;
		if (connection->last_seen_time + limit < rrr_time_get_64()) {
			RRR_DBG_1("Keep-alive exceeded for connection\n");
			ret = RRR_MQTT_CONN_DESTROY_CONNECTION;
			goto out;
		}
		else if (callback_data->exceeded_keep_alive_callback != NULL &&
				connection->last_seen_time + limit_ping < rrr_time_get_64() &&
				(ret = callback_data->exceeded_keep_alive_callback(connection, callback_data->callback_arg)) != RRR_MQTT_CONN_OK
		) {
			RRR_MSG_ERR("Error from callback in rrr_mqtt_conn_iterator_ctx_housekeeping after exceeded keep-alive\n");
			goto out;
		}
	}

	out:
	RRR_MQTT_CONN_UNLOCK(connection);

	out_nolock:
	return ret;
}

static int __rrr_mqtt_connection_write (struct rrr_mqtt_conn *connection, const char *data, ssize_t data_size) {
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
				ret = RRR_MQTT_CONN_BUSY;
				goto out;
			}
			RRR_MSG_ERR("Error while sending packet in __rrr_mqtt_connection_write: %s\n",
					strerror(errno));
			ret = RRR_MQTT_CONN_SOFT_ERROR;
		}
		else if (bytes != data_size) {
			RRR_MSG_ERR("Error while sending packet in __rrr_mqtt_connection_write, only %li of %li bytes were sent\n",
					bytes, data_size);
			ret = RRR_MQTT_CONN_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

int __rrr_mqtt_connection_create_variable_int (
		uint8_t *target,
		ssize_t *length,
		uint32_t value
) {
	*length = 1;

	if (value > 0xfffffff) {
		RRR_MSG_ERR("Integer value too large in __rrr_mqtt_connection_create_variable_int\n");
		return RRR_MQTT_CONN_INTERNAL_ERROR;
	}

	for (int i = 0; i <= 3; i++) {
//		printf ("Value[%i]: %" PRIu32 "\n", i, value);
		target[i] = value & 0x7F;
		value >>= 7;
		if (value > 0) {
			target[i] |= 1 << 7;
			(*length)++;
		}
	}

	return RRR_MQTT_CONN_OK;
}

int rrr_mqtt_conn_iterator_ctx_send_packet (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet
) {
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		RRR_BUG("Packet lock was not held in rrr_mqtt_connection_iterator_ctx_send_packet\n");
	}
	if (RRR_MQTT_CONN_TRYLOCK(connection) == 0) {
		RRR_BUG("Connection lock was not held in rrr_mqtt_connection_iterator_ctx_send_packet\n");
	}

	int ret = RRR_MQTT_CONN_OK;
	int ret_destroy = 0;

	struct rrr_mqtt_p_payload *payload = NULL;
	char *network_data = NULL;
	ssize_t network_size = 0;

	// Packets which originate from other hosts might have different protocol
	// version.
	if (connection->protocol_version != NULL &&
		connection->protocol_version != packet->protocol_version
	) {
		packet->protocol_version = connection->protocol_version;
		RRR_FREE_IF_NOT_NULL(packet->_assembled_data);
		packet->assembled_data_size = 0;
	}

	if (packet->_assembled_data == NULL) {
		int ret_tmp = RRR_MQTT_P_GET_ASSEMBLER(packet) (
				&network_data,
				&network_size,
				packet
		);

		if (network_data == NULL) {
			RRR_BUG("Assembled packet of type %s was NULL in rrr_mqtt_conn_iterator_ctx_send_packet\n",
					RRR_MQTT_P_GET_TYPE_NAME(packet));
		}

		if (network_size == 0) {
			free(network_data);
			network_data = NULL;
		}

		packet->_assembled_data = network_data;
		packet->assembled_data_size = network_size;

		network_data = NULL;

		if (ret_tmp != RRR_MQTT_ASSEMBLE_OK) {
			if (ret_tmp == RRR_MQTT_ASSEMBLE_INTERNAL_ERR) {
				RRR_MSG_ERR("Error while assembling packet in rrr_mqtt_conn_iterator_ctx_send_packet\n");
				ret = RRR_MQTT_CONN_INTERNAL_ERROR;
				goto out;
			}
			else {
				RRR_BUG("Unknown return value %i from assembler in rrr_mqtt_conn_iterator_ctx_send_packet\n", ret_tmp);
			}
		}
	}

	// It is possible here to actually send a packet which is not allowed in the current
	// connection state, but in that case, the program will crash after the write when updating
	// the state. It is a bug to call this function with a non-timely packet.

	if (RRR_MQTT_P_IS_RESERVED_FLAGS(packet) &&
		RRR_MQTT_P_GET_PROP_FLAGS(packet) != RRR_MQTT_P_GET_TYPE_FLAGS(packet)
	) {
		RRR_BUG("Illegal flags %u for packet type %s in rrr_mqtt_conn_iterator_ctx_send_packet\n",
				RRR_MQTT_P_GET_TYPE_FLAGS(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));
	}

	struct rrr_mqtt_p_header header = {0};
	ssize_t variable_int_length = 0;
	ssize_t payload_length = 0;
	payload = packet->payload;
	if (payload != NULL) {
		RRR_MQTT_P_LOCK(packet->payload);
		payload_length = packet->payload->length;
	}

	if ((ret = __rrr_mqtt_connection_create_variable_int (
			header.length,
			&variable_int_length,
			packet->assembled_data_size + payload_length
	)) != 0) {
		RRR_MSG_ERR("Error while creating variable int in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		goto out;
	}
	header.type = RRR_MQTT_P_GET_TYPE_AND_FLAGS(packet);

	ssize_t total_size = 1 + variable_int_length + packet->assembled_data_size + payload_length;

	RRR_DBG_3("Sending packet %p of type %s flen: 1, vlen: %li, alen: %li, plen: %li, total: %li, id: %u\n",
			packet,
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			variable_int_length,
			packet->assembled_data_size,
			payload_length,
			total_size,
			RRR_MQTT_P_GET_IDENTIFIER(packet)
	);

	if ((ret = __rrr_mqtt_connection_write (connection, (char*) &header, sizeof(header.type) + variable_int_length)) != 0) {
		RRR_MSG_ERR("Error while sending fixed header in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		goto out;
	}

	if (packet->assembled_data_size > 0) {
		if ((ret = __rrr_mqtt_connection_write (connection, packet->_assembled_data, packet->assembled_data_size)) != 0) {
			RRR_MSG_ERR("Error while sending assembled data in rrr_mqtt_conn_iterator_ctx_send_packet\n");
			goto out;
		}
	}
	else if (payload != NULL) {
		RRR_BUG("Payload was present without variable header in rrr_mqtt_conn_iterator_ctx_send_packet\n");
	}

	if (payload != NULL) {
		if (payload_length == 0) {
			RRR_BUG("Payload size was 0 but payload pointer was not NULL in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		}
		if ((ret = __rrr_mqtt_connection_write (connection, payload->payload_start, payload->length)) != 0) {
			RRR_MSG_ERR("Error while sending payload data in rrr_mqtt_conn_iterator_ctx_send_packet\n");
			goto out;
		}
	}

	ret = rrr_mqtt_conn_iterator_ctx_update_state (
			connection,
			packet,
			RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT
	);
	if (ret != RRR_MQTT_CONN_OK) {
		RRR_MSG_ERR("Could not update connection state in rrr_mqtt_connection_iterator_ctx_send_packet\n");
		goto out;
	}

	packet->last_attempt = rrr_time_get_64();

	out:
	if (payload != NULL) {
		RRR_MQTT_P_UNLOCK(packet->payload);
	}
	RRR_FREE_IF_NOT_NULL(network_data);
	return ret | ret_destroy;
}

int rrr_mqtt_conn_iterator_ctx_set_data_from_connect (
		struct rrr_mqtt_conn *connection,
		uint16_t keep_alive,
		const struct rrr_mqtt_p_protocol_version *protocol_version,
		struct rrr_mqtt_session *session
) {
	if (RRR_MQTT_CONN_TRYLOCK(connection) == 0) {
		RRR_BUG("Connection lock was not held in rrr_mqtt_connection_set_protocol_version_iterator_ctx\n");
	}

	connection->keep_alive = keep_alive;
	connection->protocol_version = protocol_version;
	connection->session = session;

	return RRR_MQTT_CONN_OK;
}

int rrr_mqtt_conn_iterator_ctx_update_state (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		int direction
) {
	if (RRR_MQTT_P_TRYLOCK(packet) == 0) {
		RRR_BUG("Packet lock was not held in rrr_mqtt_connection_update_state_iterator_ctx\n");
	}
	if (RRR_MQTT_CONN_TRYLOCK(connection) == 0) {
		RRR_BUG("Connection lock was not held in rrr_mqtt_connection_update_state_iterator_ctx\n");
	}

	uint8_t packet_type = RRR_MQTT_P_GET_TYPE(packet);

	// Shortcut for normal operation. It is not our job to check
	// if we are allowed to send the normal packets, other functions
	// do that.
	if (	packet_type > RRR_MQTT_P_TYPE_CONNACK &&
			packet_type < RRR_MQTT_P_TYPE_DISCONNECT
	) {
		return RRR_MQTT_CONN_OK;
	}

	if (packet_type == RRR_MQTT_P_TYPE_CONNECT) {
		if (!RRR_MQTT_CONN_STATE_CONNECT_ALLOWED(connection)) {
			if (direction == RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT) {
				RRR_BUG("This CONNECT packet was outbound, it's a bug\n");
			}
			RRR_MSG_ERR("Tried to process a CONNECT while not allowed\n");
			return RRR_MQTT_CONN_SOFT_ERROR;
		}

		RRR_MQTT_CONN_STATE_SET (connection,
				direction == RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT
					? RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_ALLOWED
					: RRR_MQTT_CONN_STATE_SEND_CONNACK_ALLOWED
		);
	}
	else if (packet_type == RRR_MQTT_P_TYPE_CONNACK) {
		if (direction == RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT) {
			if (!RRR_MQTT_CONN_STATE_SEND_CONNACK_IS_ALLOWED(connection)) {
				RRR_BUG("Tried to send CONNACK while not allowed\n");
			}
		}
		else if (!RRR_MQTT_CONN_STATE_RECEIVE_CONNACK_IS_ALLOWED(connection)) {
			RRR_MSG_ERR("Received CONNACK while not allowed\n");
			return RRR_MQTT_CONN_SOFT_ERROR;
		}

		RRR_MQTT_CONN_STATE_SET (connection,
				RRR_MQTT_P_GET_REASON_V5(packet) == RRR_MQTT_P_5_REASON_OK
					? RRR_MQTT_CONN_STATE_SEND_ANY_ALLOWED | RRR_MQTT_CONN_STATE_RECEIVE_ANY_ALLOWED
					: RRR_MQTT_CONN_STATE_DISCONNECT_WAIT
		);
	}
	else if (packet_type == RRR_MQTT_P_TYPE_DISCONNECT) {
		if (direction == RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT) {
			if (!RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
				RRR_BUG("Tried to send DISCONNECT while not allowed");
			}
		}
		else if (!RRR_MQTT_CONN_STATE_RECEIVE_ANY_IS_ALLOWED(connection)) {
			RRR_MSG_ERR("Received DISCONNECT while not allowed\n");
			return RRR_MQTT_CONN_SOFT_ERROR;
		}
		RRR_MQTT_CONN_STATE_SET (connection, RRR_MQTT_CONN_STATE_DISCONNECT_WAIT);
	}
	else {
		RRR_BUG("Unknown control packet %u in rrr_mqtt_connection_update_state_iterator_ctx\n", packet_type);
	}

	return RRR_MQTT_CONN_OK;
}
