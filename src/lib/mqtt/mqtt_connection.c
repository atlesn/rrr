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

#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "../log.h"

#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_packet.h"
#include "mqtt_parse.h"
#include "mqtt_assemble.h"

#include "../ip.h"
#include "../ip_accept_data.h"
#include "../buffer.h"
#include "../vl_time.h"
#include "../net_transport/net_transport.h"
#include "../rrr_strerror.h"
#include "../macro_utils.h"

static int __rrr_mqtt_connection_call_event_handler (struct rrr_mqtt_conn *connection, int event, int no_repeat, void *arg) {
	int ret = RRR_MQTT_OK;

	if (no_repeat == 0 || connection->last_event != event) {
		ret = connection->event_handler (
				connection,
				event,
				connection->event_handler_static_arg,
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

int rrr_mqtt_conn_update_state (
		struct rrr_mqtt_conn *connection,
		struct rrr_mqtt_p *packet,
		int direction
) {
	uint8_t packet_type = RRR_MQTT_P_GET_TYPE(packet);

	// Shortcut for normal operation. It is not our job to check
	// if we are allowed to send the normal packets, other functions
	// do that.
	if (	packet_type > RRR_MQTT_P_TYPE_CONNACK &&
			packet_type < RRR_MQTT_P_TYPE_DISCONNECT
	) {
		return RRR_MQTT_OK;
	}

	if (packet_type == RRR_MQTT_P_TYPE_CONNECT) {
		if (!RRR_MQTT_CONN_STATE_CONNECT_ALLOWED(connection)) {
			if (direction == RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT) {
				RRR_BUG("This CONNECT packet was outbound, it's a bug\n");
			}
			RRR_MSG_0("Tried to process a CONNECT while not allowed\n");
			return RRR_MQTT_SOFT_ERROR;
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
			RRR_MSG_0("Received CONNACK while not allowed\n");
			return RRR_MQTT_SOFT_ERROR;
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
			RRR_MSG_0("Received DISCONNECT while not allowed\n");
			return RRR_MQTT_SOFT_ERROR;
		}
		RRR_MQTT_CONN_STATE_SET (connection, RRR_MQTT_CONN_STATE_DISCONNECT_WAIT);
	}
	else {
		RRR_BUG("Unknown control packet %u in rrr_mqtt_connection_update_state_iterator_ctx\n", packet_type);
	}

	return RRR_MQTT_OK;
}

int rrr_mqtt_conn_iterator_ctx_send_disconnect (
		struct rrr_net_transport_handle *handle
) {
	// Will return immediately if disconnect is already sent
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	// Check if CONNECT is not yet received
	if (connection->protocol_version == NULL) {
		goto out_nolock;
	}

	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) rrr_mqtt_p_allocate (
			RRR_MQTT_P_TYPE_DISCONNECT,
			connection->protocol_version
	);
	if (disconnect == NULL) {
		RRR_MSG_0("Could not allocate DISCONNECT packet in rrr_mqtt_conn_iterator_ctx_send_disconnect\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out_nolock;
	}

	RRR_MQTT_P_LOCK(disconnect);

	disconnect->reason_v5 = connection->disconnect_reason_v5_;

	// If a CONNACK is sent, we must not sent DISCONNECT packet
	if (RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet (
				handle,
				(struct rrr_mqtt_p *) disconnect
		)) != RRR_MQTT_OK) {
			ret = ret & ~RRR_MQTT_SOFT_ERROR;
			if (ret != RRR_MQTT_OK) {
				RRR_MSG_0("Error while queuing outbound DISCONNECT packet in rrr_mqtt_conn_iterator_ctx_send_disconnect return was %i\n",
						ret);
				goto send_disconnect_out;
			}
			ret |= RRR_MQTT_SOFT_ERROR;
		}

		send_disconnect_out:
		if (ret != RRR_MQTT_OK) {
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

static void __rrr_mqtt_connection_close (
		struct rrr_mqtt_conn *connection
) {
	RRR_MQTT_CONN_STATE_SET(connection, RRR_MQTT_CONN_STATE_CLOSED);
}

static void __rrr_mqtt_connection_destroy (struct rrr_mqtt_conn *connection) {
	if (connection == NULL) {
		RRR_BUG("NULL pointer in __rrr_mqtt_connection_destroy\n");
	}

	// This will be cleaned up anyway, it's more for informational purposes
	if (!RRR_MQTT_CONN_STATE_IS_CLOSED(connection)) {
		RRR_DBG_2("Connection %p was supposedly not yet closed, closing now\n", connection);
		__rrr_mqtt_connection_close (connection);
	}

	RRR_DBG_2("Destroying connection %p, final destruction\n", connection);

	rrr_fifo_buffer_clear(&connection->receive_queue.buffer);

	rrr_mqtt_parse_session_destroy(&connection->parse_session);

	RRR_FREE_IF_NOT_NULL(connection->client_id);
	RRR_FREE_IF_NOT_NULL(connection->username);

	free(connection);
}

static void __rrr_mqtt_connection_destroy_void (void *arg) {
	__rrr_mqtt_connection_destroy(arg);
}

static int __rrr_mqtt_conn_new (
		struct rrr_mqtt_conn **connection,
		const struct sockaddr *remote_addr,
		uint64_t close_wait_time_usec,
		int (*event_handler)(RRR_MQTT_EVENT_HANDLER_DEFINITION),
		void *event_handler_arg
) {
	int ret = RRR_MQTT_OK;

	*connection = NULL;
	struct rrr_mqtt_conn *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = rrr_fifo_buffer_init_custom_free(&res->receive_queue.buffer,	rrr_mqtt_p_standardized_decref)) != 0) {
		RRR_MSG_0("Could not initialize buffers in __rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out_free;
	}

	res->connect_time = res->last_read_time = res->last_write_time = rrr_time_get_64();
	res->close_wait_time_usec = close_wait_time_usec;
	res->event_handler = event_handler;
	res->event_handler_static_arg = event_handler_arg;

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

	goto out;

	out_free:
		free(res);

	out:
		return ret;
}

static int __rrr_mqtt_connection_in_iterator_disconnect (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_mqtt_conn *connection = arg;

	int ret = RRR_MQTT_OK;

	if (RRR_MQTT_CONN_STATE_IS_DISCONNECTED(connection)) {
		RRR_BUG("Connection %p state was already DISCONNECTED in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy\n",
				connection);
	}

	// Upon some errors, connection state will not yet have transitioned into DISCONNECT WAIT.
	if (!RRR_MQTT_CONN_STATE_IS_DISCONNECT_WAIT(connection)) {
		ret = rrr_mqtt_conn_iterator_ctx_send_disconnect(handle);
		if ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) {
			RRR_MSG_0("Internal error sending disconnect packet in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy\n");
			goto out;
		}
		// Ignore soft errors when sending DISCONNECT packet here.
		ret = 0;
	}

	if (connection->close_wait_time_usec > 0) {
		uint64_t time_now = rrr_time_get_64();
		if (connection->close_wait_start == 0) {
			connection->close_wait_start = time_now;
			RRR_DBG_1("Destroying connection %p client ID '%s' reason %u, starting timer (and closing connection if neeeded)\n",
					connection,
					(connection->client_id != NULL ? connection->client_id : "(empty)"),
					connection->disconnect_reason_v5_
			);
			if (!RRR_MQTT_CONN_STATE_IS_CLOSED(connection)) {
				__rrr_mqtt_connection_close (connection);
			}
		}
		if (time_now - connection->close_wait_start < connection->close_wait_time_usec) {
/*			printf ("Connection is not to be closed closed yet, waiting %" PRIu64 " usecs\n",
					(*cur)->close_wait_time_usec - (time_now - (*cur)->close_wait_start));*/
			// We can basically return anything apart from 1 to stop net transport from destroying connection.
			// When we return 0, connection is destroyed.
			ret = RRR_LL_DIDNT_DESTROY;
			goto out;
		}
		RRR_DBG_2("Destroying connection %p reason %u, timer done\n",
				connection, connection->disconnect_reason_v5_);
	}

	// Clear DESTROY flag, it is normal for the event handler to return this upon disconnect notification
	if ((ret = (CALL_EVENT_HANDLER_NO_REPEAT(RRR_MQTT_CONN_EVENT_DISCONNECT) & ~RRR_MQTT_SOFT_ERROR)) != RRR_MQTT_OK) {
		RRR_MSG_0("Error from event handler in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy, return was %i. ", ret);
		if ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) {
			RRR_MSG_0("Error was critical.\n");
			goto out;
		}
		RRR_MSG_0("Error was non-critical, proceeding with destroy.\n");
		ret = RRR_MQTT_OK;
	}

	out:
	return ret;
}

int rrr_mqtt_conn_set_data_from_connect_and_connack (
		struct rrr_mqtt_conn *connection,
		uint16_t keep_alive,
		const struct rrr_mqtt_p_protocol_version *protocol_version,
		struct rrr_mqtt_session *session,
		const char *username
) {
	int ret = RRR_MQTT_OK;

	connection->keep_alive = keep_alive;
	connection->protocol_version = protocol_version;
	connection->session = session;

	if (username != NULL && *username != '\0') {
		RRR_FREE_IF_NOT_NULL(connection->username);
		if ((connection->username = strdup(username)) == NULL) {
			RRR_MSG_0("Could not allocate memory for username in rrr_mqtt_conn_iterator_ctx_set_data_from_connect\n");
			ret = RRR_MQTT_INTERNAL_ERROR;
		}
	}

	return ret;
}

int rrr_mqtt_conn_housekeeping (
		struct rrr_mqtt_conn *connection,
		void *rrr_mqtt_conn_iterator_ctx_housekeeping_callback_data
) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_conn_iterator_ctx_housekeeping_callback_data *callback_data = rrr_mqtt_conn_iterator_ctx_housekeeping_callback_data;

	if (connection->keep_alive > 0) {
		uint64_t limit_ping = (double) connection->keep_alive;
		uint64_t limit = (double) connection->keep_alive * 1.5;
		limit_ping *= 1000000;
		limit *= 1000000;
		if (connection->last_write_time + limit < rrr_time_get_64() || connection->last_read_time + limit < rrr_time_get_64()) {
			RRR_DBG_1("Keep-alive exceeded for connection\n");
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}
		else if (callback_data->exceeded_keep_alive_callback != NULL &&
				(connection->last_read_time + limit_ping < rrr_time_get_64() ||
				connection->last_write_time + limit_ping < rrr_time_get_64()) &&
				(ret = callback_data->exceeded_keep_alive_callback(connection, callback_data->callback_arg)) != RRR_MQTT_OK
		) {
			RRR_MSG_0("Error from callback in rrr_mqtt_conn_iterator_ctx_housekeeping after exceeded keep-alive\n");
			goto out;
		}
	}

	out:
	return ret;
}

void rrr_mqtt_conn_accept_and_connect_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	struct rrr_mqtt_common_accept_and_connect_callback_data *callback_data = arg;

	(void)(socklen);

	struct rrr_mqtt_conn *new_connection = NULL;

	if (__rrr_mqtt_conn_new (
			&new_connection,
			sockaddr,
			callback_data->close_wait_time_usec,
			callback_data->event_handler,
			callback_data->event_handler_arg
	) != RRR_MQTT_OK) {
		RRR_MSG_0("Could not create connection in __rrr_mqtt_conn_collection_accept_connect_callback\n");
		goto out;
	}

//	new_connection->transport = handle->transport;
	new_connection->transport_handle = handle->handle;

	handle->application_private_ptr = new_connection;
	handle->application_ptr_destroy = __rrr_mqtt_connection_destroy_void;
	handle->application_ptr_iterator_pre_destroy = __rrr_mqtt_connection_in_iterator_disconnect;

	callback_data->transport_handle = handle->handle;

	out:
	return;
}

int rrr_mqtt_conn_iterator_ctx_check_alive_callback (
		struct rrr_net_transport_handle *handle,
		void *rrr_mqtt_conn_check_alive_callback_data
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_conn_check_alive_callback_data *callback_data = rrr_mqtt_conn_check_alive_callback_data;
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

static void __rrr_mqtt_connection_update_last_read_time (struct rrr_mqtt_conn *connection) {
	connection->last_read_time = rrr_time_get_64();
//-	printf ("Set last_read_time to %" PRIu64 "\n", connection->last_read_time);
}

static void __rrr_mqtt_connection_update_last_write_time (struct rrr_mqtt_conn *connection) {
	connection->last_write_time = rrr_time_get_64();
//	printf ("Set last_write_time to %" PRIu64 "\n", connection->last_write_time);
}

static int __rrr_mqtt_conn_parse (
		struct rrr_read_session *read_session,
		struct rrr_mqtt_conn *connection
) {
	int ret = RRR_MQTT_INCOMPLETE;

	if (RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		ret = RRR_MQTT_OK;
		goto out;
	}

	// Read function might do realloc which means we must update our pointer
	rrr_mqtt_parse_session_update (
			&connection->parse_session,
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			connection->protocol_version
	);

	rrr_mqtt_packet_parse (&connection->parse_session);
	if (RRR_MQTT_PARSE_IS_ERR(&connection->parse_session)) {
		/* Error which was the remote's fault, close connection */
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	if (RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		ret = RRR_MQTT_OK;
		goto out;
	}

	out:
	return ret;
}

struct rrr_mqtt_conn_read_callback_data {
	struct rrr_net_transport_handle *handle;
	int (*handler_callback) (
			struct rrr_net_transport_handle *handle,
			struct rrr_mqtt_p *packet,
			void *arg
	);
	void *handler_callback_arg;
};

static int __rrr_mqtt_conn_read_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	int ret = RRR_SOCKET_READ_INCOMPLETE;

	struct rrr_mqtt_conn_read_callback_data *callback_data = arg;
	struct rrr_mqtt_conn *connection = callback_data->handle->application_private_ptr;

//	printf ("get target size in %p wpos %li target size %li buf size %li\n",
//			read_session, read_session->rx_buf_wpos, read_session->target_size, read_session->rx_buf_size);

	if ((ret = __rrr_mqtt_conn_parse (read_session, connection)) != RRR_MQTT_OK) {
		if ((ret & (RRR_MQTT_INTERNAL_ERROR|RRR_MQTT_SOFT_ERROR)) != 0) {
			ret &= ~(RRR_SOCKET_READ_INCOMPLETE);
			goto out;
		}
		// Don't got out, fixed header might be done
	}

	if (RRR_MQTT_PARSE_FIXED_HEADER_IS_DONE(&connection->parse_session)) {
		read_session->target_size = connection->parse_session.target_size;
		ret = RRR_READ_OK;
	}

//	printf ("get target size out %p wpos %li target size %li buf size %li\n",
//			read_session, read_session->rx_buf_wpos, read_session->target_size, read_session->rx_buf_size);

	out:
	return ret;
}

static int __rrr_mqtt_conn_read_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	int ret = RRR_SOCKET_OK;
	struct rrr_mqtt_p *packet = NULL;

	struct rrr_mqtt_conn_read_callback_data *callback_data = arg;
	struct rrr_mqtt_conn *connection = callback_data->handle->application_private_ptr;

//	printf ("read_complete %p wpos %li target size %li buf size %li\n",
//			read_session, read_session->rx_buf_wpos, read_session->target_size, read_session->rx_buf_size);

	__rrr_mqtt_connection_update_last_read_time (connection);

	if ((ret = __rrr_mqtt_conn_parse (read_session, connection)) != RRR_MQTT_OK) {
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (!RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		RRR_MSG_0("Reading is done for a packet but parsing did not complete. Closing connection.\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (RRR_MQTT_PARSE_STATUS_IS_MOVE_PAYLOAD_TO_PACKET(&connection->parse_session)) {
		if (connection->parse_session.packet->payload != NULL) {
			RRR_BUG("payload data was not NULL in __rrr_mqtt_conn_read_complete_callback while moving payload\n");
		}

		ret = rrr_mqtt_p_payload_new_with_allocated_payload (
				&connection->parse_session.packet->payload,
				read_session->rx_buf_ptr,
				read_session->rx_buf_ptr + connection->parse_session.payload_pos,
				read_session->rx_buf_wpos - connection->parse_session.payload_pos
		);
		if (ret != 0) {
			RRR_MSG_0("Could not move payload to packet in __rrr_mqtt_conn_read_complete_callback\n");
			goto out;
		}

		read_session->rx_buf_ptr = NULL;
		read_session->rx_buf_wpos = 0;
	}

	if ((ret = CALL_EVENT_HANDLER_ARG(RRR_MQTT_CONN_EVENT_PACKET_PARSED, connection->parse_session.packet)) != 0) {
		RRR_MSG_0("Error from event handler in __rrr_mqtt_conn_read_complete_callback, return was %i\n", ret);
		goto out;
	}

	rrr_mqtt_packet_parse_session_extract_packet(&packet, &connection->parse_session);

	if (rrr_mqtt_p_standardized_get_refcount(packet) != 1) {
		RRR_BUG("Refcount was not 1 while finalizing mqtt packet and adding to receive buffer\n");
	}

	rrr_mqtt_parse_session_destroy(&connection->parse_session);
	rrr_mqtt_parse_session_init(&connection->parse_session);

	if ((ret = callback_data->handler_callback (
			callback_data->handle,
			packet,
			callback_data->handler_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from handler callback in __rrr_mqtt_conn_read_complete_callback, return was %i\n", ret);
		goto out;
	}

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(packet);
	return ret;
}

int rrr_mqtt_conn_iterator_ctx_read (
		struct rrr_net_transport_handle *handle,
		int read_step_max_size,
		int read_per_round_max,
		int (*handler_callback) (
				struct rrr_net_transport_handle *handle,
				struct rrr_mqtt_p *packet,
				void *arg
		),
		void *handler_callback_arg
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_conn_read_callback_data callback_data = {
			handle,
			handler_callback,
			handler_callback_arg
	};

	int consecutive_nothing_happened = 0;
	int read_loops = 0;

	// TODO : Make this better
	// Do this 60 times as we send 50 packets at a time (10 more)
	for (int i = 0; i < read_per_round_max; i++) {
		uint64_t prev_bytes_read = handle->bytes_read_total;

		if ((ret = rrr_net_transport_ctx_read_message (
				handle,
				2, // Read two times this round
				2, // Read only two bytes the first time
				read_step_max_size,
				0, // No max read size
				RRR_READ_F_NO_SLEEPING,
				__rrr_mqtt_conn_read_get_target_size,
				&callback_data,
				__rrr_mqtt_conn_read_complete_callback,
				&callback_data
		)) != 0) {
			goto out;
		}

		if (prev_bytes_read == handle->bytes_read_total && ++consecutive_nothing_happened > 5) {
			// Nothing was read
			break;
		}
		read_loops++;
	}

	if (read_loops > 0) {
//		printf("Read loops: %i\n", read_loops);
	}

	out:
	return ret;
}

static int __rrr_mqtt_conn_iterator_ctx_write (
		struct rrr_net_transport_handle *handle,
		const char *data,
		ssize_t data_size
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = 0;

	if (rrr_net_transport_ctx_send_nonblock(handle, data, data_size) != 0) {
		if (ret == RRR_NET_TRANSPORT_SEND_INCOMPLETE) {
			ret = RRR_MQTT_INCOMPLETE;
			goto out;
		}
		RRR_MSG_0("Error while sending packet in __rrr_mqtt_conn_iterator_ctx_write\n");
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
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
		RRR_MSG_0("Integer value too large in __rrr_mqtt_connection_create_variable_int\n");
		return RRR_MQTT_INTERNAL_ERROR;
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

	return RRR_MQTT_OK;
}

int rrr_mqtt_conn_iterator_ctx_send_packet (
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;
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
				RRR_MSG_0("Error while assembling packet in rrr_mqtt_conn_iterator_ctx_send_packet\n");
				ret = RRR_MQTT_INTERNAL_ERROR;
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
		RRR_MSG_0("Error while creating variable int in rrr_mqtt_conn_iterator_ctx_send_packet\n");
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

	__rrr_mqtt_connection_update_last_write_time(connection);

	if ((ret = __rrr_mqtt_conn_iterator_ctx_write (handle, (char*) &header, sizeof(header.type) + variable_int_length)) != 0) {
		if (ret == RRR_MQTT_INCOMPLETE) {
			RRR_DBG_3("Note: Connection busy while sending fixed header in rrr_mqtt_conn_iterator_ctx_send_packet\n");
			ret = RRR_MQTT_OK;
			goto out;
		}

		RRR_MSG_0("Error while sending fixed header in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		goto out;
	}

	if (packet->assembled_data_size > 0) {
		if ((ret = __rrr_mqtt_conn_iterator_ctx_write (handle, packet->_assembled_data, packet->assembled_data_size)) != 0) {
			// TODO : Recover from this?
			RRR_MSG_0("Error: Error while sending assembled data in rrr_mqtt_conn_iterator_ctx_send_packet. Fixed data was already sent, cannot recover from this.\n");
			ret = RRR_MQTT_SOFT_ERROR;
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
		if ((ret = __rrr_mqtt_conn_iterator_ctx_write (handle, payload->payload_start, payload->length)) != 0) {
			RRR_MSG_0("Error while sending payload data in rrr_mqtt_conn_iterator_ctx_send_packet\n");
			goto out;
		}
	}

	ret = rrr_mqtt_conn_update_state (
			connection,
			packet,
			RRR_MQTT_CONN_UPDATE_STATE_DIRECTION_OUT
	);
	if (ret != RRR_MQTT_OK) {
		RRR_MSG_0("Could not update connection state in rrr_mqtt_connection_iterator_ctx_send_packet\n");
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
