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
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_packet.h"
#include "mqtt_parse.h"
#include "mqtt_assemble.h"

#include "../ip/ip.h"
#include "../ip/ip_accept_data.h"
#include "../fifo.h"
#include "../net_transport/net_transport.h"
#include "../rrr_strerror.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"

#define RRR_MQTT_CONN_SEND_CHUNK_LIMIT_FACTOR 0.9

static int __rrr_mqtt_connection_call_event_handler (struct rrr_mqtt_conn *connection, int event, int no_repeat, void *arg) {
	int ret = RRR_MQTT_OK;

	if (connection->event_handler != NULL && (no_repeat == 0 || connection->last_event != event)) {
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

#define RRR_MQTT_CONN_TIMEOUTS_CHECK()                         \
        short keepalive_reached = 0;                           \
        short keepalive_exceeded = 0;                          \
        __rrr_mqtt_conn_timeouts_check (&keepalive_reached, &keepalive_exceeded, connection)

int rrr_mqtt_conn_set_client_id (
		struct rrr_mqtt_conn *connection,
		const char *id
) {
	RRR_FREE_IF_NOT_NULL(connection->client_id);
	if ((connection->client_id = rrr_strdup(id)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_conn_update_client_id\n");
		return 1;
	}
	return 0;
}

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
					: RRR_MQTT_CONN_STATE_CLOSE_WAIT
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

		RRR_MQTT_CONN_STATE_SET (connection, RRR_MQTT_CONN_STATE_CLOSE_WAIT);
	}
	else {
		RRR_BUG("Unknown control packet %u in rrr_mqtt_connection_update_state_iterator_ctx\n", packet_type);
	}

	return RRR_MQTT_OK;
}

int rrr_mqtt_conn_iterator_ctx_set_disconnect_reason (
		struct rrr_net_transport_handle *handle,
		uint8_t reason_v5
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;
	RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, reason_v5);
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
		goto out_no_decref;
	}

	struct rrr_mqtt_p_disconnect *disconnect = (struct rrr_mqtt_p_disconnect *) rrr_mqtt_p_allocate (
			RRR_MQTT_P_TYPE_DISCONNECT,
			connection->protocol_version
	);
	if (disconnect == NULL) {
		RRR_MSG_0("Could not allocate DISCONNECT packet in rrr_mqtt_conn_iterator_ctx_send_disconnect\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out_no_decref;
	}

	disconnect->reason_v5 = connection->disconnect_reason_v5_;

	// If a CONNACK is sent, we must not sent DISCONNECT packet
	if (RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		if ((ret = rrr_mqtt_conn_iterator_ctx_send_packet_urgent (
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
	RRR_MQTT_P_DECREF(disconnect);

	out_no_decref:
	// Force state transition even when sending disconnect packet fails
	if (!RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(connection)) {
		RRR_DBG_1 ("Sending disconnect packet failed, force state transition to CLOSE_WAIT\n");
		connection->state_flags = RRR_MQTT_CONN_STATE_CLOSE_WAIT;
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

	rrr_fifo_clear(&connection->receive_buffer.buffer);

	rrr_mqtt_parse_session_destroy(&connection->parse_session);

	RRR_FREE_IF_NOT_NULL(connection->client_id);
	RRR_FREE_IF_NOT_NULL(connection->username);

	rrr_free(connection);
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

	res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_connection_new\n");
		ret = RRR_MQTT_INTERNAL_ERROR;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	rrr_fifo_init_custom_refcount (
			&res->receive_buffer.buffer,
			rrr_mqtt_p_standardized_incref,
			rrr_mqtt_p_standardized_decref
	);

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

//	out_free:
//		rrr_free(res);
	out:
		return ret;
}

static void __rrr_mqtt_conn_timeouts_check (
		short *keepalive_reached,
		short *keepalive_exceeded,
		struct rrr_mqtt_conn *connection
) {
	*keepalive_reached = 0;
	*keepalive_exceeded = 0;

	uint64_t limit_ping = connection->keep_alive;
	uint64_t limit = (uint64_t) ((double) connection->keep_alive * 1.5);

	limit_ping *= 1000000;
	limit *= 1000000;

	if (connection->last_read_time + limit < rrr_time_get_64()) {
		*keepalive_exceeded = 1;
	}

	if ( connection->last_read_time + limit_ping < rrr_time_get_64() ||
	     connection->last_write_time + limit_ping < rrr_time_get_64()
	) {
		*keepalive_reached = 1;
	}
}

static int __rrr_mqtt_connection_disconnect_call_event_handler_if_needed (
		struct rrr_mqtt_conn *connection
) {
	int ret = 0;

	// Clear DESTROY flag, it is normal for the event handler to return this upon disconnect notification
	if ((ret = (CALL_EVENT_HANDLER_NO_REPEAT(RRR_MQTT_CONN_EVENT_DISCONNECT) & ~RRR_MQTT_SOFT_ERROR)) != RRR_MQTT_OK) {
		RRR_MSG_0("Error from event handler in __rrr_mqtt_connection_disconnect_call_event_handler_if_needed, return was %i. ", ret);
		if ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) {
			RRR_MSG_0("Error was critical.\n");
			goto out;
		}
		RRR_MSG_0("Error was non-critical, proceeding with destroy.\n");
		ret = RRR_MQTT_OK;
	}

	// Prevents further event handler calls
	connection->event_handler = NULL;
	connection->event_handler_static_arg = NULL;

	out:
	return ret;
}

static int __rrr_mqtt_connection_in_iterator_disconnect (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_mqtt_conn *connection = arg;

	int ret = RRR_MQTT_OK;

	// The session system must be informed (through broker/client event handlers) before close_wait expires
	// in case the client re-connects before close_wait has finished. This prevents the new connection
	// from experiencing the session being destroyed shortly after connecting.
	if ((ret = __rrr_mqtt_connection_disconnect_call_event_handler_if_needed(connection)) != 0) {
		goto out;
	}

	// Check if we should send disconnect packet. When the disconnect packet has been sent, state
	// will transition to CLOSE_WAIT. If a disconnect packet is already received or sent otherwise
	// by non-error means, state is already CLOSE_WAIT here. For severe errors with V3.1 we do not
	// send the packet, these errors will set a disconnect reason >= 0x80.

	RRR_MQTT_CONN_TIMEOUTS_CHECK();

	if (keepalive_exceeded || connection->disconnect_reason_v5_ == RRR_MQTT_P_5_REASON_KEEP_ALIVE_TIMEOUT) {
		RRR_DBG_1(">>>X Destroying connection %p client ID '%s', keep alive was exceeded. Reason is otherwise set to %u.\n",
				connection,
				(connection->client_id != NULL ? connection->client_id : "(empty)"),
				connection->disconnect_reason_v5_
		);

		// Must destroy connection immediately without DISCONNECT packet. There is a reason defined
		// in v5, but the same standard also instructs to close the connection without
		// sending any DISCONNECT.

		goto out;
	}
	else if (!RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(connection)) {
		if (connection->disconnect_reason_v5_ >= 0x80) {
			const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(connection->disconnect_reason_v5_);
			RRR_DBG_1(">>>X Severe error %u ('%s') for connection with client id '%s', must disconnect now\n",
					connection->disconnect_reason_v5_,
					(reason != NULL ? reason->description : "unknown error"),
					(connection->client_id != NULL ? connection->client_id : "")
			);
		}

		// To trigger any will message when version is not 5, close the connection without sending disconnect packet

		if ( (connection->protocol_version != NULL && connection->protocol_version->id == RRR_MQTT_VERSION_5) ||
		     (connection->disconnect_reason_v5_ < 0x80 && connection->disconnect_reason_v5_ != RRR_MQTT_P_5_REASON_DISCONNECT_WITH_WILL)
		) {
			ret = rrr_mqtt_conn_iterator_ctx_send_disconnect(handle);
			// Ignore soft errors when sending DISCONNECT packet here.
			ret &= ~(RRR_MQTT_SOFT_ERROR);
			if (ret != 0) {
				RRR_MSG_0("Internal error sending disconnect packet in __rrr_mqtt_connection_collection_in_iterator_disconnect_and_destroy\n");
				goto out;
			}
		}
		else {
			// For V3.1, close connection immediately without sending DISCONNECT
			RRR_DBG_1 ("Force state transition to CLOSE_WAIT\n");
			connection->state_flags = RRR_MQTT_CONN_STATE_CLOSE_WAIT;
		}
	}

	if (connection->close_wait_time_usec == 0) {
		goto out;
	}

	const uint64_t time_now = rrr_time_get_64();

	if (connection->close_wait_start == 0) {
		connection->close_wait_start = time_now;

		RRR_DBG_1(">>>X Destroying connection %p client ID '%s' reason %u, starting timer %" PRIu64 " usecs (and closing connection if needed).\n",
				connection,
				(connection->client_id != NULL ? connection->client_id : "(empty)"),
				connection->disconnect_reason_v5_,
				connection->close_wait_time_usec
		);

	}

	if (connection->close_wait_start + connection->close_wait_time_usec > time_now) {
//			printf ("Connection is not to be closed closed yet, waiting %" PRIu64 " usecs\n",
//				connection->close_wait_time_usec - (time_now - connection->close_wait_start)).

		// When we return EOF, connection is not destroyed.
		ret = RRR_NET_TRANSPORT_READ_READ_EOF;
		goto out;
	}

	out:
		if (ret != RRR_NET_TRANSPORT_READ_READ_EOF) {
			if (!RRR_MQTT_CONN_STATE_IS_CLOSED(connection)) {
				__rrr_mqtt_connection_close (connection);
			}
			RRR_DBG_2("Destroying connection %p reason %u, timer done\n",
					connection, connection->disconnect_reason_v5_);
		}
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
		if ((connection->username = rrr_strdup(username)) == NULL) {
			RRR_MSG_0("Could not allocate memory for username in rrr_mqtt_conn_iterator_ctx_set_data_from_connect\n");
			ret = RRR_MQTT_INTERNAL_ERROR;
		}
	}

	return ret;
}

int rrr_mqtt_conn_iterator_ctx_housekeeping (
		struct rrr_net_transport_handle *handle,
		int (*exceeded_keep_alive_callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *callback_arg
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	if (connection->keep_alive > 0) {
		RRR_MQTT_CONN_TIMEOUTS_CHECK();

		if (keepalive_exceeded) {
			RRR_DBG_1("Keep-alive exceeded for connection\n");
			RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_KEEP_ALIVE_TIMEOUT);
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}
		else if ((keepalive_reached) &&
		         (exceeded_keep_alive_callback) != NULL &&
                         (ret = exceeded_keep_alive_callback(handle, callback_arg)) != RRR_MQTT_OK
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

	rrr_net_transport_ctx_handle_application_data_bind(handle, new_connection, __rrr_mqtt_connection_destroy_void);
	rrr_net_transport_ctx_handle_pre_destroy_function_set(handle, __rrr_mqtt_connection_in_iterator_disconnect);

	new_connection->transport_handle = callback_data->transport_handle = RRR_NET_TRANSPORT_CTX_HANDLE(handle);

	out:
	return;
}

int rrr_mqtt_conn_iterator_ctx_check_alive (
		int *alive,
		int *send_allowed,
		int *close_wait,
		struct rrr_net_transport_handle *handle
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	*alive = 1;
	*send_allowed = 0;
	*close_wait = 0;

	if (RRR_MQTT_CONN_STATE_IS_CLOSED_OR_CLOSE_WAIT(connection) ||
		RRR_MQTT_CONN_STATE_IS_CLOSED(connection) ||
		connection->session == NULL
	) {
		*alive = 0;
	}

	if (RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection)) {
		*send_allowed = 1;
	}


	if (RRR_MQTT_CONN_STATE_IS_CLOSE_WAIT(connection)) {
		*close_wait = 1;
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
	struct rrr_mqtt_conn *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(callback_data->handle);

//	printf ("get target size in %p wpos %li target size %li buf size %li\n",
//			read_session, read_session->rx_buf_wpos, read_session->target_size, read_session->rx_buf_size);

	if ((ret = __rrr_mqtt_conn_parse (read_session, connection)) != RRR_MQTT_OK) {
		if ((ret & (RRR_MQTT_INTERNAL_ERROR|RRR_MQTT_SOFT_ERROR)) != 0) {
			if ((ret & RRR_MQTT_SOFT_ERROR) != 0) {
				RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_MALFORMED_PACKET);
			}
			ret &= ~(RRR_SOCKET_READ_INCOMPLETE);
			RRR_MSG_0("Returned error from __rrr_mqtt_conn_parse: %i\n", ret);
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
	struct rrr_mqtt_conn *connection = RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(callback_data->handle);

//	printf ("read_complete %p wpos %li target size %li buf size %li\n",
//			read_session, read_session->rx_buf_wpos, read_session->target_size, read_session->rx_buf_size);

	__rrr_mqtt_connection_update_last_read_time (connection);

	if ((ret = __rrr_mqtt_conn_parse (read_session, connection)) != RRR_MQTT_OK) {
		RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_MALFORMED_PACKET);
		// Parse might return INCOMPLETE which indicates a malformed packet
		if (ret != RRR_MQTT_INTERNAL_ERROR) {
			ret = RRR_MQTT_SOFT_ERROR;
		}
		goto out;
	}

	if (!RRR_MQTT_PARSE_IS_COMPLETE(&connection->parse_session)) {
		// Unclear who's fault it is if this happens
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
				&read_session->rx_buf_ptr, // Set to NULL if success
				read_session->rx_buf_ptr + connection->parse_session.payload_pos,
				rrr_length_from_biglength_sub_bug_const (read_session->rx_buf_wpos, connection->parse_session.payload_pos)
		);

		RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
		read_session->rx_buf_wpos = 0;

		if (ret != 0) {
			RRR_MSG_0("Could not move payload to packet in __rrr_mqtt_conn_read_complete_callback\n");
			goto out;
		}
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
		goto out;
	}

	out:
	if (ret == RRR_MQTT_SOFT_ERROR) {
		RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_PROTOCOL_ERROR);
	}
	RRR_MQTT_P_DECREF_IF_NOT_NULL(packet);
	return ret;
}

int rrr_mqtt_conn_iterator_ctx_read (
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_step_max_size,
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

	if ((ret = rrr_net_transport_ctx_read_message (
			handle,
			2, // Read only two bytes the first time
			read_step_max_size,
			0, // No max read size
			100 * 1000, // 100 ms ratelimit interval
			(1 * 1024 * 1024) / 20, // 1/20 MB
			__rrr_mqtt_conn_read_get_target_size,
			&callback_data,
			__rrr_mqtt_conn_read_complete_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_RATELIMIT) {
			ret = RRR_SOCKET_READ_INCOMPLETE;
		}
		else if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			RRR_MQTT_CONN_SET_DISCONNECT_REASON_IF_ZERO(connection, RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR);
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_conn_iterator_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_length data_size
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = 0;

	if ((ret = rrr_net_transport_ctx_send_push(handle, data, data_size)) != 0) {
		RRR_MSG_0("Error while pushing packet to send queue in __rrr_mqtt_conn_iterator_ctx_write\n");
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_conn_iterator_ctx_send_push_urgent (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_length data_size
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = 0;

	if ((ret = rrr_net_transport_ctx_send_push_urgent(handle, data, data_size)) != 0) {
		RRR_MSG_0("Error while sending packet in __rrr_mqtt_conn_iterator_ctx_send_urgent\n");
		ret = RRR_MQTT_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

int __rrr_mqtt_connection_create_variable_int (
		uint8_t *target,
		rrr_length *length,
		rrr_biglength value
) {
	*length = 1;

	if (value > 0xfffffff) { // Seven f's
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

static int __rrr_mqtt_conn_iterator_ctx_send_packet (
		int *do_stop,
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet,
		int urgent
) {
	RRR_MQTT_DEFINE_CONN_FROM_HANDLE_AND_CHECK;

	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_p_payload *payload = NULL;
	char *network_data = NULL;
	rrr_length network_size = 0;
	void *send_data = NULL;

	if (!RRR_MQTT_CONN_STATE_SEND_ANY_IS_ALLOWED(connection) && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("BUG: Tried to send PUBLISH while not allowed in __rrr_mqtt_conn_iterator_ctx_send_packet\n");
	}

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
			rrr_free(network_data);
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
	rrr_length variable_int_length = 0;
	rrr_length payload_length = 0;
	payload = packet->payload;
	if (payload != NULL) {
		payload_length = packet->payload->length;
	}

	if ((ret = __rrr_mqtt_connection_create_variable_int (
			header.length,
			&variable_int_length,
			rrr_length_add_bug_const(packet->assembled_data_size, payload_length)
	)) != 0) {
		RRR_MSG_0("Error while creating variable int in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		goto out;
	}
	header.type = (uint8_t) RRR_MQTT_P_GET_TYPE_AND_FLAGS(packet);

	rrr_biglength total_size = 1 + variable_int_length + packet->assembled_data_size + payload_length;

	RRR_DBG_3("Sending packet %p of type %s flen: 1, vlen: %" PRIrrrl ", alen: %" PRIrrrl ", plen: %" PRIrrrl ", total: %" PRIrrrbl ", id: %u, urgent: %i\n",
			packet,
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			variable_int_length,
			packet->assembled_data_size,
			payload_length,
			total_size,
			RRR_MQTT_P_GET_IDENTIFIER(packet),
			urgent
	);

	__rrr_mqtt_connection_update_last_write_time(connection);

	const rrr_biglength send_size = sizeof(header.type) + variable_int_length + packet->assembled_data_size + (payload != NULL ? payload->length : 0);
	if (send_size > RRR_LENGTH_MAX) {
		RRR_BUG("Bug: Send size overflow in rrr_mqtt_conn_iterator_ctx_send_packet (%llu>%llu)\n",
			(unsigned long long) send_size, (unsigned long long) RRR_LENGTH_MAX);
	}

	if ((send_data = rrr_allocate(send_size)) == NULL) {
		RRR_MSG_0("Failed to allocate send data in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		ret = 1;
		goto out;
	}

	void *send_data_pos = send_data;

	memcpy(send_data_pos, (char*) &header, sizeof(header.type) + variable_int_length);
	send_data_pos += sizeof(header.type) + variable_int_length;

	if (packet->assembled_data_size > 0) {
		memcpy(send_data_pos, packet->_assembled_data, packet->assembled_data_size);
		send_data_pos += packet->assembled_data_size;
	}
	else if (payload != NULL) {
		RRR_BUG("Payload was present without variable header in rrr_mqtt_conn_iterator_ctx_send_packet\n");
	}

	if (payload != NULL) {
		if (payload_length == 0) {
			RRR_BUG("Payload size was 0 but payload pointer was not NULL in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		}
		memcpy(send_data_pos, payload->payload_start, payload->length);
	}

	int (*send_method)(
			struct rrr_net_transport_handle *handle,
			void **data,
			rrr_length data_size
	) = (urgent
		? __rrr_mqtt_conn_iterator_ctx_send_push_urgent
		: __rrr_mqtt_conn_iterator_ctx_send_push
	);

	if ((ret = send_method (handle, &send_data, (rrr_length) send_size)) != 0) {
		RRR_MSG_0("Error while pushing data in rrr_mqtt_conn_iterator_ctx_send_packet\n");
		goto out;
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

	if (!urgent && rrr_net_transport_ctx_send_waiting_chunk_limit_factor(handle) >= RRR_MQTT_CONN_SEND_CHUNK_LIMIT_FACTOR) {
		*do_stop = 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(send_data);
	RRR_FREE_IF_NOT_NULL(network_data);
	return ret;
}

int rrr_mqtt_conn_iterator_ctx_send_packet (
		int *do_stop,
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet
) {
	return __rrr_mqtt_conn_iterator_ctx_send_packet (do_stop, handle, packet, 0 /* Not urgent */);
}

int rrr_mqtt_conn_iterator_ctx_send_packet_urgent (
		struct rrr_net_transport_handle *handle,
		struct rrr_mqtt_p *packet
) {
	int do_stop_dummy = 0;

	return __rrr_mqtt_conn_iterator_ctx_send_packet (&do_stop_dummy, handle, packet, 1 /* Urgent */);
}
