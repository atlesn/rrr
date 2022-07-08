/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <string.h>
#include <assert.h>

#include "test.h"
#include "../lib/allocator.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/net_transport/net_transport_ctx.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/event/event.h"
#include "../lib/util/rrr_time.h"

#define RRR_TEST_QUIC_PROTOCOL "RRR"
#define RRR_TEST_QUIC_ALPN_PROTO "\x03" RRR_TEST_QUIC_PROTOCOL
#define RRR_TEST_QUIC_PORT 4433
//#define RRR_TEST_QUIC_PORT 5555
#define RRR_TEST_QUIC_TIMEOUT_S 5

struct rrr_test_quic_data {
	const char *msg_out;
	const char *msg_in;
	struct rrr_net_transport *transport;
	rrr_net_transport_handle transport_handle;
	int stream_blocked;
	int complete_in;
	int complete_out;
};

struct rrr_test_quic_data_common {
	struct rrr_test_quic_data client;
	struct rrr_test_quic_data server;
	uint64_t timeout;
	int round;
	int stream_opened;
};

static const char rrr_test_quic_request_data[] = "GET /\r\n";
static const char rrr_test_quic_response_data[] = "MY RESPONSE DATA\r\n";

static void __rrr_test_quic_accept_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(sockaddr);
	(void)(socklen);
	(void)(arg);
}

static int __rrr_test_quic_handshake_complete_client_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);

	TEST_MSG("Quic client handshake complete\n");
	
	return 0;
}

static int __rrr_test_quic_handshake_complete_server_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);

	char *alpn_selected_proto = NULL;

	if (rrr_net_transport_ctx_selected_proto_get(&alpn_selected_proto, handle)) {
		return 1;
	}

	if (alpn_selected_proto == NULL) {
		TEST_MSG("Quic server no ALPN selected\n");
		return 1;
	}

	if (strcmp(RRR_TEST_QUIC_PROTOCOL, alpn_selected_proto) != 0) {
		TEST_MSG("Quic server unexpected ALPN selected (%s vs expected %s)\n",
			alpn_selected_proto, RRR_TEST_QUIC_PROTOCOL);
		return 1;
	}

	TEST_MSG("Quic server handshake complete selected ALPN is %s\n", alpn_selected_proto);

	rrr_free(alpn_selected_proto);
	return 0;
}

static int __rrr_test_quic_read_stream_callback (RRR_NET_TRANSPORT_READ_STREAM_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	TEST_MSG("Stream %" PRIi64 " read %" PRIu64 " bytes\n", stream_id, buflen);

	if (buflen != strlen(data->msg_in) && memcmp(buf, data->msg_in, buflen) != 0) {
		RRR_MSG_0("Unexpected data in %s\n", __func__);
		return 1;
	}

	if (!fin) {
		RRR_MSG_0("fin missing in %s\n", __func__);
		return 1;
	}

	*consumed = buflen;

	return 0;
}

static int __rrr_test_quic_read_callback (RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS) {
	struct rrr_test_quic_data *data = arg;

	int ret = 0;

	size_t bytes_read = 0;

	if ((ret = rrr_net_transport_handle_ptr_read_stream (
			&bytes_read,
			handle,
			__rrr_test_quic_read_stream_callback,
			data
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			ret = 0;
			goto out;
		}
	}

	data->complete_in = 1;

	out:
	return ret;
}

static int __rrr_test_quic_cb_get_message (RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	if (data->complete_out || data->stream_blocked) {
		*data_vector_count = 0;
		*fin = 0;
		*stream_id = -1;
		return 0;
	}

	TEST_MSG("Stream %" PRIi64 " get message\n", *stream_id);

	data_vector[0].base = (uint8_t *) data->msg_out;
	data_vector[0].len = strlen(data->msg_out);

	*data_vector_count = 1;
	*fin = 1;

	return 0;
}

static int __rrr_test_quic_cb_blocked (RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	TEST_MSG("Stream %" PRIi64 " %i blocked\n", stream_id, is_blocked);

	data->stream_blocked = is_blocked;

	return 0;
}

static int __rrr_test_quic_cb_ack (RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	(void)(stream_id);
	(void)(arg);

	if (bytes != strlen(data->msg_out)) {
		TEST_MSG("Stream %" PRIi64 " ACK message error bytes were %llu expected %llu\n",
			stream_id,
			(unsigned long long) bytes,
			(unsigned long long) strlen(data->msg_out)
		);
		return 1;
	}

	TEST_MSG("Stream %" PRIi64 " ACK message %llu bytes\n",
		stream_id, (unsigned long long) bytes);

	data->complete_out = 1;

	return 0;
}

static int __rrr_test_quic_stream_open_callback (RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS) {
	(void)(transport);
	(void)(handle);
	(void)(flags);

	*cb_get_message = __rrr_test_quic_cb_get_message;
	*cb_blocked = __rrr_test_quic_cb_blocked;
	*cb_ack = __rrr_test_quic_cb_ack;
	*cb_arg = arg;

	TEST_MSG("Stream %" PRIi64 " open local or remote arg %p\n", stream_id, arg);

	return 0;
}

static void __rrr_test_quic_bind_and_listen_callback (RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(arg);
}

static void __rrr_test_quic_connect_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	struct rrr_test_quic_data *data = arg;

	(void)(socklen);

	data->transport_handle = rrr_net_transport_ctx_get_handle(handle);

	if (sockaddr->sa_family == AF_INET) {
		assert(socklen == sizeof(struct sockaddr_in));
	}
	else if (sockaddr->sa_family == AF_INET6) {
		assert(socklen == sizeof(struct sockaddr_in6));
	}
	else {
		RRR_BUG("Unknown family %i in %s\n", sockaddr->sa_family, __func__);
	}
}

static int __rrr_test_quic_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_quic_data_common *data = arg;

	if (rrr_time_get_64() > data->timeout) {
		TEST_MSG("Quic test timeout after %i seconds\n", RRR_TEST_QUIC_TIMEOUT_S);
		return RRR_EVENT_ERR;
	}

	if ( data->client.complete_in &&
	     data->server.complete_in &&
	     data->client.complete_out &&
	     data->server.complete_out
	) {
		if (data->round++ == 0) {
			TEST_MSG("Quic test migrating client\n");

			data->stream_opened = 0;
			data->client.complete_in = 0;
			data->server.complete_in = 0;
			data->client.complete_out = 0;
			data->server.complete_out = 0;
			data->client.stream_blocked = 0;
			data->server.stream_blocked = 0;

			if (rrr_net_transport_handle_migrate (
					data->client.transport,
					data->client.transport_handle,
					RRR_TEST_QUIC_PORT,
					"localhost",
					__rrr_test_quic_connect_callback,
					data
			) != 0) {
				TEST_MSG("Quic test migration failed\n");
				return RRR_EVENT_ERR;
			}
		}
		else {
			TEST_MSG("Quic test completed successfully, cleanup up.\n");
			return RRR_EVENT_EXIT;
		}
	}

	if (!data->stream_opened) {
		int64_t stream_id;
		switch (rrr_net_transport_handle_stream_open (
				&stream_id,
				data->client.transport,
				data->client.transport_handle,
				RRR_NET_TRANSPORT_STREAM_F_LOCAL|RRR_NET_TRANSPORT_STREAM_F_BIDI,
				NULL,
				NULL
		)) {
			case RRR_NET_TRANSPORT_READ_BUSY:
				// OK, try again
				TEST_MSG("Quic busy while opening stream...\n");
				break;
			case RRR_NET_TRANSPORT_READ_OK:
				TEST_MSG("Quic stream %" PRIi64 " opened...\n", stream_id);
				data->stream_opened = 1;
				break;
			default:
				return RRR_EVENT_ERR;
		};
	}

	return RRR_EVENT_OK;
}

int rrr_test_quic (void) {
	struct rrr_event_queue *queue;
	struct rrr_net_transport *transport_server;
	struct rrr_net_transport *transport_client;

	int ret = 0;

	/*
	 * TEST DESCRIPTION
	 *
	 * 1. Server starts listening and client connects. Client is bound to 0 (any) local address.
	 *
	 * 2. When client sees the first response from the server, the actual local address will
	 *    be set in the client path (local rebind).
	 *
	 * 3. Client opens a stream and sends data to the server.
	 *
	 * 4. When the correct response from the server arrives, the client initiates a dummy migration
	 *    back to the 0 (any) local address. This triggers path validation.
	 *
	 * 5. Once the path validation arrives at the client, local rebind is triggered again to the
	 *    actual local address.
	 *
	 * 6. Client opens a stream and sends data to the server and awaits correct response once again.
	 *  
	 */

	if ((ret = rrr_event_queue_new(&queue)) != 0) {
		goto out;
	}

	struct rrr_test_quic_data_common data = {
		.client = {
			.msg_in = rrr_test_quic_response_data,
			.msg_out = rrr_test_quic_request_data
		},
		.server = {
			.msg_in = rrr_test_quic_request_data,
			.msg_out = rrr_test_quic_response_data
		},
		.timeout = rrr_time_get_64() + RRR_TEST_QUIC_TIMEOUT_S * 1000 * 1000
	};

	static const struct rrr_net_transport_config config_server = {
		"../../misc/ssl/rrr.crt",
		"../../misc/ssl/rrr.key",
		NULL, //"../../misc/ssl/rootca/goliathdns.no.crt",
		NULL, //"../../misc/ssl/rootca",
		"RRR QUIC",
		RRR_NET_TRANSPORT_QUIC
	};

	static const struct rrr_net_transport_config config_client = {
		NULL,
		NULL,
		"../../misc/ssl/rootca/goliathdns.no.crt",
		"../../misc/ssl/rootca",
		"RRR QUIC",
		RRR_NET_TRANSPORT_QUIC
	};

	if ((ret = rrr_net_transport_new (
			&transport_server,
			&config_server,
			"quicserver",
			0,
			queue,
			RRR_TEST_QUIC_ALPN_PROTO,
			sizeof(RRR_TEST_QUIC_ALPN_PROTO) - 1,
			5 * 1000,  //  5s first read timeout
			15 * 1000, // 15s soft timeout
			30 * 1000, // 30s hard timeout
			16,        // 16  max send chunks
			__rrr_test_quic_accept_callback,
			&data.server,
			__rrr_test_quic_handshake_complete_server_callback,
			&data.server,
			__rrr_test_quic_read_callback,
			&data.server,
			__rrr_test_quic_stream_open_callback,
			&data.server
	)) != 0) {
		goto out_destroy_queue;
	}

	if ((ret = rrr_net_transport_new (
			&transport_client,
			&config_client,
			"quicclient",
			0,
			queue,
			RRR_TEST_QUIC_ALPN_PROTO,
			sizeof(RRR_TEST_QUIC_ALPN_PROTO) - 1,
			5 * 1000,  //  5s first read timeout
			15 * 1000, // 15s soft timeout
			30 * 1000, // 30s hard timeout
			16,        // 16  max send chunks
			__rrr_test_quic_accept_callback,
			&data.client,
			__rrr_test_quic_handshake_complete_client_callback,
			&data.client,
			__rrr_test_quic_read_callback,
			&data.client,
			__rrr_test_quic_stream_open_callback,
			&data.client
	)) != 0) {
		goto out_destroy_transport_server;
	}

	data.client.transport = transport_client;
	data.server.transport = transport_server;

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			transport_server,
			RRR_TEST_QUIC_PORT,
			__rrr_test_quic_bind_and_listen_callback,
			NULL
	)) != 0) {
		goto out_destroy_transport_client;
	}

	if ((ret = rrr_net_transport_connect (
			transport_client,
			RRR_TEST_QUIC_PORT,
			"localhost",
			__rrr_test_quic_connect_callback,
			&data.client
	)) != 0) {
		goto out_destroy_transport_client;
	}

	ret = rrr_event_dispatch (
			queue,
			250 * 1000, // 250 ms
			__rrr_test_quic_periodic,
			&data
	);

	goto out_destroy_transport_client;
	out_destroy_transport_client:
		rrr_net_transport_destroy(transport_client);
	out_destroy_transport_server:
		rrr_net_transport_destroy(transport_server);
	out_destroy_queue:
		rrr_event_queue_destroy(queue);
	out:
		return ret;
}
