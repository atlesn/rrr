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
#include "../lib/net_transport/net_transport.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/event/event.h"
#include "../lib/util/rrr_time.h"

#define RRR_TEST_QUIC_ALPN_PROTO "\x03RRR"
#define RRR_TEST_QUIC_PORT 4433
//#define RRR_TEST_QUIC_PORT 5555
#define RRR_TEST_QUIC_TIMEOUT_S 5

struct rrr_test_quic_data {
	const char *msg_out;
	const char *msg_in;
	int send_now;
	int send_acked;
	int complete_in;
	int complete_out;
};

struct rrr_test_quic_data_common {
	struct rrr_test_quic_data client;
	struct rrr_test_quic_data server;
	uint64_t timeout;
};

static const char rrr_test_quic_request_data[] = "GET /\r\n";
static const char rrr_test_quic_response_data[] = "MY RESPONSE DATA\r\n";

static void __rrr_test_quic_accept_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(sockaddr);
	(void)(socklen);
	(void)(arg);
}

static void __rrr_test_quic_handshake_complete_client_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	(void)(handle);

	data->send_now = 1;
}

static void __rrr_test_quic_handshake_complete_server_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);
}

static int __rrr_test_quic_read_callback (RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS) {
	struct rrr_test_quic_data *data = arg;

	int ret = 0;

	char buf[65535];
	uint64_t bytes_read = 0;
	int64_t stream_id = 0;

	if ((ret = rrr_net_transport_ctx_read (
			&bytes_read,
			&stream_id,
			handle,
			buf,
			sizeof(buf)
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			assert(bytes_read == 0 && stream_id == 0);
			ret = 0;
			goto out;
		}
	}

	TEST_MSG("Read %" PRIu64 " stream id %" PRIi64 "\n", bytes_read, stream_id);

	if (bytes_read != strlen(data->msg_in) && memcmp(buf, data->msg_in, bytes_read) != 0) {
		RRR_MSG_0("Unexpected data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	data->complete_in = 1;
	if (!data->complete_out) {
		data->send_now = 1;
	}

	out:
	return ret;
}

static int __rrr_test_quic_cb_get_message (RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	if (data->send_now && !data->send_acked) {
		*data_vector_count = 0;
		*fin = 0;
		*stream_id = -1;
		return 0;
	}

	TEST_MSG("Stream get message %li\n", *stream_id);

	data_vector[0].base = (uint8_t *) data->msg_out;
	data_vector[0].len = strlen(data->msg_out);

	*data_vector_count = 1;
	*fin = 1;

	return 0;
}

static int __rrr_test_quic_cb_blocked (RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS) {
	(void)(stream_id);
	(void)(arg);

	TEST_MSG("Stream blocked: %i", is_blocked);

	return 0;
}

static int __rrr_test_quic_cb_ack (RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS) {
	struct rrr_test_quic_data *data = arg;

	(void)(stream_id);
	(void)(arg);

	if (bytes != strlen(data->msg_out)) {
		TEST_MSG("Stream ACK message %li error bytes were %llu expected %llu\n",
			stream_id, (unsigned long long) bytes, (unsigned long long) strlen(data->msg_out));
		return 1;
	}

	TEST_MSG("Stream ACK message %li bytes %llu\n",
		stream_id, (unsigned long long) bytes);

	data->send_acked = 1;
	data->complete_out = 1;

	return 0;
}

static int __rrr_test_quic_stream_open_callback (RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS) {
	(void)(handle);

	*cb_get_message = __rrr_test_quic_cb_get_message;
	*cb_blocked = __rrr_test_quic_cb_blocked;
	*cb_ack = __rrr_test_quic_cb_ack;
	*cb_arg = arg;

	TEST_MSG("Stream open remote %li\n", stream_id);

	return 0;
}

static void __rrr_test_quic_bind_and_listen_callback (RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(arg);
}

static void __rrr_test_quic_connect_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(sockaddr);
	(void)(socklen);
	(void)(arg);
}

static int __rrr_test_quic_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_quic_data_common *data = arg;

	if (rrr_time_get_64() > data->timeout) {
		TEST_MSG("QUIC test timeout after %i seconds\n", RRR_TEST_QUIC_TIMEOUT_S);
		return RRR_EVENT_ERR;
	}

	if ( data->client.complete_in &&
	     data->server.complete_in &&
	     data->client.complete_out &&
	     data->server.complete_out
	) {
		TEST_MSG("QUIC test completed successfully\n");
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

int rrr_test_quic (void) {
	struct rrr_event_queue *queue;
	struct rrr_net_transport *transport_server;
	struct rrr_net_transport *transport_client;

	int ret = 0;

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
			NULL
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
