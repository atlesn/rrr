/*

Read Route Record

Copyright (C) 2022-2024 Atle Solbakken atle@goliathdns.no

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

#include "test.h"
#include "test_tls_common.h"
#include "../lib/allocator.h"

#define RRR_TEST_TLS_COMMON_PORT 4433
#define RRR_TEST_TLS_COMMON_TIMEOUT_S 5
#define RRR_TEST_TLS_COMMON_PROTOCOL "RRR"
#define RRR_TEST_TLS_COMMON_ALPN_PROTO "\x03" RRR_TEST_TLS_COMMON_PROTOCOL

const char rrr_test_tls_common_request_data[] = "GET /\r\n";
const char rrr_test_tls_common_response_data[] = "MY RESPONSE DATA\r\n";

static const struct rrr_test_tls_common_data_common rrr_test_tls_common_data_common_default = {
	.client = {
		.msg_in = rrr_test_tls_common_response_data,
		.msg_out = rrr_test_tls_common_request_data
	},
	.server = {
		.msg_in = rrr_test_tls_common_request_data,
		.msg_out = rrr_test_tls_common_response_data
	},
	.timeout = 0
};

static void __rrr_test_tls_common_accept_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("TLS accept callback\n");

	data->transport_handle = rrr_net_transport_ctx_get_handle(handle);

	(void)(sockaddr);
	(void)(socklen);
}

static int __rrr_test_tls_common_handshake_complete_client_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);

	TEST_MSG("TLS client handshake complete\n");
	
	return 0;
}

static int __rrr_test_tls_common_handshake_complete_server_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);

	char *alpn_selected_proto = NULL;

	if (rrr_net_transport_ctx_selected_proto_get(&alpn_selected_proto, handle)) {
		return 1;
	}

	if (alpn_selected_proto == NULL) {
		TEST_MSG("TLS server no ALPN selected\n");
		return 1;
	}

	if (strcmp(RRR_TEST_TLS_COMMON_PROTOCOL, alpn_selected_proto) != 0) {
		TEST_MSG("TLS server unexpected ALPN selected (%s vs expected %s)\n",
			alpn_selected_proto, RRR_TEST_TLS_COMMON_PROTOCOL);
		return 1;
	}

	TEST_MSG("TLS server handshake complete selected ALPN is %s\n", alpn_selected_proto);

	rrr_free(alpn_selected_proto);
	return 0;
}

static void __rrr_test_tls_common_bind_and_listen_callback (RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(arg);
}

static void __rrr_test_tls_common_connect_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

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

int rrr_test_tls_common_init (
		struct rrr_test_tls_common_data_common *data,
		const struct rrr_net_transport_config *config_server,
		const struct rrr_net_transport_config *config_client,
		struct rrr_event_queue *queue,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS)
) {
	int ret = 0;

	struct rrr_net_transport *transport_server;
	struct rrr_net_transport *transport_client;

	*data = rrr_test_tls_common_data_common_default;

	data->timeout = rrr_time_get_64() + RRR_TEST_TLS_COMMON_TIMEOUT_S * 1000 * 1000;

	strcpy(data->client.name, "Client");
	strcpy(data->server.name, "Server");

	if ((ret = rrr_net_transport_new (
			&transport_server,
			config_server,
			"tlsserver",
			0,
			queue,
			RRR_TEST_TLS_COMMON_ALPN_PROTO,
			sizeof(RRR_TEST_TLS_COMMON_ALPN_PROTO) - 1,
			5 * 1000,  //  5s first read timeout
			15 * 1000, // 15s soft timeout
			30 * 1000, // 30s hard timeout
			16,        // 16  max send chunks
			__rrr_test_tls_common_accept_callback,
			&data->server,
			__rrr_test_tls_common_handshake_complete_server_callback,
			&data->server,
			read_callback,
			&data->server,
			stream_open_callback,
			&data->server
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_net_transport_new (
			&transport_client,
			config_client,
			"tlsclient",
			0,
			queue,
			RRR_TEST_TLS_COMMON_ALPN_PROTO,
			sizeof(RRR_TEST_TLS_COMMON_ALPN_PROTO) - 1,
			5 * 1000,  //  5s first read timeout
			15 * 1000, // 15s soft timeout
			30 * 1000, // 30s hard timeout
			16,        // 16  max send chunks
			NULL,
			NULL,
			__rrr_test_tls_common_handshake_complete_client_callback,
			&data->client,
			read_callback,
			&data->client,
			stream_open_callback,
			&data->client
	)) != 0) {
		goto out_destroy_transport_server;
	}

	data->client.transport = transport_client;
	data->server.transport = transport_server;

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			transport_server,
			RRR_TEST_TLS_COMMON_PORT,
			__rrr_test_tls_common_bind_and_listen_callback,
			&data->server
	)) != 0) {
		goto out_destroy_transport_client;
	}

	if ((ret = rrr_net_transport_connect (
			transport_client,
			RRR_TEST_TLS_COMMON_PORT,
			"localhost",
			__rrr_test_tls_common_connect_callback,
			&data->client
	)) != 0) {
		goto out_destroy_transport_client;
	}

	goto out;
	out_destroy_transport_client:
		rrr_net_transport_destroy(transport_client);
	out_destroy_transport_server:
		rrr_net_transport_destroy(transport_server);
	out:
	return ret;
}

struct rrr_test_tls_common_periodic_callback_data {
	const volatile int *main_running;
	struct rrr_test_tls_common_data_common *data;
	int (*complete_callback)(struct rrr_test_tls_common_data_common *data);
	int (*periodic_callback)(struct rrr_test_tls_common_data_common *data);
};

static int __rrr_test_tls_common_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_tls_common_periodic_callback_data *cb_data = arg;
	struct rrr_test_tls_common_data_common *data = cb_data->data;

	if (!*cb_data->main_running) {
		TEST_MSG("TLS test aborted\n");
		return RRR_EVENT_ERR;
	}

	if (rrr_time_get_64() > data->timeout) {
		TEST_MSG("TLS test timeout after %i seconds\n", RRR_TEST_TLS_COMMON_TIMEOUT_S);
		return RRR_EVENT_ERR;
	}

	if (data->client.transport_handle > 0) {
		TEST_MSG("TLS notify client handle\n");

		if (rrr_net_transport_handle_notify_read_fast (
				data->client.transport,
				data->client.transport_handle
		) != 0) {
			TEST_MSG("TLS notify failed\n");
			return RRR_EVENT_ERR;
		}
	}

	TEST_MSG("CCI %s SCI %s CCO %s SCO %s\n",
		data->client.complete_in ? "Y" : "-",
		data->server.complete_in ? "Y" : "-",
		data->client.complete_out ? "Y" : "-",
		data->server.complete_out ? "Y" : "-"
	);

	if ( data->client.complete_in &&
	     data->server.complete_in &&
	     data->client.complete_out &&
	     data->server.complete_out
	) {
		return cb_data->complete_callback(data);
	}

	return cb_data->periodic_callback(data);
}

int rrr_test_tls_common_dispatch (
		const volatile int *main_running,
		struct rrr_event_queue *event_queue,
		struct rrr_test_tls_common_data_common *data,
		int (*complete_callback)(struct rrr_test_tls_common_data_common *data),
		int (*periodic_callback)(struct rrr_test_tls_common_data_common *data)
) {
	struct rrr_test_tls_common_periodic_callback_data cb_data = {
		.main_running = main_running,
		.data = data,
		.complete_callback = complete_callback,
		.periodic_callback = periodic_callback
	};

	return rrr_event_dispatch (
			event_queue,
			250 * 1000, // 250 ms
			__rrr_test_tls_common_periodic,
			&cb_data
	);
}

void rrr_test_tls_common_cleanup (
		struct rrr_test_tls_common_data_common *data
) {
	rrr_net_transport_destroy(data->client.transport);
	rrr_net_transport_destroy(data->server.transport);
}
