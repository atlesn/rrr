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

#include "test.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/event/event.h"

#define RRR_TEST_QUIC_ALPN_PROTO "\x03RRR"
#define RRR_TEST_QUIC_PORT 4433
//#define RRR_TEST_QUIC_PORT 5555
#define RRR_TEST_QUIC_TIMEOUT_S 5

struct rrr_test_quic_data {
	char a;
};

static void __rrr_test_quic_accept_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(sockaddr);
	(void)(socklen);
	(void)(arg);
	printf("Accept callback\n");
}

static void __rrr_test_quic_handshake_complete_callback (RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS) {
	(void)(handle);
	(void)(arg);
}

static int __rrr_test_quic_read_callback (RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(arg);
	return 1;
}

static void __rrr_test_quic_bind_and_listen_callback (RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS) {
	(void)(handle);
	(void)(arg);
}

static int __rrr_test_quic_periodic(RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	(void)(arg);

	RRR_MSG_0("Timeout in QUIC test after %i seconds\n", RRR_TEST_QUIC_TIMEOUT_S);

	return 1;
}

int rrr_test_quic (void) {
	struct rrr_event_queue *queue;
	struct rrr_net_transport *transport_server;

	int ret = 0;

	struct rrr_test_quic_data data = {0};

	if ((ret = rrr_event_queue_new(&queue)) != 0) {
		goto out;
	}

	static const struct rrr_net_transport_config config_server = {
		"../../misc/ssl/rrr.crt",
		"../../misc/ssl/rrr.key",
		"../../misc/ssl/rootca/goliathdns.no.crt",
		"../../misc/ssl/rootca",
		"RRR QUIC",
		RRR_NET_TRANSPORT_QUIC
	};

	if ((ret = rrr_net_transport_new (
			&transport_server,
			&config_server,
			"quictest",
			0,
			queue,
			RRR_TEST_QUIC_ALPN_PROTO,
			sizeof(RRR_TEST_QUIC_ALPN_PROTO) - 1,
			5 * 1000,  //  5s first read timeout
			15 * 1000, // 15s soft timeout
			30 * 1000, // 30s hard timeout
			16,        // 16  max send chunks
			__rrr_test_quic_accept_callback,
			&data,
			__rrr_test_quic_handshake_complete_callback,
			&data,
			__rrr_test_quic_read_callback,
			&data
	)) != 0) {
		goto out_destroy_queue;
	}

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			transport_server,
			RRR_TEST_QUIC_PORT,
			__rrr_test_quic_bind_and_listen_callback,
			&data
	)) != 0) {
		goto out_destroy_transport_server;
	}

	ret = rrr_event_dispatch (
			queue,
			RRR_TEST_QUIC_TIMEOUT_S * 1000 * 1000,
			__rrr_test_quic_periodic,
			&data
	);

	goto out_destroy_transport_server;
	out_destroy_transport_server:
		rrr_net_transport_destroy(transport_server);
	out_destroy_queue:
		rrr_event_queue_destroy(queue);
	out:
		return ret;
}
