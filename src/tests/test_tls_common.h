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

#ifndef RRR_TEST_TLS_COMMON_H
#define RRR_TEST_TLS_COMMON_H

#include "../lib/net_transport/net_transport.h"

extern const char rrr_test_tls_common_request_data[];
extern const char rrr_test_quic_response_data[];

struct rrr_test_tls_common_data {
	char name[16];
	const char *msg_out;
	const char *msg_in;
	struct rrr_net_transport *transport;
	rrr_net_transport_handle transport_handle;
	int stream_blocked;
	int complete_in;
	int complete_out;
};

struct rrr_test_tls_common_data_common {
	struct rrr_test_tls_common_data client;
	struct rrr_test_tls_common_data server;
	uint64_t timeout;
	int round;
	int flags;
};

int rrr_test_tls_common_init (
		struct rrr_test_tls_common_data_common *data,
		const struct rrr_net_transport_config *config_server,
		const struct rrr_net_transport_config *config_client,
		struct rrr_event_queue *queue,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS)
);

int rrr_test_tls_common_dispatch (
		const volatile int *main_running,
		struct rrr_event_queue *event_queue,
		struct rrr_test_tls_common_data_common *data,
		int (*complete_callback)(struct rrr_test_tls_common_data_common *data),
		int (*periodic_callback)(struct rrr_test_tls_common_data_common *data)
);

void rrr_test_tls_common_cleanup (
		struct rrr_test_tls_common_data_common *data
);

#endif /* RRR_TEST_TLS_COMMON_H */
