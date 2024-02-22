/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "test.h"
#include "test_tls.h"
#include "test_tls_common.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/log.h"

static int __rrr_test_quic_read_callback (RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	int ret = 0;

	uint64_t bytes_read = 0;
	char buf[256];

	if ((ret = rrr_net_transport_ctx_read (
			&bytes_read,
			handle,
			buf,
			sizeof(buf)
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			TEST_MSG("rrr_net_transport_ctx_read incomplete read for %s\n", data->name);
			ret = RRR_EVENT_OK;
			goto out;
		}
		TEST_MSG("rrr_net_transport_ctx_read failed for %s: %d\n", data->name, ret);
		goto out;
	}

	if (strlen(data->msg_in) != bytes_read || memcmp(data->msg_in, buf, bytes_read) != 0) {
		TEST_MSG("rrr_net_transport_ctx_read failed for %s: Unexpected data\n", data->name);
		ret = RRR_EVENT_EXIT;
		goto out;
	}

	data->complete_in = 1;

	out:
	return ret;
}

static int __rrr_test_tls_complete_callback (
		struct rrr_test_tls_common_data_common *data
) {
	(void)(data);
	return RRR_EVENT_EXIT;
}

static int __rrr_test_tls_periodic_callback (
		struct rrr_test_tls_common_data_common *data
) {
	int ret = 0;

	(void)(data);

	if (data->client.transport_handle > 0 && !data->client.complete_out) {
		if ((ret = rrr_net_transport_handle_send_push_const (
				data->client.transport,
				data->client.transport_handle,
				data->client.msg_out,
				strlen(data->client.msg_out)
		)) != 0) {
			TEST_MSG("rrr_net_transport_ctx_send_push failed for client: %d\n", ret);
			ret = RRR_EVENT_EXIT;
			goto out;
		}

		data->client.complete_out = 1;
	}

	if (data->server.transport_handle > 0 && !data->server.complete_out) {
		if ((ret = rrr_net_transport_handle_send_push_const (
				data->server.transport,
				data->server.transport_handle,
				data->server.msg_out,
				strlen(data->server.msg_out)
		)) != 0) {
			TEST_MSG("rrr_net_transport_ctx_send_push failed for server: %d\n", ret);
			ret = RRR_EVENT_EXIT;
			goto out;
		}

		data->server.complete_out = 1;
	}

	out:
	return ret;
}

int rrr_test_tls (const volatile int *main_running, struct rrr_event_queue *queue) {
	int ret = 0;

	struct rrr_test_tls_common_data_common data;

	static const struct rrr_net_transport_config config_server = {
		"../../misc/ssl/rrr.crt",
		"../../misc/ssl/rrr.key",
		NULL,
		NULL,
		RRR_NET_TRANSPORT_TLS,
		RRR_NET_TRANSPORT_F_TLS
	};

	static const struct rrr_net_transport_config config_client = {
		NULL,
		NULL,
		"../../misc/ssl/rootca/goliathdns.no.crt",
		"../../misc/ssl/rootca",
		RRR_NET_TRANSPORT_TLS,
		RRR_NET_TRANSPORT_F_TLS
	};

	if ((ret = rrr_test_tls_common_init (
			&data,
			&config_server,
			&config_client,
			queue,
			__rrr_test_quic_read_callback,
			NULL
	)) != 0) {
		goto out;
	}

	ret = rrr_test_tls_common_dispatch (
			main_running,
			queue,
			&data,
			__rrr_test_tls_complete_callback,
			__rrr_test_tls_periodic_callback
	);

	goto out_cleanup_data;
	out_cleanup_data:
		rrr_test_tls_common_cleanup(&data);
	out:
		return ret;
}
