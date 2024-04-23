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

#include <string.h>
#include <assert.h>

#include "test.h"
#include "test_tls_common.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/net_transport/net_transport_ctx.h"
#include "../lib/net_transport/net_transport_config.h"

#define RRR_TEST_QUIC_FLAGS_STREAM_OPENED (1<<0)

static int __rrr_test_quic_read_stream_callback (RRR_NET_TRANSPORT_READ_STREAM_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("%s stream %" PRIi64 " read %" PRIu64 " bytes\n", data->name, stream_id, buflen);

	if (strlen(data->msg_in) != buflen || memcmp(buf, data->msg_in, buflen) != 0) {
		RRR_MSG_0("Unexpected data in %s\n", __func__);
		return 1;
	}

	if (!fin) {
		RRR_MSG_0("fin missing in %s\n", __func__);
		return 1;
	}

	if (rrr_net_transport_ctx_stream_consume(handle, stream_id, buflen) != 0) {
		RRR_MSG_0("consume failed in %s\n", __func__);
		return 1;
	}

	return 0;
}

static int __rrr_test_quic_read_callback (RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	int ret = 0;

	size_t bytes_read = 0;

	if ((ret = rrr_net_transport_handle_ptr_read_stream (
			&bytes_read,
			handle,
			__rrr_test_quic_read_stream_callback,
			data
	)) != 0) {
		if (ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
			printf("incomplete\n");
			ret = 0;
			goto out;
		}
	}

	data->complete_in = 1;

	out:
	return ret;
}

static int __rrr_test_quic_cb_get_message (RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("%s stream %" PRIi64 " get message complete %i blocked %i\n",
		data->name, stream_id_suggestion, data->complete_out, data->stream_blocked);

	if (data->complete_out || data->stream_blocked || stream_id_suggestion < 0) {
		*data_vector_count = 0;
		*fin = 0;
		*stream_id = -1;
		return 0;
	}

	data_vector[0].base = (uint8_t *) data->msg_out;
	data_vector[0].len = strlen(data->msg_out);

	*stream_id = stream_id_suggestion;
	*data_vector_count = 1;
	*fin = 1;

	return 0;
}

static int __rrr_test_quic_cb_blocked (RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("%s stream %" PRIi64 " blocked: %i\n", data->name, stream_id, is_blocked);

	data->stream_blocked = is_blocked;

	return 0;
}

static int __rrr_test_quic_cb_stream_shutdown_read (RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("%s stream %" PRIi64 " shutdown read\n", data->name, stream_id);

	return 0;
}

static int __rrr_test_quic_cb_stream_shutdown_write (RRR_NET_TRANSPORT_STREAM_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("%s stream %" PRIi64 " shutdown write\n", data->name, stream_id);

	return 0;
}

static int __rrr_test_quic_cb_stream_close (RRR_NET_TRANSPORT_STREAM_CLOSE_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	(void)(handle);

	TEST_MSG("%s stream %" PRIi64 " close reason %" PRIu64 "\n", data->name, stream_id, application_error_reason);

	return 0;
}

static int __rrr_test_quic_cb_write_confirm (RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	(void)(stream_id);
	(void)(arg);

	if (bytes != strlen(data->msg_out)) {
		TEST_MSG("%s stream %" PRIi64 " write message error bytes were %llu expected %llu\n",
			data->name,
			stream_id,
			(unsigned long long) bytes,
			(unsigned long long) strlen(data->msg_out)
		);
		return 1;
	}

	TEST_MSG("%s stream %" PRIi64 " write confirm message %llu bytes\n",
		data->name, stream_id, (unsigned long long) bytes);

	data->complete_out = 1;

	return 0;
}

static int __rrr_test_quic_cb_ack_confirm (RRR_NET_TRANSPORT_STREAM_CONFIRM_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	(void)(stream_id);
	(void)(arg);

	if (bytes != strlen(data->msg_out)) {
		TEST_MSG("%s stream %" PRIi64 " ACK confirm message error bytes were %llu expected %llu\n",
			data->name,
			stream_id,
			(unsigned long long) bytes,
			(unsigned long long) strlen(data->msg_out)
		);
		return 1;
	}

	TEST_MSG("%s stream %" PRIi64 " ACK confirm message %llu bytes\n",
		data->name, stream_id, (unsigned long long) bytes);

	data->complete_out_ack = 1;

	return 0;
}

static int __rrr_test_quic_stream_open_callback (RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS) {
	struct rrr_test_tls_common_data *data = arg_global;

	(void)(stream_data);
	(void)(stream_data_destroy);
	(void)(handle);
	(void)(flags);
	(void)(arg_local);

	*cb_get_message = __rrr_test_quic_cb_get_message;
	*cb_blocked = __rrr_test_quic_cb_blocked;
	*cb_shutdown_read = __rrr_test_quic_cb_stream_shutdown_read;
	*cb_shutdown_write = __rrr_test_quic_cb_stream_shutdown_write;
	*cb_close = __rrr_test_quic_cb_stream_close;
	*cb_write_confirm = __rrr_test_quic_cb_write_confirm;
	*cb_ack_confirm = __rrr_test_quic_cb_ack_confirm;
	*cb_arg = arg_global;

	TEST_MSG("%s stream %" PRIi64 " open local or remote arg %p\n", data->name, stream_id, arg_global);

	return 0;
}

static void __rrr_test_quic_connect_callback (RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS) {
	struct rrr_test_tls_common_data *data = arg;

	TEST_MSG("QUIC connect callback\n");

	rrr_test_tls_common_connect_actions(data, handle, sockaddr, socklen);
}

static int __rrr_test_quic_periodic_callback (
		struct rrr_test_tls_common_data_common *data
) {
	if (!(data->flags & RRR_TEST_QUIC_FLAGS_STREAM_OPENED)) {
		int64_t stream_id;
		switch (rrr_net_transport_handle_stream_open_local (
				&stream_id,
				data->client.transport,
				data->client.transport_handle,
				RRR_NET_TRANSPORT_STREAM_F_LOCAL|RRR_NET_TRANSPORT_STREAM_F_BIDI,
				NULL
		)) {
			case RRR_NET_TRANSPORT_READ_BUSY:
				// OK, try again
				TEST_MSG("Quic busy while opening stream...\n");
				break;
			case RRR_NET_TRANSPORT_READ_OK:
				TEST_MSG("Quic stream %" PRIi64 " opened on client side...\n", stream_id);
				data->flags |= RRR_TEST_QUIC_FLAGS_STREAM_OPENED;
				break;
			default:
				return RRR_EVENT_ERR;
		};
	}

	return RRR_EVENT_OK;
}

static int __rrr_test_quic_complete_callback (
		struct rrr_test_tls_common_data_common *data
) {
	if (data->round++ == 0) {
		TEST_MSG("Quic test migrating client\n");

		data->flags = 0;
		data->client.complete_in = 0;
		data->server.complete_in = 0;
		data->client.complete_out = 0;
		data->server.complete_out = 0;
		data->client.complete_out_ack = 0;
		data->server.complete_out_ack = 0;
		data->client.stream_blocked = 0;
		data->server.stream_blocked = 0;

		if (rrr_net_transport_handle_migrate (
				data->client.transport,
				data->client.transport_handle,
				RRR_TEST_TLS_COMMON_PORT,
				"localhost",
				__rrr_test_quic_connect_callback,
				&data->client
		) != 0) {
			TEST_MSG("Quic test migration failed\n");
			return RRR_EVENT_ERR;
		}
	}
	else {
		TEST_MSG("Quic test completed successfully, cleanup up.\n");
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

int rrr_test_quic (const volatile int *main_running, struct rrr_event_queue *queue) {
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

	struct rrr_test_tls_common_data_common data;

	static const struct rrr_net_transport_config config_server = {
		"../../misc/ssl/rrr.crt",
		"../../misc/ssl/rrr.key",
		NULL,
		NULL,
		RRR_NET_TRANSPORT_QUIC,
		RRR_NET_TRANSPORT_F_QUIC,
		0
	};

	static const struct rrr_net_transport_config config_client = {
		NULL,
		NULL,
		"../../misc/ssl/rootca/goliathdns.no.crt",
		"../../misc/ssl/rootca",
		RRR_NET_TRANSPORT_QUIC,
		RRR_NET_TRANSPORT_F_QUIC,
		0
	};

	if ((ret = rrr_test_tls_common_init (
			&data,
			&config_server,
			&config_client,
			queue,
			__rrr_test_quic_read_callback,
			__rrr_test_quic_stream_open_callback
	)) != 0) {
		goto out;
	}

	ret = rrr_test_tls_common_dispatch (
			main_running,
			queue,
			&data,
			__rrr_test_quic_complete_callback,
			__rrr_test_quic_periodic_callback
	);

	goto out_cleanup_data;
	out_cleanup_data:
		rrr_test_tls_common_cleanup(&data);
	out:
		return ret;
}
