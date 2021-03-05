/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdlib.h>

#include "../log.h"

#include "mqtt_transport.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"

#include "../event.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"

void rrr_mqtt_transport_cleanup (
		struct rrr_mqtt_transport *transport
) {
	for (size_t i = 0; i < transport->transport_count; i++) {
		rrr_net_transport_common_cleanup(transport->transports[i]);
	}
}

void rrr_mqtt_transport_destroy (
		struct rrr_mqtt_transport *transport
) {
	if (transport == NULL) {
		return;
	}

	// Memory of individual connections are managed through net transport framework

	for (size_t i = 0; i < transport->transport_count; i++) {
		rrr_net_transport_destroy(transport->transports[i]);
	}

	free(transport);
}

int rrr_mqtt_transport_new (
		struct rrr_mqtt_transport **result,
		unsigned int max_connections,
		uint64_t close_wait_time_usec,
		struct rrr_event_queue *queue,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_arg,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg
) {
	int ret = RRR_MQTT_OK;

	*result = NULL;

	struct rrr_mqtt_transport *transport = malloc(sizeof(*transport));

	if (transport == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_transport_new\n");
		ret = 1;
		goto out;
	}

	memset (transport, '\0', sizeof(*transport));

	transport->event_handler = event_handler;
	transport->event_handler_static_arg = event_handler_arg;
	transport->queue = queue;
	transport->accept_callback = accept_callback;
	transport->read_callback = read_callback;
	transport->read_callback_arg = read_callback_arg;
	transport->max = max_connections;
	transport->close_wait_time_usec = close_wait_time_usec;

	*result = transport;

	out:
	return ret;
}

static void __rrr_mqtt_transport_accept_callback (
		RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS
) {
	struct rrr_mqtt_transport *transport = arg;

	printf("Accept callback %p\n", transport->accept_callback);

	struct rrr_mqtt_common_accept_and_connect_callback_data callback_data = {
			0,
			transport->close_wait_time_usec,
			transport->event_handler,
			transport->event_handler_static_arg
	};

	transport->accept_callback(handle, sockaddr, socklen, &callback_data);
}

int rrr_mqtt_transport_start (
		struct rrr_mqtt_transport *transport,
		const struct rrr_net_transport_config *net_transport_config
) {
	int ret = 0;

	if (transport->transport_count == RRR_MQTT_TRANSPORT_MAX) {
		RRR_MSG_0("Too many transports in rrr_mqtt_transport_start\n");
		ret = 1;
		goto out;
	}

	struct rrr_net_transport *tmp = NULL;

	if (net_transport_config->transport_type == RRR_NET_TRANSPORT_TLS) {
		if ((ret = rrr_net_transport_new (
				&tmp,
				net_transport_config,
				RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1,
				NULL,
				0
		)) != 0) {
			RRR_MSG_0("Could not initialize TLS network type in rrr_mqtt_transport_start_tls\n");
			goto out;
		}
	}
	else if (net_transport_config->transport_type == RRR_NET_TRANSPORT_PLAIN) {
		if ((ret = rrr_net_transport_new (
				&tmp,
				net_transport_config,
				0,
				NULL,
				0
		)) != 0) {
			RRR_MSG_0("Could not initialize plain network type in rrr_mqtt_transport_start_plain\n");
			goto out;
		}
	}
	else {
		RRR_BUG("BUG: Unknown transport type %i to rrr_mqtt_transport_start\n", net_transport_config->transport_type);
	}

	transport->transports[transport->transport_count++] = tmp;

	if ((ret = rrr_net_transport_event_setup (
			tmp,
			transport->queue,
			0, // TODO : Set timers?
			0,
			__rrr_mqtt_transport_accept_callback,
			transport,
			transport->read_callback,
			transport->read_callback_arg
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

#define RRR_MQTT_TRANSPORT_FOREACH_BEGIN()                                      \
	for (size_t i = 0; i < transport->transport_count; i++) {               \
		struct rrr_net_transport *node = transport->transports[i];

int rrr_mqtt_transport_accept (
		int *new_transport_handle,
		struct rrr_mqtt_transport *transport,
		void (*new_connection_callback)(
				struct rrr_net_transport_handle *handle,
				const struct sockaddr *sockaddr,
				socklen_t socklen,
				void *rrr_mqtt_common_accept_and_connect_callback_data
		)
) {
	int ret = RRR_MQTT_OK;

	*new_transport_handle = 0;

	struct rrr_mqtt_common_accept_and_connect_callback_data callback_data = {
			0,
			transport->close_wait_time_usec,
			transport->event_handler,
			transport->event_handler_static_arg
	};

	RRR_MQTT_TRANSPORT_FOREACH_BEGIN();
		if ((ret = rrr_net_transport_accept_all_handles (
				node,
				0, // Accept any number of connections
				new_connection_callback,
				&callback_data
		)) != 0) {
//			RRR_MSG_0("Could not accept connections in rrr_mqtt_conn_collection_accept\n");
			goto out;
		}
		if ((*new_transport_handle = callback_data.transport_handle) > 0) {
			break;
		}
	}

	out:
		return ret;
}

int rrr_mqtt_transport_connect (
		int *new_transport_handle,
		struct rrr_mqtt_transport *transport,
		unsigned int port,
		const char *host,
		void (*new_connection_callback)(
				struct rrr_net_transport_handle *handle,
				const struct sockaddr *sockaddr,
				socklen_t socklen,
				void *rrr_mqtt_common_accept_and_connect_callback_data
		)
) {
	int ret = RRR_MQTT_OK;

	*new_transport_handle = 0;

	struct rrr_mqtt_common_accept_and_connect_callback_data callback_data = {
			0,
			transport->close_wait_time_usec,
			transport->event_handler,
			transport->event_handler_static_arg
	};

	if (transport->transport_count > 1) {
		RRR_DBG_1("Note: More than one transport found in rrr_mqtt_transport_connect, using the first one.\n");
	}

	struct rrr_net_transport *net_transport = transport->transports[0];

	if (net_transport == NULL) {
		RRR_BUG("BUG: No transports started in rrr_mqtt_transport_connect\n");
	}

	if ((ret = rrr_net_transport_connect (
			net_transport,
			port,
			host,
			new_connection_callback,
			&callback_data
	)) != 0) {
		goto out;

	}

	*new_transport_handle = callback_data.transport_handle;

	out:
		return ret;
}

int rrr_mqtt_transport_iterate (
		struct rrr_mqtt_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *callback_arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_MQTT_TRANSPORT_FOREACH_BEGIN();
		ret |= rrr_net_transport_iterate_with_callback (
				node,
				mode,
				callback,
				callback_arg
		);
		if ((ret & RRR_MQTT_INTERNAL_ERROR) != 0) {
			RRR_MSG_0("Internal error in rrr_mqtt_transport_iterate\n");
			goto out;
		}
	}

	ret = 0;

	out:
	return ret;
}

struct with_iterator_ctx_do_custom_callback_data {
		int transport_handle;
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg);
		void *callback_arg;
		int connection_found;
};

static int __rrr_mqtt_transport_with_iterator_ctx_do_custom_callback (
		struct rrr_net_transport_handle *handle,
		void *callback_arg
) {
	int ret = RRR_MQTT_OK;

	struct with_iterator_ctx_do_custom_callback_data *callback_data = callback_arg;

	if (RRR_NET_TRANSPORT_CTX_HANDLE(handle) == callback_data->transport_handle) {
		callback_data->connection_found = 1;
		ret = callback_data->callback(handle, callback_data->callback_arg);
	}

	return ret;
}

int rrr_mqtt_transport_with_iterator_ctx_do_custom (
		struct rrr_mqtt_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_OK;

	struct with_iterator_ctx_do_custom_callback_data callback_data = {
			transport_handle,
			callback,
			callback_arg,
			0
	};

	if (transport->transport_count != 1) {
		RRR_BUG("BUG: Number of transports was not exactly 1 in rrr_mqtt_transport_with_iterator_ctx_do_custom\n");
	}

	ret = rrr_mqtt_transport_iterate (
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_mqtt_transport_with_iterator_ctx_do_custom_callback,
			&callback_data
	);

	if (callback_data.connection_found != 1) {
		RRR_MSG_0("Connection not found in rrr_mqtt_transport_with_iterator_ctx_do_custom\n");
		ret = RRR_MQTT_SOFT_ERROR;
	}

	return ret;
}

struct with_iterator_ctx_do_callback_data {
	int transport_handle;
	struct rrr_mqtt_p *packet;
	int (*callback)(struct rrr_net_transport_handle *handle, struct rrr_mqtt_p *packet);
};

static int __rrr_mqtt_transport_with_iterator_ctx_do_callback (
		struct rrr_net_transport_handle *handle,
		void *callback_arg
) {
	struct with_iterator_ctx_do_callback_data *callback_data = callback_arg;

	int ret = RRR_MQTT_OK;

	if (RRR_NET_TRANSPORT_CTX_HANDLE(handle) == callback_data->transport_handle) {
		struct with_iterator_ctx_do_callback_data *callback_data = callback_arg;
		ret = callback_data->callback(handle, callback_data->packet);
	}

	return ret;
}

int rrr_mqtt_transport_with_iterator_ctx_do_packet (
		struct rrr_mqtt_transport *transport,
		int transport_handle,
		struct rrr_mqtt_p *packet,
		int (*callback)(struct rrr_net_transport_handle *handle, struct rrr_mqtt_p *packet)
) {
	int ret = RRR_MQTT_OK;

	struct with_iterator_ctx_do_callback_data callback_data = {
			transport_handle,
			packet,
			callback
	};

	ret = rrr_mqtt_transport_iterate (
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_mqtt_transport_with_iterator_ctx_do_callback,
			&callback_data
	);

	return ret;
}
