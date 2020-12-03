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

#include <string.h>
#include <stdlib.h>

#include "../log.h"

#include "mqtt_transport.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"

#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"

void rrr_mqtt_transport_destroy (
		struct rrr_mqtt_transport *transport
) {
	if (transport == NULL) {
		return;
	}

	// Memory of individual connections are managed through net transport framework

	rrr_net_transport_collection_destroy(&transport->transports);
	free(transport);
}

int rrr_mqtt_transport_new (
		struct rrr_mqtt_transport **result,
		unsigned int max_connections,
		uint64_t close_wait_time_usec,
		int (*event_handler)(struct rrr_mqtt_conn *connection, int event, void *static_arg, void *arg),
		void *event_handler_arg
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

//	transport->invalid = 1;
	transport->event_handler = event_handler;
	transport->event_handler_static_arg = event_handler_arg;
	transport->max = max_connections;
	transport->close_wait_time_usec = close_wait_time_usec;

	*result = transport;

	goto out;
//	out_destroy_transport_plain:
//		rrr_net_transport_destroy(connections->transport_plain);
	out:
		return ret;
}

int rrr_mqtt_transport_start (
		struct rrr_mqtt_transport *transport,
		const struct rrr_net_transport_config *net_transport_config
) {
	int ret = 0;

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

	RRR_LL_APPEND(&transport->transports, tmp);

	out:
	return ret;
}

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

	RRR_LL_ITERATE_BEGIN(&transport->transports, struct rrr_net_transport);
		if ((ret = rrr_net_transport_accept_all_handles (
				node,
				new_connection_callback,
				&callback_data
		)) != 0) {
//			RRR_MSG_0("Could not accept connections in rrr_mqtt_conn_collection_accept\n");
			goto out;
		}
		if ((*new_transport_handle = callback_data.transport_handle) > 0) {
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

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

	if (RRR_LL_COUNT(&transport->transports) > 1) {
		RRR_DBG_1("Note: More than one transport found in rrr_mqtt_transport_connect, using the first one.\n");
	}

	struct rrr_net_transport *net_transport = RRR_LL_FIRST(&transport->transports);

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

	RRR_LL_ITERATE_BEGIN(&transport->transports, struct rrr_net_transport);
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
	RRR_LL_ITERATE_END();

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

	if (handle->handle == callback_data->transport_handle) {
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

	if (RRR_LL_COUNT(&transport->transports) != 1) {
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

	if (handle->handle == callback_data->transport_handle) {
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
