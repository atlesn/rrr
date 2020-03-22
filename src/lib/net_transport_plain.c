/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../global.h"
#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "net_transport_plain.h"
#include "ip.h"

static int __rrr_net_transport_plain_close (struct rrr_net_transport *transport, int handle) {
	(void)(transport);

	if (rrr_socket_close(handle) != 0) {
		RRR_MSG_ERR("Warning: Error from rrr_socket_close in __rrr_net_transport_plain_close\n");
		return 1;
	}
	return 0;
}

static int __rrr_net_transport_plain_handle_destroy_callback (int handle, void *arg) {
	return __rrr_net_transport_plain_close ((struct rrr_net_transport *) arg, handle);
}

static void __rrr_net_transport_plain_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_plain *plain = (struct rrr_net_transport_plain *) transport;

	rrr_net_transport_handle_collection_clear(&transport->handles, __rrr_net_transport_plain_handle_destroy_callback, transport);

	free(plain);
}

static int __rrr_net_transport_plain_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	(void)(transport);

	int ret = 0;

	*handle = 0;

	struct rrr_ip_accept_data *accept_data = NULL;

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, port, host) != 0) {
		RRR_MSG_ERR("Could not connect to server '%s' port '%u'\n", host, port);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_handle_collection_handle_add(&transport->handles, accept_data->ip_data.fd)) != 0) {
		RRR_MSG_ERR("Could not register handle in __rrr_net_transport_plain_connect\n");
		ret = 1;
		goto out_disconnect;
	}

	*handle = accept_data->ip_data.fd;

	goto out;
	out_disconnect:
		rrr_socket_close(accept_data->ip_data.fd);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

struct plain_read_callback_data {
	int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg);
	void *get_target_size_arg;
	int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg);
	void *complete_callback_arg;
};

static int __rrr_net_transport_plain_read_get_target_size_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct plain_read_callback_data *callback_data = arg;

	int ret = RRR_SOCKET_READ_INCOMPLETE;

	struct rrr_net_transport_read_session net_read_session = {
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			read_session->read_complete_method,
			read_session->target_size
	};

	// rrr_net_transport return values are equal to rrr_socket return values
	ret = callback_data->get_target_size(&net_read_session, callback_data->get_target_size_arg);

	read_session->target_size = net_read_session.target_size;
	read_session->read_complete_method = net_read_session.read_complete_method;

	return ret;
}

static int __rrr_net_transport_plain_read_complete_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct plain_read_callback_data *callback_data = arg;

	struct rrr_net_transport_read_session net_read_session = {
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			read_session->read_complete_method,
			read_session->target_size
	};

	return callback_data->complete_callback(&net_read_session, callback_data->complete_callback_arg);
}

static int __rrr_net_transport_plain_read_message (
	struct rrr_net_transport *transport,
	int transport_handle,
	ssize_t read_step_initial,
	ssize_t read_step_max_size,
	int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *get_target_size_arg,
	int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *complete_callback_arg
) {
	int ret = 0;

	(void)(transport);

	struct rrr_socket_read_session_collection read_sessions;
	rrr_socket_read_session_collection_init(&read_sessions);

	struct plain_read_callback_data callback_data = {
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	};

	for (int i = 1000; i >= 0; i--) {
		ret = rrr_socket_read_message (
				&read_sessions,
				transport_handle,
				read_step_initial,
				read_step_max_size,
				RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_USE_TIMEOUT,
				__rrr_net_transport_plain_read_get_target_size_callback,
				&callback_data,
				__rrr_net_transport_plain_read_complete_callback,
				&callback_data,
				NULL
		);

		if (ret == RRR_SOCKET_OK) {
			// TODO : Check for persistent connection/more results which might be
			//		  stored in read session overshoot buffer
			goto out;
		}
		else if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			RRR_MSG_ERR("Error while reading from server in __rrr_net_transport_plain_read_message\n");
			ret = 1;
			goto out;
		}
	}

	out:
	rrr_socket_read_session_collection_clear(&read_sessions);
	return ret;
}

static int __rrr_net_transport_plain_send (
	struct rrr_net_transport *transport,
	int transport_handle,
	void *data,
	ssize_t size
) {
	int ret = 0;

	(void)(transport);

	if ((ret = rrr_socket_sendto(transport_handle, data, size, NULL, 0)) != 0) {
		RRR_MSG_ERR("Could not send data in  __rrr_net_transport_plain_send\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static const struct rrr_net_transport_methods plain_methods = {
	__rrr_net_transport_plain_destroy,
	__rrr_net_transport_plain_connect,
	__rrr_net_transport_plain_close,
	__rrr_net_transport_plain_read_message,
	__rrr_net_transport_plain_send
};

int rrr_net_transport_plain_new (struct rrr_net_transport_plain **target) {
	struct rrr_net_transport_plain *result = NULL;

	*target = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_net_transport_plain_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->methods = &plain_methods;

	*target = result;

	out:
	return ret;
}

