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
#include "read.h"
#include "ip.h"

static int __rrr_net_transport_plain_close (struct rrr_net_transport_handle *handle) {
	if (rrr_socket_close(handle->handle) != 0) {
		RRR_MSG_ERR("Warning: Error from rrr_socket_close in __rrr_net_transport_plain_close\n");
		return 1;
	}
	return 0;
}

static void __rrr_net_transport_plain_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_plain *plain = (struct rrr_net_transport_plain *) transport;

	// This will call back into our close() function for each handle
	rrr_net_transport_common_cleanup(transport);

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

	struct rrr_net_transport_handle *new_handle = NULL;
	if ((ret = rrr_net_transport_handle_add(&new_handle, transport, accept_data->ip_data.fd, NULL)) != 0) {
		RRR_MSG_ERR("Could not register handle in __rrr_net_transport_plain_connect\n");
		ret = 1;
		goto out_disconnect;
	}

	*handle = new_handle->handle;

	goto out;
	out_disconnect:
		rrr_socket_close(accept_data->ip_data.fd);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

struct rrr_net_transport_plain_read_session {
	RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD;
};

static int __rrr_net_transport_plain_read_get_target_size_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_net_transport_plain_read_session *callback_data = arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

static int __rrr_net_transport_plain_read_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_net_transport_plain_read_session *callback_data = arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

static int __rrr_net_transport_plain_read_message (
	struct rrr_net_transport_handle *handle,
	int read_attempts,
	ssize_t read_step_initial,
	ssize_t read_step_max_size,
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
	void *get_target_size_arg,
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
	void *complete_callback_arg
) {
	int ret = 0;

	struct rrr_net_transport_plain_read_session callback_data = {
			handle,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg,
	};

	while (--read_attempts > 0) {
		ret = rrr_socket_read_message_default (
				&handle->read_sessions,
				handle->handle, // Plain method use socked number as transport ID
				read_step_initial,
				read_step_max_size,
				0,
				RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_USE_TIMEOUT,
				__rrr_net_transport_plain_read_get_target_size_callback,
				&callback_data,
				__rrr_net_transport_plain_read_complete_callback,
				&callback_data
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
	return ret;
}

static int __rrr_net_transport_plain_send (
	struct rrr_net_transport_handle *handle,
	void *data,
	ssize_t size
) {
	int ret = 0;

	if ((ret = rrr_socket_sendto(handle->handle, data, size, NULL, 0)) != 0) {
		RRR_MSG_ERR("Could not send data in  __rrr_net_transport_plain_send\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int __rrr_net_transport_plain_bind_and_listen (
		int *listen_handle,
		struct rrr_net_transport *transport,
		unsigned int port
) {
	int ret = 1;
	RRR_BUG("__rrr_net_transport_plain_bind_and_listen not implemented\n");
	return ret;
}

int __rrr_net_transport_plain_accept (
		int *handle,
		struct sockaddr *sockaddr,
		socklen_t *socklen,
		struct rrr_net_transport_handle *listen_handle
) {
	int ret = 1;
	RRR_BUG("__rrr_net_transport_plain_accept not implemented\n");
	return ret;
}

static const struct rrr_net_transport_methods plain_methods = {
	__rrr_net_transport_plain_destroy,
	__rrr_net_transport_plain_connect,
	__rrr_net_transport_plain_bind_and_listen,
	__rrr_net_transport_plain_accept,
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

