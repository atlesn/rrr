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
#include <poll.h>
#include <limits.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "net_transport_plain.h"

#include "../log.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_read.h"
#include "../read.h"
#include "../ip/ip.h"
#include "../ip/ip_util.h"
#include "../ip/ip_accept_data.h"
#include "../util/macro_utils.h"

static void __rrr_net_transport_plain_data_destroy (struct rrr_net_transport_plain_data *data) {
	RRR_FREE_IF_NOT_NULL(data);
}

static int __rrr_net_transport_plain_data_new (struct rrr_net_transport_plain_data **result) {
	*result = NULL;

	struct rrr_net_transport_plain_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_net_transport_plain_data_new\n");
		return 1;
	}

	memset(data, '\0', sizeof(*data));

	*result = data;

	return 0;
}

static int __rrr_net_transport_plain_close (struct rrr_net_transport_handle *handle) {
	if (rrr_socket_close(handle->submodule_private_fd) != 0) {
		RRR_MSG_0("Warning: Error from rrr_socket_close in __rrr_net_transport_plain_close\n");
	}
	__rrr_net_transport_plain_data_destroy (handle->submodule_private_ptr);
	return 0;
}

static void __rrr_net_transport_plain_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_plain *plain = (struct rrr_net_transport_plain *) transport;
	free(plain);
}

struct rrr_net_transport_plain_allocate_and_add_callback_data {
	const struct rrr_ip_data *ip_data;
};

static int __rrr_net_transport_plain_handle_allocate_and_add_callback (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS
) {
	struct rrr_net_transport_plain_allocate_and_add_callback_data *callback_data = arg;

	struct rrr_net_transport_plain_data *data = NULL;
	if (__rrr_net_transport_plain_data_new(&data) != 0) {
		return 1;
	}

	data->ip_data = *(callback_data->ip_data);

	*submodule_private_ptr = data;
	*submodule_private_fd = callback_data->ip_data->fd;

	return 0;
}

static int __rrr_net_transport_plain_connect (
		RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	(void)(transport);

	*handle = 0;

	int ret = 0;

	struct rrr_ip_accept_data *accept_data = NULL;

	if (*socklen < sizeof(accept_data->addr)) {
		RRR_BUG("BUG: socklen too small in __rrr_net_transport_plain_connect\n");
	}

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, port, host, NULL) != 0) {
		RRR_DBG_1("Could not connect to server '%s' port '%u'\n", host, port);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	struct rrr_net_transport_plain_allocate_and_add_callback_data callback_data = {
			&accept_data->ip_data
	};

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_net_transport_plain_handle_allocate_and_add_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not register handle in __rrr_net_transport_plain_connect\n");
		ret = 1;
		goto out_disconnect;
	}

	memcpy(addr, &accept_data->addr, accept_data->len);
	*socklen = accept_data->len;

	*handle = new_handle;

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
		RRR_NET_TRANSPORT_READ_MESSAGE_ARGS
) {
	int ret = 0;

	*bytes_read = 0;

	struct rrr_net_transport_plain_read_session callback_data = {
			handle,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg,
	};

	while (--read_attempts >= 0) {
		uint64_t bytes_read_tmp = 0;
		ret = rrr_socket_read_message_default (
				&bytes_read_tmp,
				&handle->read_sessions,
				handle->submodule_private_fd,
				read_step_initial,
				read_step_max_size,
				read_max_size,
				RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_SOCKET_READ_CHECK_EOF,
				__rrr_net_transport_plain_read_get_target_size_callback,
				&callback_data,
				__rrr_net_transport_plain_read_complete_callback,
				&callback_data
		);
		*bytes_read += bytes_read_tmp;

		if (ret == RRR_SOCKET_OK) {
			// TODO : Check for persistent connection/more results which might be
			//		  stored in read session overshoot buffer
			goto out;
		}
		else if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			if (ret == RRR_SOCKET_HARD_ERROR) {
				RRR_MSG_0("Hard error while reading from remote in __rrr_net_transport_plain_read_message\n");
			}
			else {
				RRR_DBG_1("Read returned %i while reading from remote in __rrr_net_transport_plain_read_message\n", ret);
			}
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_net_transport_plain_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	int ret = RRR_NET_TRANSPORT_READ_OK;

	if (buf_size > SSIZE_MAX) {
		RRR_MSG_0("Buffer size too large in __rrr_net_transport_plain_read\n");
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	ssize_t bytes_read_s = 0;

	ret = rrr_socket_read (
			buf,
			&bytes_read_s,
			handle->submodule_private_fd,
			buf_size,
			NULL,
			NULL,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_SOCKET_READ_CHECK_EOF
	);

	ret &= ~(RRR_SOCKET_READ_INCOMPLETE);

	if (bytes_read_s < 0) {
		RRR_BUG("BUG: Negative bytes read value in __rrr_net_transport_libressl_read\n");
	}

	*bytes_read = bytes_read_s;

	out:
	return ret;
}

static int __rrr_net_transport_plain_send (
	uint64_t *written_bytes,
	struct rrr_net_transport_handle *handle,
	const void *data,
	ssize_t size
) {
	int ret = RRR_NET_TRANSPORT_SEND_OK;

	*written_bytes = 0;

	ssize_t written_bytes_tmp = 0;

	if ((ret = rrr_socket_send_nonblock_check_retry(&written_bytes_tmp, handle->submodule_private_fd, data, size)) != 0) {
		if (ret != RRR_SOCKET_WRITE_INCOMPLETE) {
			goto out;
		}
	}

	*written_bytes += (written_bytes_tmp > 0 ? written_bytes_tmp : 0);

	out:
	return ret;
}

int __rrr_net_transport_plain_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
//	struct rrr_net_transport_plain *plain = (struct rrr_net_transport_plain *) transport;

	int ret = 0;

	struct rrr_ip_data ip_data = {0};

	ip_data.port = port;

	if ((ret = rrr_ip_network_start_tcp(&ip_data, 10, do_ipv6)) != 0) {
		goto out;
	}

	struct rrr_net_transport_plain_allocate_and_add_callback_data callback_data = {
			&ip_data
	};

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			__rrr_net_transport_plain_handle_allocate_and_add_callback ,
			&callback_data
	)) != 0) {
		goto out_destroy_ip;
	}

	RRR_DBG_7("Plain listening started on port %u transport handle %p/%i\n", port, transport, new_handle);

	ret = callback(transport, new_handle, callback_final, callback_final_arg, callback_arg);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&ip_data);
	out:
	return ret;
}

int __rrr_net_transport_plain_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_ip_accept_data *accept_data = NULL;

	int ret = 0;

	struct rrr_ip_data ip_data = {0};

	ip_data.fd = listen_handle->submodule_private_fd;

	if ((ret = rrr_ip_accept(&accept_data, &ip_data, "net_transport_plain", 0)) != 0) {
		RRR_MSG_0("Error while accepting connection in plain server\n");
		ret = 1;
		goto out;
	}

	if (accept_data == NULL) {
		goto out;
	}

	struct rrr_net_transport_plain_allocate_and_add_callback_data callback_data = {
			&accept_data->ip_data
	};

	int new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_net_transport_plain_handle_allocate_and_add_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_plain_accept return was %i\n", ret);
		ret = 1;
		goto out_destroy_ip;
	}

	const struct rrr_net_transport_plain_data *listen_plain_data = listen_handle->submodule_private_ptr;

	{
		char buf[128];
		rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) &accept_data->addr, accept_data->len);
		RRR_DBG_7("Plain transport accepted connection on port %u from %s transport handle %p/%i\n",
				listen_plain_data->ip_data.port, buf, listen_handle->transport, new_handle);
	}

	ret = callback (
			listen_handle->transport,
			new_handle,
			(struct sockaddr *) &accept_data->addr,
			accept_data->len,
			final_callback,
			final_callback_arg,
			callback_arg
	);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

static int __rrr_net_transport_plain_poll (
		struct rrr_net_transport_handle *handle
) {
	return rrr_socket_check_alive (handle->submodule_private_fd);
}

static int __rrr_net_transport_plain_is_tls (void) {
	return 0;
}

static const struct rrr_net_transport_methods plain_methods = {
	__rrr_net_transport_plain_destroy,
	__rrr_net_transport_plain_connect,
	__rrr_net_transport_plain_bind_and_listen,
	__rrr_net_transport_plain_accept,
	__rrr_net_transport_plain_close,
	__rrr_net_transport_plain_read_message,
	__rrr_net_transport_plain_read,
	__rrr_net_transport_plain_send,
	__rrr_net_transport_plain_poll,
	__rrr_net_transport_plain_is_tls
};

int rrr_net_transport_plain_new (struct rrr_net_transport_plain **target) {
	struct rrr_net_transport_plain *result = NULL;

	*target = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_plain_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->methods = &plain_methods;

	*target = result;

	out:
	return ret;
}

