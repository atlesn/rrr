/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#ifdef RRR_HAVE_TLS_H_SUBFOLDER
#  include <libressl/tls.h>
#elif RRR_HAVE_TLS_H
#  include <tls.h>
#else
#  error "Neither RRR_HAVE_TLS_H_SUBFOLDER nor RRR_HAVE_TLS_H is set"
#endif
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../log.h"
#include "../allocator.h"

#include "net_transport_libressl.h"
#include "net_transport_tls_common.h"
#include "net_transport_struct.h"
#include "net_transport.h"
#include "net_transport_common.h"

#include "../rrr_strerror.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"
#include "../ip/ip.h"
#include "../ip/ip_util.h"
#include "../ip/ip_accept_data.h"

static void __rrr_net_transport_libressl_destroy (
		RRR_NET_TRANSPORT_DESTROY_ARGS
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	if (tls->config != NULL) {
		tls_config_free(tls->config);
	}
	rrr_net_transport_tls_common_destroy(tls);
}

static void __rrr_net_transport_libressl_data_destroy (
		struct rrr_net_transport_tls_data *data
) {
	if ((data) == NULL) {
		return;
	}

	if (data->l_ctx != NULL) {
		tls_close(data->l_ctx);
		tls_free(data->l_ctx);
	}

	if (data->ip_data.fd > 0) {
		rrr_ip_close(&data->ip_data);
	}

	rrr_free(data);
}

static int __rrr_net_transport_libressl_data_new (
		struct rrr_net_transport_tls_data **result
) {
	int ret = 0;

	*result = NULL;

	struct rrr_net_transport_tls_data *data = rrr_allocate(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_net_transport_libressl_data_new\n");
		ret = 1;
		goto out;
	}

	memset(data, '\0', sizeof(*data));

	*result = data;

	out:
	return ret;
}
/*
static int __rrr_net_transport_libressl_handshake_perform (
		struct tls *ctx
) {
	int ret = 0;

	int handshake_max_retry = 1000;

	while (--handshake_max_retry) {
		ret = tls_handshake(ctx);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
			// OK, retry
		}
		else if (ret != 0) {
			RRR_MSG_0("Error during TLS handshake: %s\n", tls_error(ctx));
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}
		else {
			break;
		}
		rrr_posix_usleep(100);
	}

	if (handshake_max_retry == 0) {
		RRR_MSG_0("TLS handshake timeout\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}
*/
struct rrr_net_transport_libressl_connect_callback_data {
	struct rrr_net_transport_tls *tls;
	struct rrr_ip_accept_data *accept_data;
	const char *server_name;
};

static int __rrr_net_transport_libressl_connect_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_libressl_connect_callback_data *callback_data = arg;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	const char *err_str = NULL;
	struct rrr_net_transport_tls_data *data = NULL;

	*submodule_private_ptr = NULL;
	*submodule_fd = 0;

	if ((ret = __rrr_net_transport_libressl_data_new(&data)) != 0) {
		RRR_MSG_0("Could not create TLS data in __rrr_net_transport_libressl_connect_callback\n");
		goto out;
	}

	if ((data->l_ctx = tls_client()) == NULL) {
		RRR_MSG_0("Failed to create TLS client in __rrr_net_transport_libressl_connect_callback\n");
		ret = 1;
		goto out_destroy_data;
	}

	if (tls_configure(data->l_ctx, callback_data->tls->config) != 0) {
		RRR_MSG_0("TLS configuration failed in __rrr_net_transport_libressl_connect_callback\n");
		ret = 1;
		goto out_config_error;
	}

	if (tls_connect_fds (
			data->l_ctx,
			callback_data->accept_data->ip_data.fd,
			callback_data->accept_data->ip_data.fd,
			callback_data->server_name
	) < 0) {
		RRR_MSG_0("Failed to connect fds in __rrr_net_transport_libressl_connect_callback: %s\n", tls_error(data->l_ctx));
		ret = 1;
		goto out_destroy_data;
	}

	data->sockaddr = callback_data->accept_data->addr;
	data->socklen = callback_data->accept_data->len;
	data->ip_data = callback_data->accept_data->ip_data;

	*submodule_private_ptr = data;
	*submodule_fd = callback_data->accept_data->ip_data.fd;

	goto out;
	out_config_error:
		err_str = tls_config_error(callback_data->tls->config);
		RRR_MSG_0("TLS: %s\n", (err_str != NULL ? err_str : "(unknown error)"));
	out_destroy_data:
		__rrr_net_transport_libressl_data_destroy(data);
	out:
		return ret;
}

static int __rrr_net_transport_libressl_connect (
	RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	int ret = 0;

	struct rrr_ip_accept_data *accept_data = NULL;

	if (rrr_ip_network_connect_tcp_ipv4_or_ipv6(&accept_data, port, host) != 0) {
		RRR_DBG_1("Could not create TLS connection to %s:%u\n", host, port);
		ret = RRR_NET_TRANSPORT_READ_SOFT_ERROR;
		goto out;
	}

	if (*socklen < accept_data->len) {
		RRR_BUG("BUG: Size of sockaddr to __rrr_net_transport_libressl_connect to small %u < %u\n",
				*socklen, accept_data->len);
	}

	struct rrr_net_transport_libressl_connect_callback_data callback_data = {
			tls,
			accept_data,
			host
	};

	rrr_net_transport_handle new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			"lssl outbound",
			NULL,
			NULL,
			__rrr_net_transport_libressl_connect_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_libressl_connect return was %i\n", ret);
		goto out_destroy_ip;
	}

	*handle = new_handle;
	*socklen = accept_data->len;
	memcpy(addr, &accept_data->addr, accept_data->len);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&accept_data->ip_data);
	out:
		RRR_FREE_IF_NOT_NULL(accept_data);
		return ret;
}

struct rrr_net_transport_libressl_bind_and_listen_callback_data {
	struct rrr_net_transport_tls *tls;
	uint16_t port;
	int do_ipv6;
};

static int __rrr_net_transport_libressl_bind_and_listen_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_libressl_bind_and_listen_callback_data *callback_data = arg;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	const char *err_str = NULL;
	struct rrr_net_transport_tls_data *data = NULL;

	*submodule_private_ptr = NULL;
	*submodule_fd = 0;

	if ((ret = __rrr_net_transport_libressl_data_new(&data)) != 0) {
		RRR_MSG_0("Could not create TLS data in __rrr_net_transport_libressl_bind_and_listen_callback\n");
		ret = 1;
		goto out;
	}

	data->ip_data.port = callback_data->port;

	if (rrr_ip_network_start_tcp (&data->ip_data, 10, callback_data->do_ipv6) != 0) {
		RRR_DBG_1("Note: Could not start IP listening in __rrr_net_transport_libressl_bind_and_listen_callback\n");
		ret = 1;
		goto out_destroy_data;
	}

	if ((data->l_ctx = tls_server()) == NULL) {
		RRR_MSG_0("Failed to create TLS server in __rrr_net_transport_libressl_bind_and_listen_callback\n");
		ret = 1;
		goto out_destroy_data;
	}

	if (tls_configure(data->l_ctx, callback_data->tls->config) != 0) {
		RRR_MSG_0("TLS configuration failed in __rrr_net_transport_libressl_bind_and_listen_callback\n");
		ret = 1;
		goto out_config_error;
	}

	*submodule_private_ptr = data;
	*submodule_fd = data->ip_data.fd;

	goto out;
	out_config_error:
		err_str = tls_config_error(callback_data->tls->config);
		RRR_MSG_0("TLS: %s\n", (err_str != NULL ? err_str : "(unknown error)"));
	out_destroy_data:
		__rrr_net_transport_libressl_data_destroy(data);
	out:
		return ret;
}

static int __rrr_net_transport_libressl_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	int ret = 0;

	if (tls->certificate_file == NULL || tls->private_key_file == NULL) {
		RRR_MSG_0("Certificate file and/or private key file not set while attempting to start TLS listening server\n");
		ret = 1;
		goto out;
	}

	struct rrr_net_transport_libressl_bind_and_listen_callback_data callback_data = {
			tls,
			port,
			do_ipv6
	};

	rrr_net_transport_handle new_handle;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			"lssl listen",
			NULL,
			NULL,
			__rrr_net_transport_libressl_bind_and_listen_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	RRR_DBG_7("LibreSSL listening started on port %u transport handle %p/%i\n", port, transport, new_handle);

	ret = callback (
			transport,
			new_handle,
			callback_final,
			callback_final_arg,
			callback_arg
	);

	out:
	return ret;
}

struct rrr_net_transport_libressl_accept_callback_data {
	struct rrr_ip_accept_data *accept_data;
	struct rrr_net_transport_tls *tls;
	struct tls *l_ctx;
};

int __rrr_net_transport_libressl_accept_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_libressl_accept_callback_data *callback_data = arg;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	*submodule_private_ptr = NULL;
	*submodule_fd = 0;

	struct rrr_net_transport_tls_data *new_data = NULL;

	if ((ret = __rrr_net_transport_libressl_data_new(&new_data)) != 0) {
		RRR_MSG_0("Could not allocate memory for SSL data in __rrr_net_transport_libressl_accept_callback\n");
		goto out;
	}

	if (tls_accept_socket (
			callback_data->l_ctx,
			&new_data->l_ctx,
			callback_data->accept_data->ip_data.fd
	) < 0) {
		RRR_MSG_0("Failed to bind fd with TLS in __rrr_net_transport_libressl_accept_callback\n");
		ret = 1;
		goto out_destroy_data;
	}

	new_data->sockaddr = callback_data->accept_data->addr;
	new_data->socklen = callback_data->accept_data->len;
	new_data->ip_data = callback_data->accept_data->ip_data;

	*submodule_private_ptr = new_data;
	*submodule_fd = callback_data->accept_data->ip_data.fd;

	goto out;
	out_destroy_data:
		__rrr_net_transport_libressl_data_destroy(new_data);
	out:
		return ret;
}

int __rrr_net_transport_libressl_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_net_transport_tls_data *data = listen_handle->submodule_private_ptr;
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) listen_handle->transport;

	(void)(connection_ids);
	(void)(datagram);

	int ret = 0;

	struct rrr_ip_accept_data *accept_data = NULL;

	if ((ret = rrr_ip_accept(&accept_data, &data->ip_data, "net_transport_tls", 0)) != 0) {
		RRR_MSG_0("Error while accepting connection in TLS server\n");
		ret = 1;
		goto out;
	}

	if (accept_data == NULL) {
		goto out;
	}

	struct rrr_net_transport_libressl_accept_callback_data callback_data = {
		accept_data,
		tls,
		data->l_ctx
	};

	if ((ret = rrr_net_transport_handle_allocate_and_add (
			new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			"lssl inbound",
			NULL,
			NULL,
			__rrr_net_transport_libressl_accept_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in __rrr_net_transport_libressl_accept return was %i\n", ret);
		goto out_destroy_ip;
	}

	{
		char buf[128];
		rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) &accept_data->addr, accept_data->len);
		RRR_DBG_7("LibreSSL accepted connection on port %u from %s transport handle %p/%i\n",
				data->ip_data.port, buf, listen_handle->transport, new_handle);
	}

	ret = callback (
			listen_handle->transport,
			*new_handle,
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

static int __rrr_net_transport_libressl_close (
		RRR_NET_TRANSPORT_CLOSE_ARGS
) {
	__rrr_net_transport_libressl_data_destroy(handle->submodule_private_ptr);
	return 0;
}

static int __rrr_net_transport_libressl_pre_destroy (
		RRR_NET_TRANSPORT_PRE_DESTROY_ARGS
) {
	(void)(submodule_private_ptr);

	return handle->application_pre_destroy != NULL
		? handle->application_pre_destroy(handle, application_private_ptr)
		: 0
	;
}

static int __rrr_net_transport_libressl_read_raw (
		char *buf,
		rrr_biglength *read_bytes,
		struct rrr_net_transport_tls_data *tls_data,
		rrr_biglength read_step_max_size
) {
	int ret = RRR_READ_OK;

	ssize_t result = tls_read(tls_data->l_ctx, buf, read_step_max_size);
	if (result == 0) {
		ret = RRR_READ_EOF;
	}
	else if (result < 0) {
		if (result == TLS_WANT_POLLIN || result == TLS_WANT_POLLOUT) {
			goto out;
		}

		RRR_MSG_0("Error while reading in __rrr_net_transport_libressl_read_raw: %s\n", tls_error(tls_data->l_ctx));
		ret = RRR_READ_SOFT_ERROR;
	}

	out:
	*read_bytes = (result >= 0 ? (rrr_biglength) result : 0);
	return ret;
}

static int __rrr_net_transport_libressl_read_read (
		char *buf,
		rrr_biglength *read_bytes,
		rrr_biglength read_step_max_size,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_data *tls_data = callback_data->handle->submodule_private_ptr;

	return __rrr_net_transport_libressl_read_raw(buf, read_bytes, tls_data, read_step_max_size);
}

static int __rrr_net_transport_libressl_read_message (
		RRR_NET_TRANSPORT_READ_MESSAGE_ARGS
) {
	int ret = 0;

	*bytes_read = 0;

	struct rrr_net_transport_read_callback_data read_callback_data = {
		handle,
		get_target_size,
		get_target_size_arg,
		get_target_size_error,
		get_target_size_error_arg,
		complete_callback,
		complete_callback_arg
	};

	uint64_t bytes_read_tmp = 0;
	ret = rrr_read_message_using_callbacks (
			&bytes_read_tmp,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			RRR_LL_FIRST(&handle->read_sessions),
			ratelimit_interval_us,
			ratelimit_max_bytes,
			rrr_net_transport_common_read_get_target_size,
			rrr_net_transport_common_read_get_target_size_error_callback,
			rrr_net_transport_common_read_complete_callback,
			__rrr_net_transport_libressl_read_read,
			rrr_net_transport_tls_common_read_get_read_session_with_overshoot,
			rrr_net_transport_tls_common_read_get_read_session,
			rrr_net_transport_tls_common_read_remove_read_session,
			NULL,
			&read_callback_data
	);
	*bytes_read += bytes_read_tmp;

	if (ret == RRR_NET_TRANSPORT_READ_OK || ret == RRR_NET_TRANSPORT_READ_RATELIMIT || ret == RRR_NET_TRANSPORT_READ_INCOMPLETE) {
		// OK, no message printed
	}
	else {
		RRR_MSG_0("Error %i while reading from remote in %s\n", ret, __func__);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_net_transport_libressl_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	int ret = RRR_NET_TRANSPORT_READ_OK;

	if (buf_size > SSIZE_MAX) {
		RRR_MSG_0("Buffer size too large in __rrr_net_transport_libressl_read\n");
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	ret = __rrr_net_transport_libressl_read_raw(buf, bytes_read, handle->submodule_private_ptr, buf_size);

	if (ret == RRR_NET_TRANSPORT_READ_OK && *bytes_read == 0) {
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
	}

	out:
	return ret;
}

static int __rrr_net_transport_libressl_send (
		RRR_NET_TRANSPORT_SEND_ARGS
) {
	struct rrr_net_transport_tls_data *tls_data = handle->submodule_private_ptr;

	*bytes_written = 0;

	int ret = RRR_NET_TRANSPORT_SEND_INCOMPLETE;

	int retries = 1000;
	rrr_biglength size_remaining = size;
	struct pollfd pfd = {0};

	pfd.fd = handle->submodule_fd;
	pfd.events = POLLIN|POLLOUT;
	while (size_remaining > 0 && --retries > 0) {
		int ret_tmp = poll(&pfd, 1, 0);
		if (ret_tmp == -1) {
			RRR_DBG_7("Poll failed for TLS fd %i while writing: %s\n", pfd.fd, rrr_strerror(errno));
			ret = RRR_NET_TRANSPORT_SEND_HARD_ERROR;
			goto out;
		}
		else if ((pfd.revents & (POLLERR|POLLNVAL))) {
			RRR_DBG_7("Bad file descriptor for TLS fd %i while writing, maybe remote has closed the connection\n", pfd.fd);
			ret = RRR_NET_TRANSPORT_SEND_HARD_ERROR;
			goto out;
		}
		else if ((pfd.revents & (pfd.events|POLLHUP))) {
			ssize_t bytes = tls_write(tls_data->l_ctx, data, size);
			if (bytes == TLS_WANT_POLLIN) {
				pfd.events = POLLIN;
			}
			else if (bytes == TLS_WANT_POLLOUT) {
				pfd.events = POLLOUT;
			}
			else if (bytes < 0) {
				RRR_DBG_7("Error while writing to TLS fd %i: %s\n", pfd.fd, tls_error(tls_data->l_ctx));
				ret = RRR_NET_TRANSPORT_SEND_HARD_ERROR;
				goto out;
			}
			else {
				rrr_biglength_from_ssize_sub_bug(&size_remaining, bytes);
				*bytes_written = (rrr_biglength) bytes;

				if (size_remaining == 0) {
					ret = RRR_NET_TRANSPORT_SEND_OK;
				}

				break;
			}
		}
		pthread_testcancel();
		rrr_posix_usleep(1); // Schedule
	}

	out:
	return ret;
}

static int __rrr_net_transport_libressl_poll (
		RRR_NET_TRANSPORT_POLL_ARGS
) {
	return rrr_socket_check_alive (handle->submodule_fd);
}

static int __rrr_net_transport_libressl_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	struct rrr_net_transport_tls_data *tls_data = handle->submodule_private_ptr;

	int ret_tmp;
	if ((ret_tmp = tls_handshake(tls_data->l_ctx)) != 0) {
		return (ret_tmp == TLS_WANT_POLLIN || ret_tmp == TLS_WANT_POLLOUT
			? RRR_NET_TRANSPORT_SEND_INCOMPLETE :
			RRR_NET_TRANSPORT_SEND_SOFT_ERROR
		);
	}

	return RRR_NET_TRANSPORT_SEND_OK;
}

static int __rrr_net_transport_libressl_is_tls (void) {
	return 1;
}

static int __rrr_net_transport_libressl_selected_proto_get (
		RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS
) {
	struct rrr_net_transport_tls_data *tls_data = handle->submodule_private_ptr;

	const char *proto_source = tls_conn_alpn_selected(tls_data->l_ctx);
	char *proto_new = NULL;

	*proto = NULL;

	if (proto_source != 0 && (proto_new = rrr_strdup(proto_source)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		return 1;
	}

	*proto = proto_new;

	return 0;
}

static const struct rrr_net_transport_methods libressl_methods = {
	__rrr_net_transport_libressl_destroy,
	__rrr_net_transport_libressl_connect,
	NULL,
	__rrr_net_transport_libressl_bind_and_listen,
	NULL,
	NULL,
	__rrr_net_transport_libressl_accept,
	__rrr_net_transport_libressl_close,
	__rrr_net_transport_libressl_pre_destroy,
	__rrr_net_transport_libressl_read_message,
	__rrr_net_transport_libressl_read,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	__rrr_net_transport_libressl_send,
	__rrr_net_transport_libressl_poll,
	__rrr_net_transport_libressl_handshake,
	__rrr_net_transport_libressl_is_tls,
	__rrr_net_transport_libressl_selected_proto_get
};

int rrr_net_transport_libressl_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	int ret = 0;

	const char *err_str = NULL;
	char alpn_protos_tmp[256];

	alpn_protos_tmp[0] = '\0';

	if (alpn_protos != NULL && alpn_protos_length > 0) {
		rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated((unsigned char *) alpn_protos_tmp, sizeof(alpn_protos_tmp), (unsigned const char *) alpn_protos, alpn_protos_length);
	}

	if ((ret = rrr_net_transport_tls_common_new (
			target,
			flags,
			0,
			certificate_file,
			private_key_file,
			ca_file,
			ca_path,
			alpn_protos,
			alpn_protos_length
	)) != 0) {
		goto out;
	}

	struct rrr_net_transport_tls *tls = *target;

	tls->methods = &libressl_methods;
	if ((tls->config = tls_config_new()) == NULL) {
		RRR_MSG_0("Failed to create TLS config in rrr_net_transport_libressl_new\n");
		ret = 1;
		goto out_destroy;
	}

	tls_config_insecure_noverifyname(tls->config);

	if (flags & RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY) {
		tls_config_insecure_noverifycert(tls->config);
	}

	if (certificate_file != NULL && *certificate_file != '\0' && tls_config_set_cert_file(tls->config, certificate_file) < 0) {
		goto out_config_error;
	}

	if (private_key_file != NULL && *private_key_file != '\0' && tls_config_set_key_file(tls->config, private_key_file) < 0) {
		goto out_config_error;
	}

	if (ca_file != NULL && *ca_file != '\0' && tls_config_set_ca_file(tls->config, ca_file) < 0) {
		goto out_config_error;
	}

	if (ca_path != NULL && *ca_path != '\0' && tls_config_set_ca_path(tls->config, ca_path) < 0) {
		goto out_config_error;
	}

	unsigned int protocols = 0;
	if(tls_config_parse_protocols(&protocols, "secure") < 0) {
		goto out_config_error;
	}

	if (tls_config_set_protocols(tls->config, protocols) < 0) {
		goto out_config_error;
	}

	const char *ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384";
	if(tls_config_set_ciphers(tls->config, ciphers) < 0) {
		goto out_config_error;
	}

	if (strlen(alpn_protos_tmp) > 0) {
		if (tls_config_set_alpn(tls->config, alpn_protos_tmp) < 0) {
			goto out_config_error;
		}
	}

	goto out;
	out_config_error:
		ret = 1;
		err_str = tls_config_error(tls->config);
		RRR_MSG_0("TLS: %s\n", (err_str != NULL ? err_str : "(unknown error)"));
//	out_destroy_config:
		tls_config_free(tls->config);
	out_destroy:
		rrr_net_transport_tls_common_destroy(tls);
	out:
		return ret;
}
