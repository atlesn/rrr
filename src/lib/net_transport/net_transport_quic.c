/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include <openssl/err.h>
#include <ngtcp2/ngtcp2.h>

#include "../log.h"
#include "../allocator.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_quic.h"
#include "net_transport_tls_common.h"
#include "net_transport_openssl_common.h"
#include "net_transport_common.h"

#include "../allocator.h"
#include "../rrr_openssl.h"
#include "../rrr_strerror.h"
#include "../ip/ip_util.h"
#include "../ip/ip_accept_data.h"

#define RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH 18

struct rrr_net_transport_quic_data {
	struct rrr_ip_data ip_data;
};

static int __rrr_net_transport_quic_data_new (
		struct rrr_net_transport_quic_data **result,
		const struct rrr_ip_data *ip_data
) {
	*result = NULL;

	struct rrr_net_transport_quic_data *data;

	if ((data = rrr_allocate_zero(sizeof(*data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		return 1;
	}

	data->ip_data = *ip_data;

	*result = data;

	return 0;
}

static void __rrr_net_transport_quic_data_destroy (
		struct rrr_net_transport_quic_data *data
) {
	RRR_FREE_IF_NOT_NULL(data);
}

static int __rrr_net_transport_quic_close (struct rrr_net_transport_handle *handle) {
	if (rrr_socket_close(handle->submodule_fd) != 0) {
		RRR_MSG_0("Warning: Error from rrr_socket_close in %s\n", __func__);
	}
	__rrr_net_transport_quic_data_destroy(handle->submodule_private_ptr);
	return 0;
}

static void __rrr_net_transport_quic_destroy (
		RRR_NET_TRANSPORT_DESTROY_ARGS
) {
	rrr_openssl_global_unregister_user();

	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	rrr_net_transport_tls_common_destroy(tls);
}

static int __rrr_net_transport_quic_connect (
		RRR_NET_TRANSPORT_CONNECT_ARGS
) {
	(void)(handle);
	(void)(addr);
	(void)(socklen);
	(void)(transport);
	(void)(port);
	(void)(host);
	printf("Connect\n");
	return 1;
}

struct rrr_net_transport_quic_allocate_and_add_callback_data {
	const struct rrr_ip_data *ip_data;
};

static int __rrr_net_transport_quic_allocate_and_add_callback (RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS) {
	struct rrr_net_transport_quic_allocate_and_add_callback_data *callback_data = arg;

	struct rrr_net_transport_quic_data *data = NULL;
	if (__rrr_net_transport_quic_data_new (&data, callback_data->ip_data) != 0) {
		return 1;
	}

	*submodule_private_ptr = data;
	*submodule_fd = callback_data->ip_data->fd;

	return 0;
}

static int __rrr_net_transport_quic_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	int ret = 0;

	struct rrr_ip_data ip_data = {0};

	ip_data.port = port;

	if ((ret = rrr_ip_network_start_udp (&ip_data, do_ipv6)) != 0) {
		goto out;
	}

	struct rrr_net_transport_quic_allocate_and_add_callback_data callback_data = {
		&ip_data
	};

	rrr_net_transport_handle new_handle = 0;
	if ((ret = rrr_net_transport_handle_allocate_and_add (
			&new_handle,
			transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
			__rrr_net_transport_quic_allocate_and_add_callback,
			&callback_data
	)) != 0) {
		goto out_destroy_ip;
	}

	RRR_DBG_7("QUIC started on port %u IPv%s transport handle %p/%i\n", port, do_ipv6 ? "6" : "4", transport, new_handle);

	ret = callback(transport, new_handle, callback_final, callback_final_arg, callback_arg);

	goto out;
	out_destroy_ip:
		rrr_ip_close(&ip_data);
	out:
		return ret;
}
		
static int __rrr_net_transport_quic_send_version_negotiation (
		struct rrr_net_transport_handle *handle
) {
	(void)(handle);
	// ngtcp2_pkt_write_version_negotiation
	return 1;
}

static int __rrr_net_transport_quic_decode (
		RRR_NET_TRANSPORT_DECODE_ARGS
) {
	struct rrr_net_transport_datagram *datagram = &listen_handle->datagram;

	int ret = 0;

	rrr_net_transport_datagram_reset(datagram);

	ssize_t bytes = recvmsg(listen_handle->submodule_fd, &datagram->msg, 0);
	
	if (bytes == 0 || bytes == EAGAIN || bytes == ENOTCONN) {
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		goto out;
	}
	else if (bytes < 0) {
		RRR_MSG_0("recvmsg failed for fd %i: %s\n", rrr_strerror(errno));
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	datagram->size = (size_t) bytes;

	// TODO : Read ECN from IP header
	// ngtcp2_pkt_info pi = {.ecn = NGTCP2_ECN_NOT_ECT};

	uint32_t version;
	const uint8_t *dcid, *scid;
	size_t dcidlen, scidlen;

	int ret_tmp = ngtcp2_pkt_decode_version_cid (
			&version,
			&dcid,
			&dcidlen,
			&scid,
			&scidlen,
			datagram->buf,
			(size_t) bytes,
			RRR_NET_TRANSPORT_QUIC_SHORT_CID_LENGTH
	);

	// Return INCOMPLETE for invalid packets or if there is nothing
	// more to do.

	if (ret_tmp < 0) {
		if (ret_tmp == NGTCP2_ERR_INVALID_ARGUMENT) {
			RRR_DBG_7("fd %i failed to decode QUIC packet of size %llu\n", listen_handle->submodule_fd, (long long unsigned) bytes);
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}
		else if (ret_tmp == NGTCP2_ERR_VERSION_NEGOTIATION) {
			if ((ret = __rrr_net_transport_quic_send_version_negotiation (
				listen_handle
			)) != 0) {
				goto out;
			}
			ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
			goto out;
		}

		RRR_MSG_0("Error while decoding QUIC packet: %s\n", ngtcp2_strerror(ret_tmp));
		ret = RRR_NET_TRANSPORT_READ_HARD_ERROR;
		goto out;
	}

	if (dcidlen > connection_id->length) {
		RRR_DBG_7("fd %i dcid too long in received QUIC paccket (%llu>%llu)\n",
				listen_handle->submodule_fd, (long long unsigned) dcidlen, (long long unsigned) connection_id->length);
		ret = RRR_NET_TRANSPORT_READ_INCOMPLETE;
		goto out;
	}

	memcpy(connection_id->data, dcid, dcidlen);
	connection_id->length = dcidlen;

	out:
	return ret;
}

struct rrr_net_transport_quic_accept_callback_data {
	struct rrr_net_transport_tls *tls;
};

static int __rrr_net_transport_quic_accept_callback (
		RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS
) {
	struct rrr_net_transport_quic_accept_callback_data *callback_data = arg;
	struct rrr_net_transport_tls *tls = callback_data->tls;

	int ret = 0;

	struct rrr_net_transport_tls_data *ssl_data = NULL;

	if ((ssl_data = rrr_net_transport_openssl_common_ssl_data_new()) == NULL) {
		RRR_MSG_0("Could not allocate memory for SSL data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (rrr_net_transport_openssl_common_new_ctx (
			&ssl_data->ctx,
			tls->ssl_server_method,
			tls->flags,
			tls->certificate_file,
			tls->private_key_file,
			tls->ca_file,
			tls->ca_path,
			&tls->alpn
	) != 0) {
		RRR_SSL_ERR("Could not get SSL CTX when accepting connection in net transport QUIC");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	if ((ssl_data->web = BIO_new_ssl(ssl_data->ctx, 0)) == NULL) {
		RRR_SSL_ERR("Could not allocate BIO when accepting connection in net transport QUIC");
		ret = 1;
		goto out_destroy_ssl_data;
	}

	SSL *ssl;
	BIO_get_ssl(ssl_data->web, &ssl);
	SSL_set_accept_state(ssl);

	*submodule_private_ptr = ssl_data;
	*submodule_fd = -1; // Set to disable polling on events for this handle

	goto out;
	out_destroy_ssl_data:
		rrr_net_transport_openssl_common_ssl_data_destroy(ssl_data);
	out:
		return ret;
}

static int __rrr_net_transport_quic_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	struct rrr_ip_accept_data *accept_data = NULL;
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) listen_handle->transport;

	(void)(connection_id);

	int ret = 0;

	struct rrr_net_transport_tls_data *listen_ssl_data = listen_handle->submodule_private_ptr;

	struct rrr_net_transport_quic_accept_callback_data callback_data = {
		tls
	};

	if ((ret = rrr_net_transport_handle_allocate_and_add (
			new_handle,
			listen_handle->transport,
			RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION,
			__rrr_net_transport_quic_accept_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Could not get handle in %s return was %i\n", __func__, ret);
		goto out_destroy_ip;
	}

	{
		RRR_DBG_7("QUIC OpenSSL accepted connection on port %u transport handle %p/%i\n",
				listen_ssl_data->ip_data.port, listen_handle->transport, new_handle);
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

static int __rrr_net_transport_quic_read_message (
		RRR_NET_TRANSPORT_READ_MESSAGE_ARGS
) {
	(void)(bytes_read);
	(void)(handle);
	(void)(read_step_initial);
	(void)(read_step_max_size);
	(void)(read_max_size);
	(void)(ratelimit_interval_us);
	(void)(ratelimit_max_bytes);
	(void)(get_target_size);
	(void)(get_target_size_arg);
	(void)(get_target_size_error);
	(void)(get_target_size_error_arg);
	(void)(complete_callback);
	(void)(complete_callback_arg);
	printf("Read message\n");
	return 1;
}

static int __rrr_net_transport_quic_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	(void)(bytes_read);
	(void)(handle);
	(void)(buf);
	(void)(buf_size);
	printf("Read\n");
	return 1;
}

static int __rrr_net_transport_quic_send (
		RRR_NET_TRANSPORT_SEND_ARGS
) {
	(void)(bytes_written);
	(void)(handle);
	(void)(data);
	(void)(size);
	printf("Send\n");
	return 1;
}

static void __rrr_net_transport_quic_selected_proto_get (
		RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS
) {
	(void)(handle);
	(void)(proto);
}

static int __rrr_net_transport_quic_poll (
		RRR_NET_TRANSPORT_POLL_ARGS
) {
	(void)(handle);
	printf("Poll\n");
	return 1;
}

static int __rrr_net_transport_quic_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	(void)(handle);
	printf("Handshake\n");
	return 1;
}

static int __rrr_net_transport_quic_is_tls (void) {
	return 1;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_quic_destroy,
	__rrr_net_transport_quic_connect,
	__rrr_net_transport_quic_bind_and_listen,
	__rrr_net_transport_quic_decode,
	__rrr_net_transport_quic_accept,
	__rrr_net_transport_quic_close,
	__rrr_net_transport_quic_read_message,
	__rrr_net_transport_quic_read,
	__rrr_net_transport_quic_send,
	__rrr_net_transport_quic_poll,
	__rrr_net_transport_quic_handshake,
	__rrr_net_transport_quic_is_tls,
	__rrr_net_transport_quic_selected_proto_get
};

int rrr_net_transport_quic_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	if ((rrr_net_transport_tls_common_new(target, flags, certificate_file, private_key_file, ca_file, ca_path, alpn_protos, alpn_protos_length)) != 0) {
		return 1;
	}

	rrr_openssl_global_register_user();

	(*target)->methods = &tls_methods;
	(*target)->ssl_client_method = TLS_client_method();
	(*target)->ssl_server_method = TLS_server_method();

	return 0;
}
