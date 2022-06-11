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

#include "../log.h"
#include "../allocator.h"

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_quic.h"
#include "net_transport_tls_common.h"
#include "net_transport_common.h"

#include "../rrr_openssl.h"

static int __rrr_net_transport_quic_ssl_data_close (struct rrr_net_transport_handle *handle) {
	(void)(handle);
	return 1;
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
	return 1;
}

static int __rrr_net_transport_quic_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {
	(void)(transport);
	(void)(port);
	(void)(do_ipv6);
	(void)(callback);
	(void)(callback_arg);
	(void)(callback_final);
	(void)(callback_final_arg);
	return 1;
}

int __rrr_net_transport_quic_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {
	(void)(did_accept);
	(void)(listen_handle);
	(void)(callback);
	(void)(callback_arg);
	(void)(final_callback);
	(void)(final_callback_arg);
	return 1;
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
	return 1;
}

static int __rrr_net_transport_quic_read (
		RRR_NET_TRANSPORT_READ_ARGS
) {
	(void)(bytes_read);
	(void)(handle);
	(void)(buf);
	(void)(buf_size);
	return 1;
}

static int __rrr_net_transport_quic_send (
		RRR_NET_TRANSPORT_SEND_ARGS
) {
	(void)(bytes_written);
	(void)(handle);
	(void)(data);
	(void)(size);
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
	return 1;
}

static int __rrr_net_transport_quic_handshake (
		RRR_NET_TRANSPORT_HANDSHAKE_ARGS
) {
	(void)(handle);
	return 1;
}

static int __rrr_net_transport_quic_is_tls (void) {
	return 1;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_quic_destroy,
	__rrr_net_transport_quic_connect,
	__rrr_net_transport_quic_bind_and_listen,
	__rrr_net_transport_quic_accept,
	__rrr_net_transport_quic_ssl_data_close,
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
