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

#include "../ip/ip.h"
#include "net_transport_libressl.h"
#include "net_transport_tls_common.h"

struct rrr_net_transport_opensl_ssl_data {
	struct rrr_ip_data ip_data;
	struct sockaddr_storage sockaddr;
	socklen_t socklen;
	int handshake_complete;
};


static void __rrr_net_transport_libressl_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;
	rrr_net_transport_tls_common_destroy(tls);
}

static int __rrr_net_transport_libressl_connect (
		int *handle,
		struct sockaddr *addr,
		socklen_t *socklen,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {

}

static int __rrr_net_transport_libressl_bind_and_listen (
		RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS
) {

}

int __rrr_net_transport_libressl_accept (
		RRR_NET_TRANSPORT_ACCEPT_ARGS
) {

}

static int __rrr_net_transport_libressl_ssl_data_close (struct rrr_net_transport_handle *handle) {

	return 0;
}

static int __rrr_net_transport_libressl_read_message (
		RRR_NET_TRANSPORT_READ_ARGS
) {
}

static int __rrr_net_transport_libressl_send (
	uint64_t *sent_bytes,
	struct rrr_net_transport_handle *handle,
	const void *data,
	ssize_t size
) {
}

static int __rrr_net_transport_libressl_poll (
		struct rrr_net_transport_handle *handle
) {
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_libressl_destroy,
	__rrr_net_transport_libressl_connect,
	__rrr_net_transport_libressl_bind_and_listen,
	__rrr_net_transport_libressl_accept,
	__rrr_net_transport_libressl_ssl_data_close,
	__rrr_net_transport_libressl_read_message,
	__rrr_net_transport_libressl_send,
	__rrr_net_transport_libressl_poll
};

int rrr_net_transport_libressl_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path
) {
	int ret = 0;

	if ((ret = rrr_net_transport_tls_common_new(target, flags, certificate_file, private_key_file, ca_file, ca_path)) != 0) {
		goto out;
	}

	(*target)->methods = &tls_methods;

	out:
	return ret;
}
