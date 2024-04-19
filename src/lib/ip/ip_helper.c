/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <sys/socket.h>
#include <string.h>

#include "ip_helper.h"
#include "ip.h"
#include "ip_util.h"
#include "../allocator.h"
#include "../socket/rrr_socket_client.h"
#include "../util/gnu.h"

struct rrr_ip_socket_client_resolve_suggestion_callback_data {
	size_t address_count;
	struct sockaddr **addresses;
	socklen_t *address_lengths;
};

static int __rrr_ip_socket_client_resolve_suggestion_callback (
		const char *host,
		uint16_t port,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *arg
) {
	struct rrr_ip_socket_client_resolve_suggestion_callback_data *callback_data = arg;

	int ret = 0;

	if (RRR_DEBUGLEVEL_7) {
		char buf[256];
		*buf = '\0';
		rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);
		RRR_DBG_7("socket client resolve[%llu] %s:%u => %s\n",
				(long long unsigned int) callback_data->address_count,
				host,
				port,
				buf
		);
	}

	{
		struct sockaddr **addresses_new = rrr_reallocate(callback_data->addresses, sizeof(void *) * (callback_data->address_count + 1));
		if (addresses_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in rrr_ip_socket_client_resolve_suggestion_callback A\n");
			ret = 1;
			goto out;
		}
		callback_data->addresses = addresses_new;
	}

	{
		socklen_t *address_lengths_new = rrr_reallocate(callback_data->address_lengths, sizeof(socklen_t) * (callback_data->address_count + 1));
		if (address_lengths_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in rrr_ip_socket_client_resolve_suggestion_callback B\n");
			ret = 1;
			goto out;
			
		}
		callback_data->address_lengths = address_lengths_new;
	}

	if ((callback_data->addresses[callback_data->address_count] = (void *) rrr_allocate(sizeof(struct sockaddr_storage))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in rrr_ip_socket_client_resolve_suggestion_callback C\n");
		ret = 1;
		goto out;
	}

	memcpy(callback_data->addresses[callback_data->address_count], addr, addr_len);
	callback_data->address_lengths[callback_data->address_count] = addr_len;

	callback_data->address_count++;

	out:
	return ret;
}

struct rrr_ip_socket_client_resolve_callback_data {
	const char *host;
	uint16_t port;
};

static int __rrr_ip_socket_client_resolve_callback (
		size_t *address_count,
		struct sockaddr ***addresses,
		socklen_t **address_lengths,
		void *arg
) {
	int ret = 0;

	struct rrr_ip_socket_client_resolve_callback_data *callback_data = arg;

	struct rrr_ip_socket_client_resolve_suggestion_callback_data suggestion_callback_data = {
		0,
		NULL,
		NULL
	};

	if ((ret = rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
			callback_data->port,
			callback_data->host,
			__rrr_ip_socket_client_resolve_suggestion_callback,
			&suggestion_callback_data
	)) != 0) {
		goto out;
	}

	*address_count = suggestion_callback_data.address_count;
	*addresses = suggestion_callback_data.addresses;
	*address_lengths = suggestion_callback_data.address_lengths;

	suggestion_callback_data.address_count = 0;
	suggestion_callback_data.addresses = NULL;
	suggestion_callback_data.address_lengths = NULL;

	out:
	for (size_t i = 0; i < suggestion_callback_data.address_count; i++) {
		rrr_free(suggestion_callback_data.addresses[i]);
	}
	RRR_FREE_IF_NOT_NULL(suggestion_callback_data.addresses);
	RRR_FREE_IF_NOT_NULL(suggestion_callback_data.address_lengths);
	return ret;
}

int rrr_ip_socket_client_collection_send_push_const_by_host_and_port_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const char *host,
		uint16_t port,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data,
		int (*data_prepare_callback)(const void **data, rrr_biglength *size, void *callback_data, void *private_data),
		void *data_prepare_callback_data
) {
	int ret = 0;

	char *addr_string;

	struct rrr_ip_socket_client_resolve_callback_data callback_data = {
		host,
		port
	};

	if (!(rrr_asprintf(&addr_string, "%s:%u", host, port) > 0)) {
		RRR_MSG_0("Failed to create address string in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
			send_chunk_count,
			collection,
			addr_string,
			data,
			size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy,
			__rrr_ip_socket_client_resolve_callback,
			&callback_data,
			connect_callback,
			connect_callback_data,
			data_prepare_callback,
			data_prepare_callback_data
	)) != 0) {
		goto out_free;
	}

	out_free:
		rrr_free(addr_string);
	out:
		return ret;
}

int rrr_ip_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const char *addr_string,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data,
		int (*data_prepare_callback)(const void **data, rrr_biglength *size, void *callback_data, void *private_data),
		void *data_prepare_callback_data
) {
	int ret = 0;

	char *host;
	uint16_t port;

	if ((ret = rrr_ip_address_string_split (
			&host,
			&port,
			addr_string
	)) != 0) {
		goto out;
	}

	struct rrr_ip_socket_client_resolve_callback_data callback_data = {
		host,
		port
	};

	if ((ret = rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
			send_chunk_count,
			collection,
			addr_string,
			data,
			size,
			chunk_private_data_new,
			chunk_private_data_arg,
			chunk_private_data_destroy,
			__rrr_ip_socket_client_resolve_callback,
			&callback_data,
			connect_callback,
			connect_callback_data,
			data_prepare_callback,
			data_prepare_callback_data
	)) != 0) {
		goto out_free;
	}

	out_free:
		rrr_free(host);
	out:
		return ret;
}
