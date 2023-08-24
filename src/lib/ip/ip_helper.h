/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_IP_HELPER_H
#define RRR_IP_HELPER_H

#include <sys/socket.h>

#include "../rrr_types.h"

struct rrr_socket_client_collection;

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
		void (*data_prepare_callback)(const void **data, rrr_biglength *size, void *callback_data, void *private_data),
		void *data_prepare_callback_data
);

#endif /* RRR_IP_HELPER_H */
