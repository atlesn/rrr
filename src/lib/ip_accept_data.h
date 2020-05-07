/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_IP_ACCEPT_DATA_H
#define RRR_IP_ACCEPT_DATA_H

#include <sys/socket.h>

#include "rrr_socket.h"
#include "linked_list.h"

struct rrr_ip_accept_data {
	RRR_LL_NODE(struct rrr_ip_accept_data);
	struct rrr_sockaddr addr;
	socklen_t len;
	struct rrr_ip_data ip_data;
	int custom_data;
};

struct rrr_ip_accept_data_collection {
	RRR_LL_HEAD(struct rrr_ip_accept_data);
};

void rrr_ip_accept_data_close_and_destroy (
		struct rrr_ip_accept_data *accept_data
);
void rrr_ip_accept_data_close_and_destroy_void (
		void *accept_data
);
void rrr_ip_accept_data_collection_clear(
		struct rrr_ip_accept_data_collection *collection
);
void rrr_ip_accept_data_collection_clear_void(
		void *collection
);
void rrr_ip_accept_data_collection_close_and_remove(
		struct rrr_ip_accept_data_collection *collection,
		struct sockaddr *sockaddr,
		socklen_t socklen
);
void rrr_ip_accept_data_collection_close_and_remove_by_fd (
		struct rrr_ip_accept_data_collection *collection,
		int fd
);
struct rrr_ip_accept_data *rrr_ip_accept_data_collection_find (
		struct rrr_ip_accept_data_collection *collection,
		struct sockaddr *sockaddr,
		socklen_t socklen
);
struct rrr_ip_accept_data *rrr_ip_accept_data_collection_find_by_fd (
		struct rrr_ip_accept_data_collection *collection,
		int fd
);

#endif /* RRR_IP_ACCEPT_DATA_H */
