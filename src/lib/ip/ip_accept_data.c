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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../log.h"
#include "../allocator.h"
#include "ip.h"
#include "ip_accept_data.h"

void rrr_ip_accept_data_close_and_destroy (struct rrr_ip_accept_data *accept_data) {
	if (accept_data->ip_data.fd != 0) {
		rrr_ip_close(&accept_data->ip_data);
	}
	rrr_free(accept_data);
}

void rrr_ip_accept_data_close_and_destroy_void (void *accept_data) {
	rrr_ip_accept_data_close_and_destroy(accept_data);
}

void rrr_ip_accept_data_collection_clear(struct rrr_ip_accept_data_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_ip_accept_data, rrr_ip_accept_data_close_and_destroy(node));
}

void rrr_ip_accept_data_collection_clear_void(void *collection) {
	rrr_ip_accept_data_collection_clear(collection);
}

void rrr_ip_accept_data_collection_close_and_remove (
		struct rrr_ip_accept_data_collection *collection,
		struct sockaddr *sockaddr,
		socklen_t socklen
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_ip_accept_data);
		if (node->len == socklen && memcmp(&node->addr, sockaddr, node->len) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_ip_accept_data_close_and_destroy(node));
}

void rrr_ip_accept_data_collection_close_and_remove_by_fd (
		struct rrr_ip_accept_data_collection *collection,
		int fd
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_ip_accept_data);
		if (node->ip_data.fd == fd) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_ip_accept_data_close_and_destroy(node));
}

struct rrr_ip_accept_data *rrr_ip_accept_data_collection_find (
		struct rrr_ip_accept_data_collection *collection,
		const struct sockaddr *sockaddr,
		socklen_t socklen
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_ip_accept_data);
		if (node->len == socklen && memcmp(&node->addr, sockaddr, node->len) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

struct rrr_ip_accept_data *rrr_ip_accept_data_collection_find_by_fd (
		struct rrr_ip_accept_data_collection *collection,
		int fd
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_ip_accept_data);
		if (node->ip_data.fd == fd) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}
