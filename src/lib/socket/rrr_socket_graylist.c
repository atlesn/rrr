/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "../log.h"
#include "rrr_socket_graylist.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../util/linked_list.h"

struct rrr_socket_graylist_entry {
	RRR_LL_NODE(struct rrr_socket_graylist_entry);
	struct sockaddr_storage addr;
	socklen_t addr_len;
	uint64_t expire_time;
};

int rrr_socket_graylist_exists (
		struct rrr_socket_graylist *list,
		const struct sockaddr *addr,
		socklen_t len
) {
	uint64_t time_now = rrr_time_get_64();
	RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_graylist_entry);
		if (time_now > node->expire_time) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->addr_len == len) {
			if (memcmp(&node->addr, addr, len) == 0) {
				return 1;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; free(node));
	return 0;
}

static int __rrr_socket_graylist_push (
		struct rrr_socket_graylist *target,
		const struct sockaddr *addr,
		socklen_t len,
		uint64_t graylist_period_us
) {
	int ret = 0;

	struct rrr_socket_graylist_entry *new_entry = NULL;

	if (graylist_period_us == 0) {
		goto out;
	}

	if ((new_entry = malloc(sizeof(*new_entry))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_graylist_push\n");
		ret = 1;
		goto out;
	}

	memset(new_entry, '\0', sizeof(*new_entry));

	if (len > sizeof(new_entry->addr)) {
		RRR_BUG("BUG: address length too long in __rrr_socket_graylist_push %u > %lu\n",
			len, sizeof(new_entry->addr));
	}

	memcpy (&new_entry->addr, addr, len);
	new_entry->addr_len = len;
	new_entry->expire_time = rrr_time_get_64() + graylist_period_us;

	RRR_LL_APPEND(target, new_entry);
	new_entry = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(new_entry);
	return ret;
}

int rrr_socket_graylist_push (
		struct rrr_socket_graylist *target,
		const struct sockaddr *addr,
		socklen_t len,
		uint64_t graylist_period_us
) {
	return __rrr_socket_graylist_push(target, addr, len, graylist_period_us);
}

void rrr_socket_graylist_clear (
		struct rrr_socket_graylist *target
) {
	RRR_LL_DESTROY(target, struct rrr_socket_graylist_entry, free(node));
}

void rrr_socket_graylist_clear_void (
		void *target
) {
	return rrr_socket_graylist_clear(target);
}

void rrr_socket_graylist_init (
		struct rrr_socket_graylist *target
) {
	memset(target, '\0', sizeof(*target));
}
