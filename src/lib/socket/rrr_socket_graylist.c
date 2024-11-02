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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "../log.h"
#include "../allocator.h"
#include "rrr_socket_graylist.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../util/linked_list.h"

struct rrr_socket_graylist {
	RRR_LL_HEAD(struct rrr_socket_graylist_entry);
};

struct rrr_socket_graylist_entry {
	RRR_LL_NODE(struct rrr_socket_graylist_entry);
	struct sockaddr_storage addr;
	socklen_t addr_len;
	uint64_t expire_time;
	int flags;
};

void rrr_socket_graylist_get (
		int *flags,
		struct rrr_socket_graylist *list,
		const struct sockaddr *addr,
		socklen_t len
) {
	*flags = 0;

	uint64_t time_now = rrr_time_get_64();
	RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_graylist_entry);
		if (time_now > node->expire_time) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->addr_len == len) {
			if (memcmp(&node->addr, addr, len) == 0) {
				*flags |= node->flags;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; rrr_free(node));
}

int rrr_socket_graylist_count (
		struct rrr_socket_graylist *list,
		const struct sockaddr *addr,
		socklen_t len
) {
	int count = 0;

	uint64_t time_now = rrr_time_get_64();
	RRR_LL_ITERATE_BEGIN(list, struct rrr_socket_graylist_entry);
		if (time_now > node->expire_time) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->addr_len == len) {
			if (memcmp(&node->addr, addr, len) == 0) {
				count++;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, 0; rrr_free(node));

	return count;
}

int rrr_socket_graylist_exists (
		struct rrr_socket_graylist *list,
		const struct sockaddr *addr,
		socklen_t len
) {
	return rrr_socket_graylist_count(list, addr, len) > 0;
}

static int __rrr_socket_graylist_push (
		struct rrr_socket_graylist *target,
		const struct sockaddr *addr,
		socklen_t len,
		uint64_t graylist_period_us,
		int flags
) {
	int ret = 0;

	struct rrr_socket_graylist_entry *new_entry = NULL;

	if (graylist_period_us == 0) {
		goto out;
	}

	if ((new_entry = rrr_allocate(sizeof(*new_entry))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_graylist_push\n");
		ret = 1;
		goto out;
	}

	memset(new_entry, '\0', sizeof(*new_entry));

	if (len > sizeof(new_entry->addr)) {
		RRR_BUG("BUG: address length too long in __rrr_socket_graylist_push %u > %llu\n",
			len, (long long unsigned) sizeof(new_entry->addr));
	}

	memcpy (&new_entry->addr, addr, len);
	new_entry->addr_len = len;
	new_entry->expire_time = rrr_time_get_64() + graylist_period_us;
	new_entry->flags = flags;

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
		uint64_t graylist_period_us,
		int flags
) {
	return __rrr_socket_graylist_push(target, addr, len, graylist_period_us, flags);
}

void rrr_socket_graylist_flags_clear (
		struct rrr_socket_graylist *target,
		const struct sockaddr *addr,
		socklen_t len,
		int flags
) {
	RRR_LL_ITERATE_BEGIN(target, struct rrr_socket_graylist_entry);
		if (node->addr_len == len) {
			if (memcmp(&node->addr, addr, len) == 0) {
				node->flags &= ~(flags);
			}
		}
		if (node->flags == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(target, 0; rrr_free(node));
}

void rrr_socket_graylist_destroy (
		struct rrr_socket_graylist *target
) {
	RRR_LL_DESTROY(target, struct rrr_socket_graylist_entry, rrr_free(node));
	rrr_free(target);
}

void rrr_socket_graylist_destroy_void (
		void *target
) {
	rrr_socket_graylist_destroy(target);
}

int rrr_socket_graylist_new (
		struct rrr_socket_graylist **target
) {
	int ret = 0;

	struct rrr_socket_graylist *graylist;

	*target = NULL;

	if ((graylist = rrr_allocate_zero(sizeof(*graylist))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*target = graylist;

	out:
	return ret;
}
