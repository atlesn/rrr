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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"
#include "msg_addr.h"
#include "msg.h"
#include "../ip/ip_util.h"

int rrr_msg_addr_to_host (struct rrr_msg_addr *msg) {
	if (!RRR_MSG_ADDR_SIZE_OK(msg)) {
		return 1;
	}

	return 0;
}

void rrr_msg_addr_init_head (struct rrr_msg_addr *target, uint64_t addr_len) {
	rrr_msg_populate_head (
			(struct rrr_msg *) target,
			RRR_MSG_TYPE_MESSAGE_ADDR,
			sizeof(*target),
			0
	);
	RRR_MSG_ADDR_SET_ADDR_LEN(target, addr_len);
}

void rrr_msg_addr_init (struct rrr_msg_addr *target) {
	memset(target, '\0', sizeof(*target));
	rrr_msg_addr_init_head(target, 0);
}

int rrr_msg_addr_new (struct rrr_msg_addr **target) {
	*target = NULL;

	struct rrr_msg_addr *result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memorty in rrr_msg_addr_new");
		return 1;
	}

	rrr_msg_addr_init(result);

	*target = result;

	return 0;
}

int rrr_msg_addr_clone (
		struct rrr_msg_addr **target,
		const struct rrr_msg_addr *source
) {
	int ret = 0;

	struct rrr_msg_addr *new_message = NULL;

	if ((ret = rrr_msg_addr_new(&new_message)) != 0) {
		goto out;
	}

	*new_message = *source;
	*target = new_message;
	new_message = NULL;

	out:
	return ret;
}

void rrr_msg_addr_to_str (
		char *target,
		size_t target_size,
		const struct rrr_msg_addr *msg
) {
	rrr_ip_to_str (target, target_size, (const struct sockaddr *) msg->addr, sizeof(msg->addr));
}
