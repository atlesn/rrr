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

#include "../global.h"
#include "message_addr.h"
#include "rrr_socket_msg.h"

int rrr_message_addr_to_host (struct rrr_message_addr *msg) {
	msg->addr_len = be64toh(msg->addr_len);

	if (	msg->addr_len > sizeof(msg->addr) ||
			msg->msg_size != sizeof(struct rrr_message_addr) ||
			msg->msg_size - msg->network_size != 0
	) {
		return 1;
	}

	return 0;
}

void rrr_message_addr_init (struct rrr_message_addr *target) {
	memset(target, '\0', sizeof(*target));

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) target,
			RRR_SOCKET_MSG_TYPE_MESSAGE_ADDR,
			sizeof(struct rrr_message_addr),
			0
	);
}

int rrr_message_addr_new (struct rrr_message_addr **target) {
	*target = NULL;

	struct rrr_message_addr *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_ERR("Could not allocate memorty in rrr_message_addr_new");
		return 1;
	}

	rrr_message_addr_init(result);

	*target = result;

	return 0;
}
