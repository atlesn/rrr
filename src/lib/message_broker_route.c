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

#include "log.h"

#include "message_broker_route.h"
#include "linked_list.h"

#include <stdlib.h>
#include <string.h>

void rrr_message_broker_route_clear (
		struct rrr_message_broker_route *route
) {
	RRR_LL_DESTROY(route, struct rrr_message_broker_route_leg, free(node));
}

int rrr_message_broker_route_push (
		struct rrr_message_broker_route *route,
		const void *leg_id
) {
	struct rrr_message_broker_route_leg *new_leg = malloc(sizeof(*new_leg));
	if (new_leg == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_message_broker_route_push\n");
		return 1;
	}

	memset(new_leg, '\0', sizeof(*new_leg));
	new_leg->leg_id = leg_id;

	RRR_LL_APPEND(route, new_leg);

	return 0;
}
