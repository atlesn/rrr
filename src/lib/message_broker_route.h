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

#ifndef RRR_MESSAGE_BROKER_ROUTE_H
#define RRR_MESSAGE_BROKER_ROUTE_H

#include "linked_list.h"

struct rrr_message_broker_route_leg {
	RRR_LL_NODE(struct rrr_message_broker_route_leg);
	const void *leg_id;
};

struct rrr_message_broker_route {
	RRR_LL_HEAD(struct rrr_message_broker_route_leg);
};

void rrr_message_broker_route_clear (
		struct rrr_message_broker_route *route
);
int rrr_message_broker_route_push (
		struct rrr_message_broker_route *route,
		const void *leg_id
);

#endif /* RRR_MESSAGE_BROKER_ROUTE_H */
