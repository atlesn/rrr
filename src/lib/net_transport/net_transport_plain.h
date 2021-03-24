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

#ifndef RRR_NET_TRANSPORT_PLAIN_H
#define RRR_NET_TRANSPORT_PLAIN_H

#include "net_transport.h"
#include "net_transport_struct.h"

#include "../ip/ip.h"

struct rrr_net_transport_plain {
	RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport_plain);
};

struct rrr_net_transport_plain_data {
	struct rrr_ip_data ip_data;
};

int rrr_net_transport_plain_new (struct rrr_net_transport_plain **target);

#endif /* RRR_NET_TRANSPORT_PLAIN_H */
