/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_TYPES_H
#define RRR_NET_TRANSPORT_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef int rrr_net_transport_handle;

struct rrr_net_transport_vector {
	uint8_t *base;
	size_t len;
};

#endif /* RRR_NET_TRANSPORT_TYPES_H */
