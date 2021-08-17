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

#ifndef RRR_IP_UTIL_H
#define RRR_IP_UTIL_H

#include <sys/socket.h>

#include "../rrr_types.h"

void rrr_ip_to_str (
		char *dest, rrr_biglength dest_size, const struct sockaddr *addr, socklen_t addr_len
);
int rrr_ip_to_str_and_port (
		uint16_t *target_port,
		char *target_ip,
		socklen_t target_ip_size,
		const struct sockaddr *addr,
		socklen_t addr_len
);
void rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed (
		struct sockaddr_storage *target,
		socklen_t *target_len,
		const struct sockaddr *source,
		const socklen_t source_len
);

#endif /* RRR_IP_UTIL_H */
