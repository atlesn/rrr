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
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "ip_util.h"

void rrr_ip_to_str (char *dest, size_t dest_size, const struct sockaddr *addr, socklen_t addr_len) {
	const char *result = NULL;

	*dest = '\0';

	if (addr == NULL || addr_len == 0) {
		snprintf(dest, dest_size, "[null]");
	}
	else {
		const void *addr_final = NULL;
		in_port_t port_final = 0;

		if (addr->sa_family == AF_INET) {
			const struct sockaddr_in *in_addr = (const struct sockaddr_in *) addr;
			addr_final = &in_addr->sin_addr;
			port_final = in_addr->sin_port;
		}
		else if (addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6_addr = (const struct sockaddr_in6 *) addr;
			addr_final = &in6_addr->sin6_addr;
			port_final = in6_addr->sin6_port;
		}
		else {
			snprintf(dest, dest_size, "[Unknown address family %i]", addr->sa_family);
			goto out;
		}

		char buf[256];
		*buf = '\0';
		result = inet_ntop(addr->sa_family, addr_final, buf, 256);
		buf[256 - 1] = '\0';

		if (result == NULL) {
			snprintf(dest, dest_size, "[Unknown address of length %i]", addr_len);
			goto out;
		}

		snprintf(dest, dest_size, "[%s:%u]", buf, ntohs(port_final));
	}

	out:
	dest[dest_size - 1] = '\0';
}

void rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed (
		struct sockaddr_storage *target,
		socklen_t *target_len,
		const struct sockaddr *source,
		const socklen_t source_len
) {
	const struct sockaddr_in6 *source_in6 = (const struct sockaddr_in6 *) source;

	if (source_len != sizeof(*source_in6) || source->sa_family != AF_INET6) {
		goto out_copy;
	}

	// RFC4291

	uint32_t zero_a = source_in6->sin6_addr.__in6_u.__u6_addr32[0];
	uint32_t zero_b = source_in6->sin6_addr.__in6_u.__u6_addr32[1];
	uint32_t zero_c = source_in6->sin6_addr.__in6_u.__u6_addr16[4];
	uint32_t ffff = source_in6->sin6_addr.__in6_u.__u6_addr16[5];
	uint32_t ipv4 = source_in6->sin6_addr.__in6_u.__u6_addr32[3];

	//printf ("ipv4: %08x, ffff: %04x zeros: %u,%u,%u\n", ipv4, ffff, zero_a, zero_b, zero_c);

	if (zero_a != 0 || zero_b != 0 || zero_c != 0 || ffff != 0xffff) {
		goto out_copy;
	}

	struct sockaddr_in addr_new;
	memset(&addr_new, '\0', sizeof(addr_new));

	addr_new.sin_port = source_in6->sin6_port;
	addr_new.sin_family = AF_INET;
	addr_new.sin_addr.s_addr = ipv4;

	if (*target_len < sizeof(addr_new)) {
		RRR_BUG("BUG: Target length too small in rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed A\n");
	}

	memcpy(target, &addr_new, sizeof(addr_new));
	*target_len = sizeof(addr_new);

	goto out;
	out_copy:
		if (*target_len < source_len) {
			RRR_BUG("BUG: Target length too small in rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed B\n");
		}
		memcpy(target, source, source_len);
		*target_len = source_len;
	out:
	return;
}
