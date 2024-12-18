/*

Read Route Record

Copyright (C) 2018-2022 Atle Solbakken atle@goliathdns.no

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
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../log.h"
#include "../allocator.h"
#include "ip_util.h"
#include "../rrr_strerror.h"

int rrr_ip_addr_is_any (
		const struct sockaddr *addr
) {
	int ret = 0;

	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
		struct in6_addr zero = {0};
		ret = 0 == memcmp(&in->sin6_addr, &zero, sizeof(zero));
	}
	else if (addr->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *) addr;
		struct in_addr zero = {0};
		ret = 0 == memcmp(&in->sin_addr, &zero, sizeof(zero));
	}
	else {
		RRR_BUG("Unknown address family %u to %s\n", addr->sa_family, __func__);
	}

	return ret;
}

uint16_t rrr_ip_addr_get_port (
		const struct sockaddr *addr
) {
	uint16_t port = 0;

	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
		port = ntohs(in->sin6_port);
	}
	else if (addr->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *) addr;
		port = ntohs(in->sin_port);
	}
	else {
		RRR_BUG("Unknown address family %u to %s\n", addr->sa_family, __func__);
	}

	return port;
}

void rrr_ip_to_str (
		char *dest,
		rrr_biglength dest_size,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	const char *result = NULL;

	*dest = '\0';

	if (sizeof(rrr_biglength) > sizeof(size_t) && dest_size > SIZE_MAX) {
		dest_size = SIZE_MAX;
	}

	if (addr == NULL || addr_len == 0) {
		snprintf(dest, (size_t) dest_size, "[null]");
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
			snprintf(dest, (size_t) dest_size, "[Unknown address family %i]", addr->sa_family);
			goto out;
		}

		char buf[256];
		*buf = '\0';
		result = inet_ntop(addr->sa_family, addr_final, buf, sizeof(buf));
		buf[256 - 1] = '\0';

		if (result == NULL) {
			snprintf(dest, (size_t) dest_size, "[Unknown address of length %i]", addr_len);
			goto out;
		}

		snprintf(dest, (size_t) dest_size, "[%s:%u]", buf, ntohs(port_final));
	}

	out:
	dest[dest_size - 1] = '\0';
}

int rrr_ip_to_str_and_port (
		uint16_t *target_port,
		char *target_ip,
		socklen_t target_ip_size,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	*target_port = 0;
	*target_ip = '\0';

	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if (addr_len == sizeof(*in6)) {
		if (inet_ntop(AF_INET6, &in6->sin6_addr, target_ip, target_ip_size) == NULL) {
			RRR_MSG_0("Could not convert IPv6 address to string: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		*target_port = ntohs(in6->sin6_port);
	}
	else if (addr_len == sizeof(*in)) {
		if (inet_ntop(AF_INET, &in->sin_addr, target_ip, target_ip_size) == NULL) {
			RRR_MSG_0("Could not convert IPv4 address to string: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		*target_port = ntohs(in->sin_port);
	}
	else {
		RRR_MSG_0("Unknown address length %llu while extracting IP and port\n", (long long unsigned) addr_len);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

void rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed (
		struct sockaddr_storage *target,
		socklen_t *target_len,
		const struct sockaddr *source,
		const socklen_t source_len
) {
	// Allow target and source to be the same
	struct sockaddr_storage source_tmp;

	assert(sizeof(source_tmp) >= source_len);
	memcpy(&source_tmp, source, source_len);

	const struct sockaddr_in6 *source_in6 = (const struct sockaddr_in6 *) &source_tmp;

	if (source_len != sizeof(*source_in6) || source->sa_family != AF_INET6) {
		goto out_copy;
	}

	// RFC4291

#if defined HAVE_INET_IN6_BSD
	uint32_t zero_a = source_in6->sin6_addr.__u6_addr.__u6_addr32[0];
	uint32_t zero_b = source_in6->sin6_addr.__u6_addr.__u6_addr32[1];
	uint32_t zero_c = source_in6->sin6_addr.__u6_addr.__u6_addr16[4];
	uint32_t ffff = source_in6->sin6_addr.__u6_addr.__u6_addr16[5];
	uint32_t ipv4 = source_in6->sin6_addr.__u6_addr.__u6_addr32[3];
#elif defined HAVE_INET_IN6_LINUX
	uint32_t zero_a = source_in6->sin6_addr.__in6_u.__u6_addr32[0];
	uint32_t zero_b = source_in6->sin6_addr.__in6_u.__u6_addr32[1];
	uint32_t zero_c = source_in6->sin6_addr.__in6_u.__u6_addr16[4];
	uint32_t ffff = source_in6->sin6_addr.__in6_u.__u6_addr16[5];
	uint32_t ipv4 = source_in6->sin6_addr.__in6_u.__u6_addr32[3];
#elif defined HAVE_INET_IN6_MUSL
	uint32_t zero_a = source_in6->sin6_addr.__in6_union.__s6_addr32[0];
	uint32_t zero_b = source_in6->sin6_addr.__in6_union.__s6_addr32[1];
	uint32_t zero_c = source_in6->sin6_addr.__in6_union.__s6_addr16[4];
	uint32_t ffff = source_in6->sin6_addr.__in6_union.__s6_addr16[5];
	uint32_t ipv4 = source_in6->sin6_addr.__in6_union.__s6_addr32[3];
#else
#	error "Neither HAVE_INET_IN6_BSD, HAVE_INET_IN6_LINUX nor HAVE_INET_IN6_MUSL was defined"
#endif

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
		memcpy(target, &source_tmp, source_len);
		*target_len = source_len;
	out:
	return;
}

int rrr_ip_check (
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	char buf[128];

	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if (addr_len == sizeof(*in6) && addr->sa_family == AF_INET6) {
		// OK
	}
	else if (addr_len == sizeof(*in) && addr->sa_family == AF_INET) {
		// OK
	}
	else {
		// NOT OK
		return 1;
	}

	return inet_ntop(addr->sa_family, addr, buf, sizeof(buf)) == NULL
		? 1
		: 0
	;
}

void rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed_alt (
		struct sockaddr *addr,
		socklen_t *addr_len
) {
	return rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed (
			(struct sockaddr_storage *) addr,
			addr_len,
			addr,
			*addr_len
	);
}
