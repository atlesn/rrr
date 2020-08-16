/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <inttypes.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "test.h"
#include "test_inet.h"
#include "../lib/log.h"
#include "../lib/ip/ip_util.h"

int rrr_test_inet (void) {
	struct sockaddr_in6 in6;
	struct sockaddr_in in;
	struct sockaddr_storage target;

	memset(&in6, '\0', sizeof(in6));
	memset(&in, '\0', sizeof(in));
	memset(&target, '\0', sizeof(target));

	socklen_t target_len = sizeof(target);

	// Check IPv4 mapped IPv6 conversion

	if (inet_pton(AF_INET6, "::ffff:127.0.0.1", &in6.sin6_addr) != 1) {
		TEST_MSG("Could not initialize IPv4 mapped IPv6 address\n");
		return 1;
	}
	if (inet_pton(AF_INET, "127.0.0.1", &in.sin_addr) != 1) {
		TEST_MSG("Could not initialize IPv4 address\n");
		return 1;
	}

	in6.sin6_family = AF_INET6;
	in.sin_family = AF_INET;

	rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed (
		&target,
		&target_len,
		(const struct sockaddr *) &in6,
		sizeof(in6)
	);


	char buf_a[256];
	char buf_b[256];

	rrr_ip_to_str(buf_a, sizeof(buf_a), (const struct sockaddr *) &in, sizeof(in));
	rrr_ip_to_str(buf_b, sizeof(buf_b), (const struct sockaddr *) &target, target_len);

	int result = 0;

	if (target_len != sizeof(in)) {
		TEST_MSG("IPv4 mapped IPv6 to IPv4 convesion failure: Size mismatch %u vs %llu\n",
			target_len, (long long unsigned) sizeof(in));
		result |= 1;
	}

	if (strcmp(buf_a, buf_b) != 0) {
		TEST_MSG("IPv4 mapped IPv4 convesion failure: Result mismatch %s vs %s\n", buf_a, buf_b);
		result |= 1;
	}

	if (result) {
		return 1;
	}

	return 0;
}
