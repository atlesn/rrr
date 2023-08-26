/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/random.h"
#include "lib/util/rrr_endian.h"

#define RRR_MODBUS_PORT 502
#define RRR_MODBUS_BUFFER_SIZE 1024

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_modbus_server");

static int __make_response (
		char *dst_buf,
		size_t *dst_buf_size,
		const char *src_buf,
		const size_t *src_buf_size
) {
	int ret = 0;
/*
	if (rrr_rand() % 100 > 90) {
		rrr_random_string(dst_buf, *dst_buf_size);
		size_t size = ((size_t) rrr_rand()) % 10 + 1;
		assert(*dst_buf_size >= size);
		*dst_buf_size = size;
		printf("Generated random junk data size %llu\n", (unsigned long long) size);
		goto out;
	}
*/
	assert(*dst_buf_size >= *src_buf_size);

	memcpy(dst_buf, src_buf, *src_buf_size);
	*dst_buf_size = *src_buf_size;

	uint8_t exception = 0x01; /* Illegal function */

	if (*src_buf_size < 7) {
		printf("Frame too short\n");
		ret = 1;
		goto out;
	}
	printf("Request %u received, making response.\n", dst_buf[7]);

	uint16_t length = rrr_be16toh(*((uint16_t *) &dst_buf[4]));

	switch(dst_buf[7]) { // Function code
		case 0x01:
			if (dst_buf[10] != 0 || dst_buf[11] != 8) {
				printf("Illegal address/quantity %u/%u for function 0x01\n", dst_buf[10], dst_buf[11]);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			if (length < 6) {
				printf("Length %u too short function 0x01\n", length);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			if ((size_t) length + 6 < *dst_buf_size) {
				printf("Reported length %lu less than buffer size %lu for function 0x01\n", (size_t) length + 6, *dst_buf_size);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 4;     // Length low
			dst_buf[8] = 1;     // Byte count
			dst_buf[9] = 0x01;  // Coil status 0
			*dst_buf_size = 10;
			break;
		default:
			printf("Illegal function 0x%u\n", dst_buf[7]);
			goto exception;
	}

	goto out;
	exception:
		dst_buf[4] = 0;     // Length high
		dst_buf[5] = 3;     // Length low
		dst_buf[7] += 0x80;
		dst_buf[8] = (char) exception;
		*dst_buf_size = 9;
	out:
		return ret;
}

int main(int argc, const char **argv) {
	int ret = EXIT_SUCCESS;

	(void)(argc);
	(void)(argv);

	int server_fd, client_fd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len;
	ssize_t bytes;
	char buf[RRR_MODBUS_BUFFER_SIZE];
	char buf2[RRR_MODBUS_BUFFER_SIZE];
	size_t buf_size, buf2_size;

	rrr_strerror_init();

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed to create listening socket: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	memset(&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(RRR_MODBUS_PORT);

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		fprintf(stderr, "Failed bind to TCP port %u: %s\n", RRR_MODBUS_PORT, rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out_close;
	}

	if (listen(server_fd, 1) < 0) {
		fprintf(stderr, "Failed to listen: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("Listening on port %u\n", RRR_MODBUS_PORT);

	while (1) {
		client_addr_len = sizeof(client_addr);
		if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
			fprintf(stderr, "Error while accepting: %s\n", rrr_strerror(errno));
			continue;
		}

		while (1) {
			bytes = recv(client_fd, buf, sizeof(buf), 0);
			if (bytes <= 0) {
				printf("Connection closed\n");
				break;
			}

			buf_size = (size_t) bytes;
			buf2_size = sizeof(buf2);

			if (__make_response(buf2, &buf2_size, buf, &buf_size) != 0) {
				break;
			}

			printf("Write response size %lu\n", buf2_size);

			if (write(client_fd, buf2, buf2_size) != (ssize_t) buf2_size) {
				fprintf(stderr, "Write to client failed: %s\n", rrr_strerror(errno));
				break;
			}
		}

		close(client_fd);
	}

	out_close:
		close(server_fd);
	out:
		rrr_strerror_cleanup();
		return ret;
}
