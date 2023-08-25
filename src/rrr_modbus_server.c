#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"

#define RRR_MODBUS_PORT 502
#define RRR_MODBUS_BUFFER_SIZE 1024

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_modbus_server");

static void __make_response (
		char *dst_buf,
		size_t *dst_buf_size,
		const char *src_buf,
		const size_t *src_buf_size
) {
	assert(*dst_buf_size >= *src_buf_size);

	memcpy(dst_buf, src_buf, *src_buf_size);
	*dst_buf_size = *src_buf_size;

	uint8_t exception = 0x01; /* Illegal function */

	printf("Request %u received, making response.\n", dst_buf[7]);

	switch(dst_buf[7]) { // Function code
		case 0x01:
			if (dst_buf[10] == 0 || dst_buf[11] == 16) {
				dst_buf[4] = 0;     // Length high
				dst_buf[5] = 4;     // Length low
				dst_buf[8] = 2;     // Byte count
				dst_buf[9] = 0x01;  // Coil status 0
				dst_buf[10] = 0x01; // Coil status 1
				(*dst_buf_size)--;
				break;
			}
			exception = 0x02; /* Illegal data address */
			goto exception;
		default:
			goto exception;
	}

	return;
	exception:
		dst_buf[7] += 0x80;
		dst_buf[8] = exception;
		(*dst_buf_size) -= 3;
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

			buf_size = bytes;
			buf2_size = sizeof(buf2);

			__make_response(buf2, &buf2_size, buf, &buf_size);

			if (write(client_fd, buf2, buf2_size) != (ssize_t) buf2_size) {
				fprintf(stderr, "Write to client failed: %s\n", rrr_strerror(errno));
				continue;
			}
		}
	}

	goto out;
	out_close:
		close(server_fd);
	out:
		rrr_strerror_cleanup();
		return ret;
}
