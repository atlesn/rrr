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

#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

// Allow INADDR_LOOPBACK
#undef __BSD_VISIBLE
#define __BSD_VISIBLE 1

#include <netinet/in.h>

int main (int argc, char **argv) {
	int ret = 0;
	int fd = 0;

	if (argc != 2) {
		fprintf(stderr, "Port number argument missing to send_ip\n");
		ret = 1;
		goto out;
	}

	char *end;
	unsigned long long port = strtoull(argv[1], &end, 10);
	if (end - argv[1] != strlen(argv[1]) || port == 0 || port > 65535) {
		fprintf (stderr, "Invalid port argument '%s' to send_ip\n", argv[1]);
		ret = 1;
		goto out;
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "Could not open socket: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	char buf[1024];
	int bytes = read(STDIN_FILENO, buf, 1024);
	if (bytes == 0) {
		fprintf(stderr, "No data on stdin to send_ip\n");
		ret = 1;
		goto out;
	}

	if (bytes == sizeof(buf)) {
		fprintf (stderr, "Too many bytes read in send_ip\n");
		ret = 1;
		goto out;
	}

	struct sockaddr_in sockaddr;
	socklen_t socklen = sizeof(sockaddr);

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(port);

	if (sendto(fd, buf, bytes, 0, (struct sockaddr *) &sockaddr, socklen) != bytes) {
		fprintf (stderr, "Could not send all bytes in send_ip: %s", strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	if (fd > 0) {
		close(fd);
	}
	return ret;
}
