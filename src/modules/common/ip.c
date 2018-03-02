/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include "ip.h"
#include "../../lib/messages.h"

int ip_receive_packets(int fd, void (*callback)(struct ip_buffer_entry *entry, void *arg), void *arg) {
	struct sockaddr src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	char errbuf[256];

	struct pollfd fds;
	fds.fd = fd;
	fds.events = POLLIN;

	char buffer[MSG_STRING_MAX_LENGTH];

	while (1) {
		int res = poll(&fds, 1, 500);
		if (res == -1) {
			fprintf (stderr, "Error from poll when reading data from network: %s\n", strerror(errno));
			return 1;
		}
		else if (!(fds.revents & POLLIN)) {
			break;
		}

		memset(buffer, '\0', MSG_STRING_MAX_LENGTH);
		ssize_t count = recvfrom(fd, buffer, MSG_STRING_MAX_LENGTH, 0, &src_addr, &src_addr_len);

		if (count == -1) {
			fprintf (stderr, "Error from recvfrom when reading data from network: %s\n", strerror(errno));
			return 1;
		}

		if (count < 10) {
			fprintf (stderr, "Received short packet from network\n");
			continue;
		}

		char *start = buffer;
		if (*start != '\0') {
			fprintf (stderr, "Datagram received from network did not start with zero\n");
			continue;
		}

		start++;
		count--;

		struct ip_buffer_entry *entry = malloc(sizeof(*entry));
		memset(entry, '\0', sizeof(*entry));

		entry->addr = src_addr;
		entry->addr_len = src_addr_len;

		if (parse_message(start, count, &entry->message) != 0) {
			fprintf (stderr, "Received invalid message\n");
			free (entry);
			continue;
		}

		if (message_checksum_check(&entry->message) != 0) {
			fprintf (stderr, "Message checksum was invalid for '%s'\n", start);
			free (entry);
			continue;
		}
		else {
			callback(entry, arg);
		}
	}

	return 0;
}
