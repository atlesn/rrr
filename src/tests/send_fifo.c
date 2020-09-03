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

#include <errno.h>
#include <string.h>

#include "../lib/log.h"
#include "../lib/rrr_strerror.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/util/posix.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("send_fifo");

int main (int argc, char **argv) {
	int ret = 0;
	int fd = 0;

	rrr_strerror_init();

	if ((ret = rrr_log_init()) != 0) {
		goto out;
	}

	if (argc != 2) {
		RRR_MSG_0("Filename argument missing to send_fifo\n");
		ret = 1;
		goto out_cleanup_log;
	}

	if ((ret = rrr_socket_fifo_create(&fd, argv[1], "main", 1, 1, 1)) != 0) {
		RRR_MSG_0("Failed to create fifo pipe in send_fifo\n");
		goto out_cleanup_log;
	}

	rrr_posix_usleep(1000000);

	char buf[1024];
	int bytes = read(STDIN_FILENO, buf, 1024);
	if (bytes == 0) {
		RRR_MSG_0("No data on stdin to send_fifo\n");
		ret = 1;
		goto out_cleanup_log;
	}

	if (bytes == sizeof(buf)) {
		RRR_MSG_0("Too many bytes read in send_fifo\n");
		ret = 1;
		goto out_cleanup_log;
	}

	if ((ret = write(fd, buf, bytes)) != bytes) {
		RRR_MSG_0("Write to fifo failed: %s, %i of %i bytes written in send_fifo\n",
				rrr_strerror(errno), ret, bytes);
		ret = 1;
		goto out_cleanup_log;
	}

	out_cleanup_log:
		rrr_log_cleanup();
	out:
		rrr_socket_close_all();
		rrr_strerror_cleanup();
		return ret;
}
