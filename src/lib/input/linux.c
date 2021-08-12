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

#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef RRR_WITH_FREEBSD_INPUT
#	include <dev/evdev/input.h>
#else
#	include <linux/input.h>
#endif

#include "../log.h"
#include "../allocator.h"
#include "linux.h"
#include "../socket/rrr_socket_read.h"
#include "../rrr_strerror.h"
#include "../read_constants.h"

int rrr_input_linux_device_grab (int fd, int onoff) {
	// Valgrind complains here with false positive
	//   Syscall param ioctl(generic) points to unaddressable byte(s)
	if (ioctl (fd, EVIOCGRAB, (onoff ? (void *) 1 : (void *) 0)) != 0) {
		RRR_DBG_3("Note: EVIOCGRAB (%i) failed for fd %i: %s\n",
				onoff, fd, rrr_strerror(errno));
		return 1;
	}
	return 0;
}

int rrr_input_linux_device_read_key (
		unsigned int *key,
		unsigned int *is_down,
		int fd,
		int socket_read_flags
) {
	int ret = RRR_READ_OK;

	*key = 0;
	*is_down = 0;

	struct input_event event = {0};
	rrr_biglength bytes_read = 0;
	if ((ret = rrr_socket_read (
			(char *) &event,
			&bytes_read,
			fd,
			sizeof(event),
			NULL,
			NULL,
			socket_read_flags
	)) != 0) {
		goto out;
	}

	if (bytes_read == 0) {
		ret = RRR_READ_INCOMPLETE;
		goto out;
	}

	if (event.type == EV_KEY && event.value >= 0 && event.value <= 2) {
		*key = event.code;
		*is_down = (event.value != 0);
	}

	out:
	return ret;
}

