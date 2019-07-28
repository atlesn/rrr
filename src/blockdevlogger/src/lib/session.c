/*

Block Device Logger

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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "session.h"
#include "io.h"
#include "../include/bdl.h"

void bdl_init_session (struct bdl_session *session) {
	session->usercount = 0;
}

int bdl_start_session (struct bdl_session *session, const char *device_path, int no_mmap) {
	if (session->usercount > 0) {
		if (device_path != NULL) {
			fprintf (stderr, "Device argument dev=DEVICE was given while session was already open\n");
			return 1;
		}
		session->usercount++;
		return 0;
	}

	if (device_path == NULL) {
		fprintf (stderr, "Device argument dev=DEVICE was missing\n");
		return 1;
	}

	if (io_open(device_path, &session->device, no_mmap) != 0) {
		fprintf (stderr, "Error while opening %s\n", device_path);
		return 1;
	}

	session->usercount = 1;

	return 0;
}

void bdl_close_session (struct bdl_session *session) {
	if (session->usercount <= 0) {
		fprintf (stderr, "Bug: close_session called while no session was active\n");
		exit (EXIT_FAILURE);
	}

	session->usercount--;

	if (session->usercount == 0) {
		io_close(&session->device);
	}

	return;
}
