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
#include <unistd.h>
#include <stdlib.h>

#include "../log.h"
#include "../allocator.h"
#include "../util/macro_utils.h"
#include "../rrr_strerror.h"

// Allow speed > 38400 on BSD
#ifdef __BSD_VISIBLE
#	undef __BSD_VISIBLE
#endif
#define __BSD_VISIBLE 1
#include <termios.h>

int rrr_serial_check (int *is_serial, int fd) {
	*is_serial = 0;

	int ret = 0;

	struct termios termios_p;

	if (tcgetattr(fd, &termios_p) != 0) {
		if (errno == EINVAL) {
			// Not serial device
			goto out;
		}

		RRR_MSG_0("Could not get termios attributes of fd %i: %s\n", fd, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	*is_serial = 1;

	out:
	return ret;
}

#define RRR_SERIAL_SPEED_CASE(speed)	\
	case speed:							\
	*target = RRR_PASTE(B,speed);		\
	break

static int __rrr_serial_speed_convert (speed_t *target, unsigned int speed) {
	switch (speed) {
		RRR_SERIAL_SPEED_CASE(0);
		RRR_SERIAL_SPEED_CASE(50);
		RRR_SERIAL_SPEED_CASE(75);
		RRR_SERIAL_SPEED_CASE(110);
		RRR_SERIAL_SPEED_CASE(134);
		RRR_SERIAL_SPEED_CASE(150);
		RRR_SERIAL_SPEED_CASE(200);
		RRR_SERIAL_SPEED_CASE(300);
		RRR_SERIAL_SPEED_CASE(600);
		RRR_SERIAL_SPEED_CASE(1200);
		RRR_SERIAL_SPEED_CASE(1800);
		RRR_SERIAL_SPEED_CASE(2400);
		RRR_SERIAL_SPEED_CASE(4800);
		RRR_SERIAL_SPEED_CASE(9600);
		RRR_SERIAL_SPEED_CASE(19200);
		RRR_SERIAL_SPEED_CASE(38400);
		RRR_SERIAL_SPEED_CASE(57600);
		RRR_SERIAL_SPEED_CASE(115200);
		RRR_SERIAL_SPEED_CASE(230400);
		default:
			return 1;
	}
	return 0;
}

int rrr_serial_speed_check (unsigned int speed) {
	speed_t dummy;
	return __rrr_serial_speed_convert(&dummy, speed);
}

#define RRR_SERIAL_DEFINE_AND_GET_ATTR()														\
	struct termios termios_p;																	\
	do {if (tcgetattr(fd, &termios_p) != 0) {													\
		RRR_MSG_0("Could not get termios attributes of fd %i: %s\n", fd, rrr_strerror(errno));	\
		ret = 1;																				\
		goto out;																				\
	}} while (0)

#define RRR_SERIAL_SET_ATTR()																	\
	do {if (tcsetattr (fd, TCSANOW, &termios_p) != 0) {											\
		RRR_MSG_0("Could not set termios attributes of fd %i: %s\n", fd, rrr_strerror(errno));	\
		ret = 1;																				\
		goto out;																				\
	}} while(0)

int rrr_serial_speed_set (int fd, unsigned int speed_bps) {
	int ret = 0;

	RRR_SERIAL_DEFINE_AND_GET_ATTR();

	speed_t speed = B0;

	if ((ret = __rrr_serial_speed_convert(&speed, speed_bps)) != 0) {
		RRR_BUG("Invalid speed %u to rrr_serial_set_speed, caller must check speed with rrr_serial_speed_check first\n", speed_bps);
	}

	if (cfsetospeed (&termios_p, speed) != 0) {
		RRR_MSG_0("cfsetospeed on fd %i failed, speed was %u: %s\n",
				fd, speed_bps, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (cfsetispeed (&termios_p, speed) != 0) {
		RRR_MSG_0("cfsetispeed on fd %i failed, speed was %u: %s\n",
				fd, speed_bps, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	RRR_SERIAL_SET_ATTR();

	out:
	return ret;
}

int rrr_serial_raw_set (int fd) {
	int ret = 0;

	RRR_SERIAL_DEFINE_AND_GET_ATTR();

	// BSD-specific
	// cfmakeraw(&termios_p);

	// Copied from termios man page
    termios_p.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    termios_p.c_oflag &= ~OPOST;
    termios_p.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    termios_p.c_cflag &= ~(CSIZE | PARENB);
    termios_p.c_cflag |= CS8;

	RRR_SERIAL_SET_ATTR();

	out:
	return ret;
}

int rrr_serial_parity_set (int fd, int is_odd) {
	int ret = 0;

	RRR_SERIAL_DEFINE_AND_GET_ATTR();

	termios_p.c_cflag |= PARENB;

	if (is_odd) {
		termios_p.c_cflag |= PARODD;
	}

	RRR_SERIAL_SET_ATTR();

	out:
	return ret;
}

int rrr_serial_stop_bit_set (int fd, int is_two) {
	int ret = 0;

	RRR_SERIAL_DEFINE_AND_GET_ATTR();

	if (is_two) {
		termios_p.c_cflag |= CSTOPB;
	}
	else {
		termios_p.c_cflag &= ~(CSTOPB);
	}

	RRR_SERIAL_SET_ATTR();

	out:
	return ret;
}

int rrr_serial_parity_unset (int fd) {
	int ret = 0;

	RRR_SERIAL_DEFINE_AND_GET_ATTR();

	termios_p.c_cflag &= ~(PARENB|PARODD);

	RRR_SERIAL_SET_ATTR();

	out:
	return ret;
}
