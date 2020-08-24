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

#ifndef RRR_INPUT_H
#define RRR_INPUT_H

struct rrr_input_special_key_state {
	int flags_mode_active;
	int flags_blocked;
};

int rrr_input_device_grab (int fd);
int rrr_input_device_read_key_character (
		char *c,
		int fd,
		int socket_read_flags
);

#endif /* RRR_INPUT_H */
