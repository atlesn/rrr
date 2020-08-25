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

#ifndef RRR_LINUX_INPUT_H
#define RRR_LINUX_INPUT_H

int rrr_input_linux_device_grab (int fd, int onoff);
int rrr_input_linux_device_read_key (
		unsigned int *key,
		unsigned int *is_down,
		int fd,
		int socket_read_flags
);

#endif /* RRR_LINUX_INPUT_H */
