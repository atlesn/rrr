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

#ifndef RRR_SERIAL_H
#define RRR_SERIAL_H

int rrr_serial_check (int *is_serial, int fd);
int rrr_serial_speed_check (unsigned long long speed);
int rrr_serial_speed_set (int fd, unsigned long long speed_bps);
int rrr_serial_raw_set (int fd);
int rrr_serial_parity_set (int fd, int is_odd);
int rrr_serial_stop_bit_set (int fd, int is_two);
int rrr_serial_parity_unset (int fd);

#endif /* RRR_SERIAL_H */
