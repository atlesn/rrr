/*

Read Route Record

Copyright (C) 2026 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_GPIO_H
#define RRR_GPIO_H

struct rrr_gpio_request;

int rrr_gpio_set_line(struct rrr_gpio_request **request, const char *chip_path, unsigned int line_offset, int value);
void rrr_gpio_request_destroy(struct rrr_gpio_request **request);

#endif /* RRR_GPIO_H */
