/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_GNU_H
#define RRR_GNU_H

#include <stdarg.h>

int rrr_vasprintf (char **resultp, const char *format, va_list args);
int rrr_asprintf (char **resultp, const char *format, ...);
char *rrr_strcasestr (const char *haystack, const char *needle);

/* Use this instead of asm("") */ 
int rrr_slow_noop (void);

#endif /* RRR_GNU_H */
