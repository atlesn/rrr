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

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

void rrr_log_printf (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	printf("<%u> <%s> ", loglevel, prefix);
	vprintf(__format, args);

	va_end(args);
}

void rrr_log_fprintf (FILE *file, unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	fprintf(file, "<%u> <%s> ", loglevel, prefix);
	vfprintf(file, __format, args);

	va_end(args);
}
