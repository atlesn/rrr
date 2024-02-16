/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_BSD_H
#define RRR_BSD_H

#ifdef RRR_HAVE_LIBBSD
#  include <bsd/unistd.h>
#else
#  include <unistd.h>
#endif

#ifdef RRR_HAVE_SETPROCTITLE
#  define rrr_setproctitle setproctitle
#else
static void rrr_setproctitle(const char *fmt, ...) {
	(void)(fmt);
}
#endif

#ifdef RRR_HAVE_SETPROCTITLE_INIT
#  define rrr_setproctitle_init(a,b,c) setproctitle_init(a,(char**)b,(char**)c)
#else
static void rrr_setproctitle_init(int argc, const char *argv[], const char *envp[]) {
	(void)(argc);
	(void)(argv);
	(void)(envp);
}
#endif

#endif /* RRR_BSD_H */
