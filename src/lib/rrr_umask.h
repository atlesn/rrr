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

#ifndef RRR_UMASK_H
#define RRR_UMASK_H

#include <sys/types.h>

mode_t rrr_umask_get_global (void);
void rrr_umask_onetime_set_global (
		mode_t mask_new
);
int rrr_umask_with_umask_lock_do (
		mode_t mask_new,
		int (*callback)(void *callback_arg),
		void *callback_arg
);

#endif /* RRR_UMASK_H */
