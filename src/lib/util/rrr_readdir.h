/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_READDIR_H
#define RRR_READDIR_H

#include "rrr_dirent.h"

int rrr_readdir_foreach_prefix (
		const char *dir_path,
		const char *prefix,
		int (*callback)(struct dirent *entry, const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_data
);

int rrr_readdir_foreach (
		const char *dir_path,
		int (*callback)(struct dirent *entry, const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_data
);
int rrr_readdir_foreach_recursive (
		const char *dir_path,
		int (*callback)(const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_arg
);

#endif /* RRR_READDIR_H */
