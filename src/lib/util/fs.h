/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_UTIL_FS_H
#define RRR_UTIL_FS_H

int rrr_util_fs_basename (
		const char *path,
		int (*callback)(const char *path, const char *dir, const char *name, void *arg),
		void *callback_arg
);
int rrr_util_fs_dir_ensure (const char *dir);
int rrr_util_fs_dir_clean (const char *dir);

#endif /* RRR_UTIL_FS_H */
