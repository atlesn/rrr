/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "fs.h"

#include <string.h>

#include "../log.h"
#include "../allocator.h"
#include "../rrr_path_max.h"

int rrr_util_fs_basename (
		const char *path,
		int (*callback)(const char *path, const char *dir, const char *name, void *arg),
		void *callback_arg
) {
	char tmp[PATH_MAX + 1];
	char *sep;

	if (strlen(path) > PATH_MAX) {
		RRR_MSG_0("Path too long in %s\n", __func__);
		return 1;
	}

	strcpy(tmp, path);

	if ((sep = strrchr(tmp, '/')) == NULL) {
		return callback(path, "", tmp, callback_arg);
	}

	*sep = '\0';

	return callback(path, tmp, sep + 1, callback_arg);
}
