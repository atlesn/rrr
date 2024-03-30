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

#include "fs.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "rrr_readdir.h"
#include "rrr_dirent.h"
#include "../log.h"
#include "../allocator.h"
#include "../rrr_path_max.h"
#include "../rrr_umask.h"

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

static int __rrr_util_fd_dir_ensure_umask_cb (mode_t mode, void *callback_arg) {
	const char *dir = callback_arg;

	if (chmod(dir, mode) != 0) {
		return 1;
	}

	return 0;
}

int rrr_util_fs_dir_ensure (const char *dir) {
	struct stat sb;

	if (lstat(dir, &sb) == 0) {
		if ((sb.st_mode & S_IFMT) != S_IFDIR) {
			errno = ENOTDIR;
			return 1;
		}
	}
	else if (errno != ENOENT) {
		return 1;
	}

	if (mkdir(dir, 0777) == 0) {
		// OK, created
	}
	else if (errno != EEXIST) {
		return 1;
	}
	else if (rrr_umask_with_umask_lock_and_mode_do (
			0777,
			__rrr_util_fd_dir_ensure_umask_cb,
			(void *) dir
	) != 0) {
		return 1;
	}

	return 0;
}

static int __rrr_util_fs_dir_clean_entry_cb (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	int ret = 0;

	(void)(entry);
	(void)(resolved_path);
	(void)(private_data);

	if (type == DT_DIR) {
		goto out;
	}

	if (unlink(orig_path) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_util_fs_dir_clean (const char *dir) {
	int ret = 0;

	if ((ret = rrr_readdir_foreach (
			dir,
			__rrr_util_fs_dir_clean_entry_cb,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
