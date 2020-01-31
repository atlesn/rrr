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

/*
 * This file must be compiled with -DRRR_INTERCEPT_ALLOW_READDIR prior to inclusion
 * of intercept.h, or intercept.h must not be included. If this is done incorrectly,
 * we will not be able to use readdir()
 */

#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../global.h"
#include "rrr_readdir.h"
#include "rrr_strerror.h"

pthread_mutex_t rrr_readdir_lock = PTHREAD_MUTEX_INITIALIZER;

// #define RRR_READDIR_DEBUG

int rrr_readdir_foreach (
		const char *dir_path,
		int (*callback)(struct dirent *entry, const char *resolved_path, unsigned char type, void *private_data),
		void *private_data
) {
	pthread_mutex_lock(&rrr_readdir_lock);

	int ret = 0;

	DIR *dirp = opendir(dir_path);
	if (dirp == NULL) {
		VL_MSG_ERR("Could not open directory '%s': %s\n", dir_path, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

#ifdef RRR_READDIR_DEBUG
	printf ("dir_path: %s\n", dir_path);
#endif

	struct dirent *entry = NULL;
	while ((entry = readdir(dirp)) != NULL) {
		unsigned char d_type = DT_UNKNOWN;

#ifdef RRR_READDIR_DEBUG
		printf ("entry: %s\n", entry->d_name);
#endif

		char resolved_path[PATH_MAX + 1];
		if (snprintf(resolved_path, PATH_MAX, "%s/%s", dir_path, entry->d_name) >= PATH_MAX) {
			VL_MSG_ERR("Path was too long for file '%s' in rrr_readdir_foreach\n", entry->d_name);
			continue; // Non-critical
		}

#if defined(_DEFAULT_SOURCE) || defined(_BSD_SOURCE)
		d_type = entry->d_type;
#endif

		int i = 100;
		char realpath_tmp[PATH_MAX + 1];
		while (--i > 0 && (d_type == DT_UNKNOWN || d_type == DT_LNK)) {
			struct stat sb;
			if (lstat(resolved_path, &sb) != 0) {
				VL_MSG_ERR("Could not stat file '%s': %s\n", resolved_path, rrr_strerror(errno));
				goto next_entry; // Non-critical
			}

			switch (sb.st_mode & S_IFMT) {
				case S_IFBLK:	d_type = DT_BLK;	break;
				case S_IFCHR:	d_type = DT_CHR;	break;
				case S_IFDIR:	d_type = DT_DIR;	break;
				case S_IFIFO:	d_type = DT_FIFO;	break;
				case S_IFLNK:	d_type = DT_LNK;	break;
				case S_IFREG:	d_type = DT_REG;	break;
				case S_IFSOCK:	d_type = DT_SOCK;	break;
				default:		d_type = 0;			break;
			}

			if (d_type == DT_LNK) {
				if (realpath(resolved_path, realpath_tmp) == NULL) {
					VL_MSG_ERR("Could not resolve real path for '%s': %s\n", resolved_path, rrr_strerror(errno));
					goto next_entry; // Non-critical
				}
#ifdef RRR_READDIR_DEBUG
				printf ("entry %s was symlink, translates to %s\n", entry->d_name, realpath_tmp);
#endif
				strcpy(resolved_path, realpath_tmp);
				continue;
			}

			break;
		}

		if (i <= 0) {
			VL_MSG_ERR("Possible symlink loop in rrr_readdir_foreach for file '%s'\n", resolved_path);
			goto next_entry; // Non-critical
		}

        if (callback (entry, resolved_path, d_type, private_data) != 0) {
        	ret = 1;
        	goto out;
        }

        next_entry:
		continue;
	}

	out:
	if (dirp != NULL) {
		closedir(dirp);
	}
	pthread_mutex_unlock(&rrr_readdir_lock);
	return ret;
}
