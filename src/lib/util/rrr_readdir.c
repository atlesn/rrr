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


/*
 * This file must be compiled with -DRRR_INTERCEPT_ALLOW_READDIR prior to inclusion
 * of intercept.h, or intercept.h must not be included. If this is done incorrectly,
 * we will not be able to use readdir()
 */

#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>

#include "../log.h"
#include "../allocator.h"

#include "rrr_readdir.h"

#include "../rrr_strerror.h"
#include "../rrr_path_max.h"
#include "../util/linked_list.h"

pthread_mutex_t rrr_readdir_lock = PTHREAD_MUTEX_INITIALIZER;

//#define RRR_READDIR_DEBUG

static int __rrr_readdir_prefix_match (const char *filename, const char *prefix) {
	size_t filename_length = strlen(filename);
	size_t prefix_length = strlen(prefix);

	if (prefix_length == 0) {
		return 1;
	}

	if (filename_length < prefix_length) {
#ifdef RRR_READDIR_DEBUG
		printf("\tPrefix mismatch, too short %lu<%lu\n", filename_length, prefix_length);
#endif
		return 0;
	}

	for (size_t i = 0; i < prefix_length; i++) {
		if (filename[i] != prefix[i]) {
#ifdef RRR_READDIR_DEBUG
			printf("\tPrefix mismatch at %lu %s<>%s\n", i, filename, prefix);
#endif
			return 0;
		}
	}

#ifdef RRR_READDIR_DEBUG
	printf("\tPrefix match %s=%s\n", filename, prefix);
#endif

	return 1;
}

int rrr_readdir_foreach_prefix (
		const char *dir_path,
		const char *prefix,
		int (*callback)(struct dirent *entry, const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_data
) {
	pthread_mutex_lock(&rrr_readdir_lock);

	int ret = 0;

	DIR *dirp = opendir(dir_path);
	if (dirp == NULL) {
		RRR_MSG_0("Could not open directory '%s': %s\n", dir_path, rrr_strerror(errno));
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

		char orig_path[PATH_MAX + 1];
		char real_path[PATH_MAX + 1];
		if (snprintf(orig_path, PATH_MAX, "%s/%s", dir_path, entry->d_name) >= PATH_MAX) {
			RRR_DBG_3("Path was too long for file '%s' in rrr_readdir_foreach\n", entry->d_name);
			continue; // Non-critical
		}

		memcpy(real_path, orig_path, PATH_MAX + 1);

#if defined(_DEFAULT_SOURCE) || defined(_BSD_SOURCE)
		d_type = entry->d_type;
#endif

		int i = 100;
		while (--i > 0 && (d_type == DT_UNKNOWN || d_type == DT_LNK)) {
			struct stat sb;
			if (lstat(real_path, &sb) != 0) {
				RRR_DBG_3("Could not stat file '%s': %s\n", orig_path, rrr_strerror(errno));
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
				if (realpath(orig_path, real_path) == NULL) {
					RRR_DBG_3("Could not resolve real path for '%s': %s\n", orig_path, rrr_strerror(errno));
					goto next_entry; // Non-critical
				}
#ifdef RRR_READDIR_DEBUG
				printf ("entry %s was symlink, translates to %s\n", entry->d_name, real_path);
#endif
				continue;
			}

			break;
		}

		if (i <= 0) {
			RRR_DBG_3("Possible symlink loop in rrr_readdir_foreach for file '%s'\n", orig_path);
			goto next_entry; // Non-critical
		}

		if (prefix == NULL || __rrr_readdir_prefix_match(entry->d_name, prefix)) {
			if ((ret = callback (entry, orig_path, real_path, d_type, private_data)) != 0) {
				goto out;
			}
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

int rrr_readdir_foreach (
		const char *dir_path,
		int (*callback)(struct dirent *entry, const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_data
) {
	return rrr_readdir_foreach_prefix(dir_path, NULL, callback, private_data);
}

struct rrr_readdir_entry_collection;

struct rrr_readdir_entry {
	RRR_LL_NODE(struct rrr_readdir_entry);
	struct rrr_readdir_entry_collection *collection;
	char *orig_path;
	char *resolved_path;
	unsigned char type;
};

struct rrr_readdir_entry_collection {
	RRR_LL_HEAD(struct rrr_readdir_entry);
};

static void __rrr_readdir_entry_collection_destroy (
	struct rrr_readdir_entry_collection *collection
);

static void __rrr_readdir_entry_destroy (
	struct rrr_readdir_entry *entry
) {
	if (entry->collection != NULL) {
		__rrr_readdir_entry_collection_destroy(entry->collection);
	}
	RRR_FREE_IF_NOT_NULL(entry->orig_path);
	RRR_FREE_IF_NOT_NULL(entry->resolved_path);
	rrr_free(entry);
}

static void __rrr_readdir_entry_collection_destroy (
	struct rrr_readdir_entry_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_readdir_entry, __rrr_readdir_entry_destroy(node));
	rrr_free(collection);
}

static int __rrr_readdir_entry_collection_new (
	struct rrr_readdir_entry_collection **target
) {
	if ((*target = rrr_allocate(sizeof(**target))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_readdir_entry_collection_new\n");
		return 1;
	}

	memset(*target, '\0', sizeof(**target));

	return 0;
}

int __rrr_readdir_foreach_path_is_self_or_parent (
		const char *path
) {
	int dot_count = 0;

	size_t length = strlen(path);

	if (length - 1 > SSIZE_MAX) {
		RRR_BUG("Bug: Path too long in __rrr_readdir_foreach_path_is_self_or_parent\n");
	}

	// Note : Must be signed
	for (ssize_t i = (ssize_t) length - 1; i >= 0; i--) {
		char chr = *(path + i);
		if (chr == '.') {
			dot_count++;
		}
		else if (chr == '/' && dot_count > 0) {
			return 1;
		}
		else {
			return 0;
		}
	}

	return dot_count > 0 ? 1 : 0;
}

static int __rrr_readdir_foreach_recursive_descend_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	int ret = 0;

	if (__rrr_readdir_foreach_path_is_self_or_parent (orig_path)) {
		goto out;
	}

	struct rrr_readdir_entry_collection *target = private_data;

	(void)(entry);

	struct rrr_readdir_entry *new_entry = NULL;

	if ((new_entry = rrr_allocate_zero(sizeof(*new_entry))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_readdir_foreach_recursive_callback\n");
		ret = 1;
		goto out;
	}

	if ((new_entry->orig_path = rrr_strdup(orig_path)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for path in %s\n", __func__);
		goto out_free;
	}

	if ((new_entry->resolved_path = rrr_strdup(resolved_path)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for resolved path in %s\n", __func__);
		goto out_free;
	}

	new_entry->type = type;

	RRR_LL_APPEND(target, new_entry);

	goto out;
	out_free:
		RRR_FREE_IF_NOT_NULL(new_entry->orig_path);
		RRR_FREE_IF_NOT_NULL(new_entry->resolved_path);
		rrr_free(entry);
	out:
		return ret;
}

int __rrr_readdir_foreach_recursive_descend (
		struct rrr_readdir_entry_collection **target,
		const char *dir_path
) {
	int ret = 0;

	struct rrr_readdir_entry_collection *collection = NULL;

	if ((ret = __rrr_readdir_entry_collection_new (&collection)) != 0) {
		goto out;
	}

	if ((ret = rrr_readdir_foreach (
			dir_path,
			__rrr_readdir_foreach_recursive_descend_callback,
			collection
	)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_readdir_entry);
		if (node->type == DT_DIR) {
			if ((ret = __rrr_readdir_foreach_recursive_descend(&node->collection, node->orig_path)) != 0) {
				goto out;
			}
		}
	RRR_LL_ITERATE_END();

	*target = collection;
	collection = NULL;

	out:
	if (collection != NULL) {
		__rrr_readdir_entry_collection_destroy(collection);
	}
	return ret;
}

static int __rrr_readdir_foreach_recursive_final_callback (
	struct rrr_readdir_entry_collection *collection,
	int (*callback)(const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
	void *private_data
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_readdir_entry);
		if ((ret = callback(node->orig_path, node->resolved_path, node->type, private_data)) != 0) {
			goto out;
		}
		if (node->collection) {
			if ((ret = __rrr_readdir_foreach_recursive_final_callback(node->collection, callback, private_data)) != 0) {
				goto out;
			}
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_readdir_foreach_recursive (
		const char *dir_path,
		int (*callback)(const char *orig_path, const char *resolved_path, unsigned char type, void *private_data),
		void *private_arg
) {
	int ret = 0;

	struct rrr_readdir_entry_collection *collection = NULL;

	if ((ret = __rrr_readdir_foreach_recursive_descend(&collection, dir_path)) != 0) {
		goto out;
	}

	if ((ret = __rrr_readdir_foreach_recursive_final_callback (collection, callback, private_arg)) != 0) {
		goto out;
	}

	out:
	if (collection != NULL) {
		__rrr_readdir_entry_collection_destroy(collection);
	}
	return ret;
}
