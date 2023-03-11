
/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "test.h"
#include "test_readdir.h"

#include "../lib/util/rrr_readdir.h"
#include "../lib/util/fs.h"
#include "../lib/rrr_path_max.h"

#define TEST_DIR                 "readdir"
#define TEST_PREFIX_LINK         "test_readdir_link_"
#define TEST_LINK_INITIAL        "test_readdir_link_initial"
#define TEST_LINK_INTERMEDIATE   "test_readdir_link_intermediate"
#define TEST_LINK_TARGET         "test_readdir_target"
#define TEST_FILE_EMPTY          "test_readdir_empty_file"

#define FOUND_INITIAL       1
#define FOUND_INTERMEDIATE  2
#define FOUND_TARGET        4
#define FOUND_EMPTY         8

static int __rrr_test_readdir_check_paths (const char *prefix, const char *path, const char *dir, const char *name) {
	int ret = 0;

	char tmp[PATH_MAX + 1];

	sprintf(tmp, "%s%s", prefix, TEST_DIR);

	if (strcmp(tmp, dir) != 0) {
		TEST_MSG("- dir mismatch (got %s expected %s)\n", dir, tmp);
		ret |= 1;
	}

	sprintf(tmp, "%s%s/%s", prefix, TEST_DIR, name);

	if (strcmp(tmp, path) != 0) {
		TEST_MSG("- dir and/or path mismatch (got %s expected %s)\n", path, tmp);
		ret |= 1;
	}

	return ret;
}

static int __rrr_test_readdir_orig_path_callback (const char *path, const char *dir, const char *name, void *arg) {
	int *status = arg;

	int ret = 0;

	ret |= __rrr_test_readdir_check_paths("", path, dir, name);

	if (strcmp(name, TEST_LINK_INITIAL) == 0) {
		if ((*status) & FOUND_INITIAL) {
			TEST_MSG("- " TEST_LINK_INITIAL " found more than once\n");
			ret |= 1;
		}

		(*status) |= FOUND_INITIAL;
	}
	else if (strcmp(name, TEST_LINK_INTERMEDIATE) == 0) {
		if ((*status) & FOUND_INTERMEDIATE) {
			TEST_MSG("- " TEST_LINK_INTERMEDIATE " found more than once\n");
			ret |= 1;
		}

		(*status) |= FOUND_INTERMEDIATE;
	}
	else if (strcmp(name, TEST_FILE_EMPTY) == 0) {
		if ((*status) & FOUND_EMPTY) {
			TEST_MSG("- " TEST_FILE_EMPTY " found more than once\n");
			ret |= 1;
		}

		(*status) |= FOUND_EMPTY;
	}
	else {
		TEST_MSG("- Unexpeted filename %s in %s\n", name, __func__);
		ret |= 1;
	}

	return ret;
}

static int __rrr_test_readdir_resolved_path_callback (const char *path, const char *dir, const char *name, void *arg) {
	int *status = arg;

	int ret = 0;

	if (strcmp(name, TEST_FILE_EMPTY) == 0) {
		if (!((*status) & FOUND_EMPTY)) {
			TEST_MSG("- Status not set for filename %s in %s\n", name, __func__);
			ret |= 1;
		}
	}
	else {
		char cwd[PATH_MAX + 2];
		getcwd(cwd, sizeof(cwd) - 1);
		sprintf(cwd + strlen(cwd), "/");

		ret |= __rrr_test_readdir_check_paths(cwd, path, dir, name);

		if (strcmp(name, TEST_LINK_TARGET) == 0) {
			(*status) |= FOUND_TARGET;
		}
		else {
			TEST_MSG("- Unexpeted filename %s in %s\n", name, __func__);
			ret |= 1;
		}
	}


	return ret;
}

static int __rrr_test_readdir_foreach_callback (struct dirent *entry, const char *orig_path, const char *resolved_path, unsigned char type, void *arg) {
	int ret = 0;

	(void)(entry);
	(void)(type);

	ret |= rrr_util_fs_basename(orig_path, __rrr_test_readdir_orig_path_callback, arg);
	ret |= rrr_util_fs_basename(resolved_path, __rrr_test_readdir_resolved_path_callback, arg);

	return ret;
}

int rrr_test_readdir(void) {
	int ret = 0;

	int status;

	TEST_MSG("Readdir symlinks...\n");

	status = 0;

	if (rrr_readdir_foreach_prefix(TEST_DIR, TEST_PREFIX_LINK, __rrr_test_readdir_foreach_callback, &status) != 0) {
		TEST_MSG("- Failed\n");
		ret |= 1;
	}

	if (status != (FOUND_INITIAL|FOUND_INTERMEDIATE|FOUND_TARGET)) {
		TEST_MSG("- Failed, statuses missing (result was %i)\n", status);
		ret |= 1;
	}

	TEST_MSG("Readdir empty file...\n");

	status = 0;

	if (rrr_readdir_foreach_prefix(TEST_DIR, TEST_FILE_EMPTY, __rrr_test_readdir_foreach_callback, &status) != 0) {
		TEST_MSG("- Failed\n");
		ret |= 1;
	}

	if (status != (FOUND_EMPTY)) {
		TEST_MSG("- Failed, statuses missing (result was %i)\n", status);
		ret |= 1;
	}

	return ret;
}

