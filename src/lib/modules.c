/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../global.h"
#include "modules.h"
#include "rrr_strerror.h"

#ifndef RRR_MODULE_PATH
#define RRR_MODULE_PATH "./modules/"
#endif

void rrr_module_unload (void *dl_ptr, void (*unload)(void)) {
	unload();

#ifndef RRR_MODULE_NO_DL_CLOSE
	if (dlclose(dl_ptr) != 0) {
		RRR_MSG_ERR ("Warning: Error while unloading module: %s\n", dlerror());
	}
#else
	RRR_MSG_ERR ("Warning: Not unloading shared object due to configuration RRR_MODULE_NO_DL_CLOSE\n");
#endif
}

int rrr_module_load(struct rrr_module_load_data *target, const char *name, const char **library_paths) {
	int ret = 1; // NOT OK

	memset (target, '\0', sizeof(*target));

	for (int i = 0; *(library_paths[i]) != '\0'; i++) {
		char path[256 + strlen(name) + 1];
		sprintf(path, "%s/%s.so", library_paths[i], name);

		struct stat buf;
		if (stat(path, &buf) != 0) {
			if (errno == ENOENT) {
				continue;
			}
			RRR_MSG_ERR ("Could not stat %s while loading module: %s\n", path, rrr_strerror(errno));
			continue;
		}

		void *handle = dlopen(path, RTLD_LAZY);
		RRR_DBG_1 ("dlopen handle for %s: %p\n", name, handle);

		if (handle == NULL) {
			RRR_MSG_ERR ("Error while opening module %s: %s\n", path, dlerror());
			continue;
		}

		void (*init)(struct rrr_instance_dynamic_data *data) = dlsym(handle, "init");
		void (*unload)(void) = dlsym(handle, "unload");

		if (init == NULL || unload == NULL) {
			dlclose(handle);
			RRR_MSG_ERR ("Module %s missing init/unload functions\n", path);
			continue;
		}

		target->dl_ptr = handle;
		target->init = init;
		target->unload = unload;

		ret = 0; // OK
		break;
	}

	return ret;
}
