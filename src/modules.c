/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "modules.h"

#ifndef VL_MODULE_PATH
#define VL_MODULE_PATH "./modules/"
#endif

static struct module_data *first_module = NULL;

static const char *library_paths[] = {
		VL_MODULE_PATH,
		"/usr/lib/voltagelogger",
		"/lib/voltagelogger",
		"/usr/local/lib/voltagelogger",
		"/usr/lib/",
		"/lib/",
		"/usr/local/lib/",
		"./src/modules/.libs",
		"./src/modules",
		"./modules",
		"./",
		""
};

static int unregister_module(struct module_data *module_data) {
	if (module_data->operations->module_destroy(module_data) != 0) {
		fprintf (stderr, "Error while running destructor in module\n");
	}
	if (dlclose(module_data->dl_ptr) != 0) {
		fprintf (stderr, "Error while unloading module: %s\n", dlerror());
		return 1;
	}
	return 0;
}

static int register_module(struct module_data *module_data) {
	if (first_module == NULL) {
		first_module = module_data;
		return 0;
	}

	struct module_data *ptr = first_module;
	while (ptr->next != NULL) {
		ptr = ptr->next;
	}


	ptr->next = module_data;
	return 0;
}

struct module_data *get_module(const char *name, unsigned int type) {
	struct module_data *ptr = first_module;
	while (ptr != NULL) {
		if (strcmp(name, ptr->name) == 0 && ptr->type == type) {
			return ptr;
		}
		ptr = ptr->next;
	}
	return NULL;
}

int unload_modules() {
	int err = 0;
	struct module_data *ptr = first_module;
	first_module = NULL;
	while (ptr != NULL) {
		struct module_data *next = ptr->next;
		ptr->next = NULL;
		char name[256];
		sprintf(name, "%s", ptr->name);
		if (unregister_module(ptr) != 0) {
			fprintf(stderr, "Error while unloading source module %s\n", name);
			err = 1;
		}
		ptr = next;
	}
	return err;
}

int load_module(const char *name) {
	void *handle = NULL;
	char path[256 + strlen(name) + 1];
	int err = 1;

	for (int i = 0; *(library_paths[i]) != '\0'; i++) {
		sprintf(path, "%s/%s.so", library_paths[i], name);

		struct stat buf;
		int ret = stat(path, &buf);

		if (ret != 0) {
			if (errno == ENOENT) {
				continue;
			}
			fprintf (stderr, "Could not stat %s while loading module: %s\n", path, strerror(errno));
			continue;
		}

		handle = dlopen(path, RTLD_LAZY);

		if (handle == NULL) {
			fprintf (stderr, "Error while opening module %s: %s\n", path, dlerror());
			continue;
		}

		struct module_data *(*module_get_data)(void) = dlsym(handle, "module_get_data");
		if (module_get_data == NULL) {
			fprintf (stderr, "Problem with module, could not find module_get_data-symbol: %s\n", dlerror());
			dlclose(handle);
			break;
		}

		struct module_data *data = module_get_data();
		data->dl_ptr = handle;

		if (data->operations->module_init(data) != 0) {
			fprintf (stderr, "Error while initializing module.\n");
			dlclose(handle);
			break;
		}

		if (register_module(data) != 0) {
			fprintf (stderr, "Error while registering module.\n");
			dlclose(handle);
			break;
		}

		err = 0;
		break;
	}

	return err;
}
