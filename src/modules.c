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

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "modules.h"
#include "lib/threads.h"

#ifndef VL_MODULE_PATH
#define VL_MODULE_PATH "./modules/"
#endif

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

void module_threads_init() {
	threads_init();
}

void module_threads_stop() {
	threads_stop();
}

void module_threads_destroy() {
	threads_destroy();
}

void module_set_sender (struct module_dynamic_data *data, struct module_dynamic_data *sender) {
	void (*set_sender)(struct module_dynamic_data *data) = dlsym(data->dl_ptr, "set_sender");
	if (set_sender == NULL) {
		fprintf (stderr, "Cannot set sender for this module (%s), function not found\n", data->name);
		exit (EXIT_FAILURE);
	}
}

void module_free_thread(struct module_thread_data *module) {
	free(module);
}

struct module_thread_data *module_start_thread(struct module_dynamic_data *module, void *private_data) {
	struct module_thread_data *data = malloc(sizeof(*data));

	data->thread = thread_start (module->operations.thread_entry, private_data);
	data->private_data = private_data;

	if (data->thread == NULL) {
		fprintf (stderr, "Error while starting thread for module %s\n", module->name);
		free(data);
		return NULL;
	}

	return data;
}

void unload_module(struct module_dynamic_data *ptr) {
	int err = 0;

	void *dl_ptr = ptr->dl_ptr;

	char name[256];
	sprintf(name, "%s", ptr->name);

	ptr->unload(ptr);


#ifndef VL_MODULE_NO_DL_CLOSE
	if (dlclose(dl_ptr) != 0) {
		fprintf (stderr, "Warning: Error while unloading module: %s\n", dlerror());
	}
#else
	fprintf(stderr, "Warning: Not unloading shared object due to configuration VL_MODULE_NO_DL_CLOSE\n");
#endif
}

struct module_dynamic_data *load_module(const char *name) {
	for (int i = 0; *(library_paths[i]) != '\0'; i++) {
		char path[256 + strlen(name) + 1];
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

		void *handle = dlopen(path, RTLD_LAZY);

		if (handle == NULL) {
			fprintf (stderr, "Error while opening module %s: %s\n", path, dlerror());
			continue;
		}

		void (*load)(void*) = dlsym(handle, "load");
		void (*unload)(void*) = dlsym(handle, "unload");

		if (load == NULL || unload == NULL) {
			dlclose(handle);
			fprintf (stderr, "Module %s missing load/unload functions\n", path);
			continue;
		}

		struct module_dynamic_data *data = malloc(sizeof(*data));
		data->dl_ptr = handle;
		data->unload = unload;

		load(data);

		return data;

		break;
	}

	return NULL;
}
