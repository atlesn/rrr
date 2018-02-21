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
#include <semaphore.h>

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

int count_module_users(struct module_data *module, int *result) {
	if (sem_getvalue(&module->users, result) != 0) {
		fprintf(stderr, "Could not get semaphore value: %s\n", strerror(errno));
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

int hard_unload_modules() {
	int err = 0;
	struct module_data *ptr = first_module;
	first_module = NULL;

	while (ptr != NULL) {
		struct module_data *next = ptr->next;
		ptr->next = NULL;
		void *dl_ptr = ptr->dl_ptr;
		ptr->state = VL_MODULE_STATE_INVALID;

		char name[256];
		sprintf(name, "%s", ptr->name);

		int usercount;
		count_module_users(ptr, &usercount);
		if (usercount != 1) {
			fprintf (stderr, "Warning: Usercount for module was not 1 at hard unload stage. Not unloading library.\n");
			err = 1;
		}

		if (ptr->operations->module_destroy(ptr) != 0) {
			fprintf (stderr, "Error while running destructor in module\n");
		}

		give_module(ptr);

		if (sem_destroy(&ptr->users) != 0) {
			fprintf (stderr, "Warning: Error while destroying usercount semaphore: %s\n", strerror(errno));
		}

#ifndef VL_MODULE_NO_DL_CLOSE
		if (usercount == 1) {
			if (dlclose(dl_ptr) != 0) {
				fprintf (stderr, "Error while unloading module: %s\n", dlerror());
				return 1;
			}
		}
#else
		fprintf(stderr, "Warning: Not unloading shared object due to configuration VL_MODULE_NO_DL_CLOSE\n");
#endif

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
		sem_init(&data->users, 0, 0);

		if (register_module(data) != 0) {
			fprintf (stderr, "Error while registering module.\n");
#ifndef VL_MODULE_NO_DL_CLOSE
			dlclose(handle);
#endif
			break;
		}

		if (data->operations->module_init(data) != 0) {
			fprintf (stderr, "Error while initializing module.\n");
			dlclose(handle);
			break;
		}

		take_module(data);

		data->state = VL_MODULE_STATE_UP;

		err = 0;
		break;
	}

	return err;
}
