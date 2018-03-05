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

#include "lib/cmdlineparser/cmdline.h"
#include "modules.h"
#include "lib/threads.h"
#include "global.h"

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

void module_free_thread(struct module_thread_data *data) {
	if (data == NULL) {
		return;
	}

	free(data);
}

struct module_thread_data *module_init_thread(struct module_thread_init_data *init_data) {
	VL_DEBUG_MSG_1 ("Init thread %s\n", init_data->module->name);
	struct module_thread_data *data = malloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	data->module = init_data->module;
	data->senders_count = init_data->senders_count;

	return data;
}

int module_restart_thread(struct module_thread_data *data, struct cmd_data *cmd) {
	VL_DEBUG_MSG_1 ("Restarting thread %s\n", data->module->name);
	if (data->thread != NULL) {
		free(data->thread);
	}

	data->thread = thread_start (data->module->operations.thread_entry, data, cmd, data->module->name);

	if (data->thread == NULL) {
		VL_MSG_ERR ("Error while starting thread for module %s\n", data->module->name);
		free(data);
		return 1;
	}

	return 0;
}

int module_start_thread(struct module_thread_data *data, struct cmd_data *cmd) {
	VL_DEBUG_MSG_1 ("Starting thread %s\n", data->module->name);
	data->thread = thread_start (data->module->operations.thread_entry, data, cmd, data->module->name);

	if (data->thread == NULL) {
		VL_MSG_ERR ("Error while starting thread for module %s\n", data->module->name);
		free(data);
		return 1;
	}

	return 0;
}

void unload_module(struct module_dynamic_data *ptr) {
	int err = 0;

	void *dl_ptr = ptr->dl_ptr;

	ptr->unload(ptr);

	free(ptr);

#ifndef VL_MODULE_NO_DL_CLOSE
	if (dlclose(dl_ptr) != 0) {
		VL_MSG_ERR ("Warning: Error while unloading module: %s\n", dlerror());
	}
#else
	VL_MSG_ERR ("Warning: Not unloading shared object due to configuration VL_MODULE_NO_DL_CLOSE\n");
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
			VL_MSG_ERR ("Could not stat %s while loading module: %s\n", path, strerror(errno));
			continue;
		}

		void *handle = dlopen(path, RTLD_LAZY);

		if (handle == NULL) {
			VL_MSG_ERR ("Error while opening module %s: %s\n", path, dlerror());
			continue;
		}

		void (*init)(struct module_dynamic_data *data) = dlsym(handle, "init");
		void (*unload)(struct module_dynamic_data *data) = dlsym(handle, "unload");

		if (init == NULL || unload == NULL) {
			dlclose(handle);
			VL_MSG_ERR ("Module %s missing init/unload functions\n", path);
			continue;
		}

		struct module_dynamic_data *data = malloc(sizeof(*data));

		init(data);
		data->dl_ptr = handle;
		data->unload = unload;

		return data;
	}

	return NULL;
}
