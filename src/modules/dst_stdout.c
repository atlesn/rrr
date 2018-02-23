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
#include <string.h>

#include "../modules.h"
#include "../measurement.h"
#include "src_dummy.h"

struct stdout_private_data {
	struct module_dynamic_data *sender;
};

static int print(struct module_dynamic_data *module_data, struct output *output) {
	return 0;
}

static void *thread_entry(void *arg) {
	return NULL;
}

static struct module_operations module_operations = {
		thread_entry,
		NULL,
		print
};

static const char *module_name = "stdout";

__attribute__((constructor)) void load(struct module_dynamic_data *data) {
	data->name = module_name;
	data->type = VL_MODULE_TYPE_DESTINATION;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->private_data = malloc(sizeof(struct stdout_private_data));
}

__attribute__((constructor)) void unload(struct module_dynamic_data *data) {
	free(data->private_data);
}

__attribute__((constructor)) void set_sender (struct module_dynamic_data *data, struct module_dynamic_data *sender) {
	struct stdout_private_data *private_data = (struct stdout_private_data *) data->private_data;
	private_data->sender = sender;
}


