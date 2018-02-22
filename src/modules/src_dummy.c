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

static void module_destroy(struct module_dynamic_data *data) {
	free(data);
}

static int poll(struct module_dynamic_data *data, struct reading *measurement) {
	return 0;
}

static void *thread_entry(void *arg) {
}

static struct module_operations module_operations = {
		module_destroy,
		thread_entry,
		poll,
		NULL,
		NULL
};

static const char *module_name = "dummy";

struct module_dynamic_data *module_get_data() {
		struct module_dynamic_data *data = malloc(sizeof(*data));
		data->name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
		return data;
};

__attribute__((constructor)) void load(void) {
}
