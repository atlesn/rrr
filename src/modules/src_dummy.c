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

static int module_init(struct module_data *data) {
	printf ("Initialize dummy module\n");
	return 0;
}

static int module_destroy(struct module_data *data) {
	return 0;
}

static int poll(struct module_data *data, struct reading *measurement) {
	return 0;
}

static struct module_operations module_operations = {
		module_init,
		module_destroy,
		poll,
		NULL
};

static struct module_data module_data = {
		"dummy",
		VL_MODULE_TYPE_SOURCE,
		NULL,
		&module_operations,
		NULL
};

struct module_data *module_get_data() {
		return &module_data;
};

__attribute__((constructor)) void load(void) {
	module_data.operations = &module_operations;

}
