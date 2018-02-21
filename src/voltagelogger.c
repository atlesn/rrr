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

#include "modules.h"
#include "threads.h"
#include "cmdlineparser/cmdline.h"

int main_loop() {
	return 0;
}

int main (int argc, const char *argv[]) {
	struct cmd_data cmd;

	int ret = EXIT_SUCCESS;

	if (cmd_parse(&cmd, argc, argv, CMD_CONFIG_NOCOMMAND) != 0) {
		fprintf (stderr, "Error while parsing command line\n");
		ret = EXIT_FAILURE;
	}

	const char *src_module_string = cmd_get_value(&cmd, "src_module");
	const char *p_module_string = cmd_get_value(&cmd, "p_module");
	const char *dst_module_string = cmd_get_value(&cmd, "dst_module");

	if (src_module_string == NULL) {
		src_module_string = "dummy";
	}
	if (p_module_string == NULL) {
		p_module_string = "raw";
	}
	if (dst_module_string == NULL) {
		dst_module_string = "stdout";
	}

	printf ("Using source module '%s' for input\n", src_module_string);

	if (load_module(src_module_string) != 0) {
		fprintf(stderr, "Error while loading module %s\n", src_module_string);
		ret = EXIT_FAILURE;
	}

	printf ("Using processor module '%s' for processing\n", p_module_string);

	if (load_module(p_module_string) != 0) {
		fprintf(stderr, "Error while loading module %s\n", p_module_string);
		ret = EXIT_FAILURE;
	}

	printf ("Using destination module '%s' for output\n", dst_module_string);

	if (load_module(dst_module_string) != 0) {
		fprintf(stderr, "Error while loading module %s\n", dst_module_string);
		ret = EXIT_FAILURE;
	}

	struct module_data *source_module =
			get_module(src_module_string, VL_MODULE_TYPE_SOURCE);
	struct module_data *processor_module =
			get_module(p_module_string, VL_MODULE_TYPE_PROCESSOR);
	struct module_data *destination_module =
			get_module(dst_module_string, VL_MODULE_TYPE_DESTINATION);

	if (source_module == NULL) {
		fprintf (stderr, "Module %s could not be used as source module\n", src_module_string);
		ret = EXIT_FAILURE;
		goto out;
	}
	if (processor_module == NULL) {
		fprintf (stderr, "Module %s could not be used as processor module\n", p_module_string);
		ret = EXIT_FAILURE;
		goto out;
	}
	if (destination_module == NULL) {
		fprintf (stderr, "Module %s could not be used as destination module\n", dst_module_string);
		ret = EXIT_FAILURE;
		goto out;
	}

	processor_module->operations->set_sender(processor_module, source_module);
	processor_module->operations->set_receiver(processor_module, destination_module);

	ret = main_loop();

	out:
	hard_unload_modules();
	return ret;
}
