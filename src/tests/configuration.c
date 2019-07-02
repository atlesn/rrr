/*
#include <src/main.h>

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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
#include <unistd.h>

#include "../main.h"
#include "../global.h"
#include "../../build_timestamp.h"
#include "../lib/configuration.h"
#include "../lib/version.h"
#include "../lib/instances.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "test.h"

int main (int argc, const char **argv) {
	int ret = 0;

	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Starting test with module path %s\n", VL_MODULE_PATH);
	TEST_MSG("Change to directory %s\n", VL_TEST_PATH);

	if (chdir(VL_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out;
	}

	struct cmd_data cmd;
	TEST_BEGIN("PARSE CMD") {
		if (main_parse_cmd_arguments(&cmd, argc, argv) != 0) {
			ret = 1;
		}
	} TEST_RESULT(1)

	if (ret == 1) {
		goto out;
	}

	struct rrr_config *config;

	TEST_BEGIN("non-existent config file") {
	config = rrr_config_parse_file("nonexistent_file");
	} TEST_RESULT(config == NULL)

	if (config != NULL) {
		free(config);
	}

	TEST_BEGIN("true configuration loading") {
		config = rrr_config_parse_file("test.conf");
	} TEST_RESULT(config != NULL)

	struct instance_metadata_collection *instances;
	TEST_BEGIN("init instances") {
		if (instance_metadata_collection_new (&instances) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0)

	if (ret != 0) {
		goto out_cleanup_config;
	}

	TEST_BEGIN("process instances from config") {
		if (instance_process_from_config(instances, config) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0)

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	struct vl_thread_collection *collection = NULL;
	TEST_BEGIN("start threads") {
		if (main_start_threads(&collection, instances, config, &cmd) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0)

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	out_stop_threads:
	main_threads_stop(collection, instances);
	thread_destroy_collection (collection);

	out_cleanup_instances:
	instance_metadata_collection_destroy(instances);

	out_cleanup_config:
	if (config != NULL) {
		rrr_config_destroy(config);
	}

	out:
	return ret;
}
