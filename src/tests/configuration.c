/*

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

#include "../global.h"
#include "../lib/configuration.h"
#include "../lib/version.h"
#include "test.h"

int main (int argc, const char **argv) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = 0;

	struct rrr_config *config;

	TEST_BEGIN("non-existent config file")
	config = rrr_config_parse_file("nonexistent_file");
	TEST_RESULT(config == NULL)

	if (config != NULL) {
		free(config);
	}

	TEST_BEGIN("true configuration loading");
	config = rrr_config_parse_file("test.conf");
	TEST_RESULT(config != NULL)

	if (config != NULL) {
		rrr_config_destroy(config);
	}

	return ret;
}
