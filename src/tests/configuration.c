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

#include "../lib/configuration.c"
#include "test.h"

int main (int argc, const char **argv) {
	int ret = 0;

	struct rrr_config *config;

	MSG_TEST("Testing non-existent config file\n");
	config = rrr_config_parse_file("nonexistent_file");

	MSG_TEST("Testing configuration loading\n");
	config = rrr_config_parse_file("test.conf");


	return ret;
}
