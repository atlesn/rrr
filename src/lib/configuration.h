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

#include "settings.h"

#ifndef RRR_CONFIGURATION_H
#define RRR_CONFIGURATION_H

#define RRR_CONFIG_MAX_MODULES CMD_MAXIMUM_CMDLINE_ARGS
#define RRR_CONFIG_MAX_SIZE 16*1024*1024
#define RRR_CONFIG_MAX_SETTINGS 32

struct rrr_config {

};

struct rrr_module_config {
	char *name;
	struct rrr_module_settings *settings;
};

int config_parse_file (const char *filename);

#endif /* RRR_CONFIGURATION_H */
