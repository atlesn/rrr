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

#ifndef MODULE_CONFIG_H
#define MODULE_CONFIG_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "settings.h"

struct rrr_module_config {
	char *name;
	struct rrr_module_settings *settings;
};

void rrr_config_destroy_module_config(struct rrr_module_config *config);
struct rrr_module_config *rrr_config_new_module_config (const char *name_begin, const int name_length, const int max_settings);

static inline int rrr_module_config_get_string_noconvert (char **target, struct rrr_module_config *source, const char *name) {
	return rrr_settings_get_string_noconvert(target, source->settings, name);
}

#endif /* MODULE_CONFIG_H */
