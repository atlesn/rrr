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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "settings.h"
#include "instance_config.h"

void rrr_config_destroy_instance_config(struct rrr_instance_config *config) {
	rrr_settings_destroy(config->settings);
	free(config->name);
	free(config);
}

struct rrr_instance_config *rrr_config_new_instance_config (const char *name_begin, const int name_length, const int max_settings) {
	struct rrr_instance_config *ret = NULL;

	char *name = malloc(name_length + 1);
	if (name == NULL) {
		VL_MSG_ERR("Could not allocate memory for name in __rrr_config_new_instance_config");
		goto out;
	}

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory for name in __rrr_config_new_instance_config");
		goto out_free_name;
	}

	memcpy(name, name_begin, name_length);
	name[name_length] = '\0';

	ret->name = name;
	ret->settings = rrr_settings_new(max_settings);
	if (ret->settings == NULL) {
		VL_MSG_ERR("Could not create settings structure in __rrr_config_new_instance_config");
		goto out_free_config;
	}

	goto out;

	out_free_config:
	free(ret);
	ret = NULL;

	out_free_name:
	free(name);

	out:
	return ret;
}

int rrr_instance_config_read_port_number (rrr_setting_uint *target, struct rrr_instance_config *source, const char *name) {
	int ret = 0;

	*target = 0;

	rrr_setting_uint tmp_uint = 0;
	ret = rrr_settings_read_unsigned_integer (&tmp_uint, source->settings, name);

	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			char *tmp_string;

			ret = rrr_settings_read_string (&tmp_string, source->settings, name);
			VL_MSG_ERR (
					"Syntax error in port setting %s. Could not parse '%s' as number.\n",
					name, (tmp_string != NULL ? tmp_string : "")
			);

			if (tmp_string != NULL) {
				free(tmp_string);
			}

			ret = 1;
			goto out;
		}
	}
	else {
		if (tmp_uint < 1 || tmp_uint > 65535) {
			VL_MSG_ERR (
					"port setting %s out of range, must be 1-65535 but was %llu.\n",
					name, tmp_uint
			);
			ret = 1;
			goto out;
		}
	}

	*target = tmp_uint;

	out:
	return ret;
}
