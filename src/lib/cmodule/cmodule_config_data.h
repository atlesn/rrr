
/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CMODULE_CONFIG_DATA_H
#define RRR_CMODULE_CONFIG_DATA_H

#include "cmodule_defines.h"
#include "../settings.h"

struct rrr_cmodule_config_data {
	rrr_time_us_t worker_spawn_interval;
	rrr_setting_uint worker_count;

	enum rrr_cmodule_process_mode process_mode;
	int do_spawning;
	int do_drop_on_error;
	int do_require_all_settings_used;

	char *config_method;
	char *process_method;
	char *source_method;
	char *log_prefix;
};

#endif /* RRR_CMODULE_CONFIG_DATA_H */
