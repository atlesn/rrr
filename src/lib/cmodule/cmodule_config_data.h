
/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#include "../settings.h"

struct rrr_cmodule_config_data {
	rrr_setting_uint worker_spawn_interval_us;
	rrr_setting_uint worker_count;

	int do_spawning;
	int do_processing;
	int do_drop_on_error;

	char *config_function;
	char *process_function;
	char *source_function;
	char *log_prefix;
};

#endif /* RRR_CMODULE_CONFIG_DATA_H */
