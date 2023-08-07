/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CONFIGURATION_H
#define RRR_CONFIGURATION_H

#include "settings.h"
#include "array_tree.h"
#include "route.h"

#define RRR_CONFIG_MAX_MODULES CMD_MAXIMUM_CMDLINE_ARGS
#define RRR_CONFIG_MAX_SIZE 16*1024*1024
#define RRR_CONFIG_ALLOCATION_INTERVAL 4
		
#define RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS     void **block, \
                                               struct rrr_config *config, \
                                               const char *name, \
					       void *callback_arg
#define RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS   void *block, const char *name, const char *value, void *callback_arg

struct rrr_config {
	struct rrr_array_tree_list array_trees;
	struct rrr_route_collection routes;
};

int rrr_config_new (
		struct rrr_config **result
);
void rrr_config_destroy (
		struct rrr_config *target
);
int rrr_config_parse_file (
		struct rrr_config *config,
		const char *filename,
		int (*new_block_callback)(RRR_CONFIG_NEW_BLOCK_CALLBACK_ARGS),
		int (*new_setting_callback)(RRR_CONFIG_NEW_SETTING_CALLBACK_ARGS),
		void *callback_arg
);
const struct rrr_array_tree_list *rrr_config_get_array_tree_list (
		struct rrr_config *config
);
const struct rrr_route_collection *rrr_config_get_routes (
		struct rrr_config *config
);

#endif /* RRR_CONFIGURATION_H */
