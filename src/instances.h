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

#ifndef RRR_INSTANCES_H
#define RRR_INSTANCES_H

#include "global.h"
#include "lib/configuration.h"
#include "lib/module_thread.h"

int instance_check_threads_stopped(struct module_metadata instances[CMD_ARGUMENT_MAX]);
void instance_free_all_threads(struct module_metadata instances[CMD_ARGUMENT_MAX]);
int instance_count_library_users (struct module_metadata instances[CMD_ARGUMENT_MAX], void *dl_ptr);
void instance_unload_all(struct module_metadata instances[CMD_ARGUMENT_MAX]);

int instance_add_senders (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		struct rrr_config *all_config,
		struct rrr_instance_config *instance_config,
		struct module_metadata *module
);
int instance_load (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		struct rrr_config *all_config,
		struct rrr_instance_config *instance_config
);
struct module_metadata *instance_find (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		const char *name
);

#endif /* RRR_INSTANCES_H */
