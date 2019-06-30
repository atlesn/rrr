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

#include "../global.h"
#include "configuration.h"
#include "module_thread.h"

struct instance_metadata {
	struct instance_metadata *next;
	struct module_dynamic_data *dynamic_data;
	struct module_thread_data *thread_data;
	struct instance_metadata *senders[VL_MODULE_MAX_SENDERS];
	struct rrr_instance_config *config;
	unsigned long int senders_count;
};

struct instance_metadata_collection {
	int length;
	struct instance_metadata *first_entry;
};

#define RRR_INSTANCE_LOOP(target,collection) \
	for (struct instance_metadata *target = collection->first_entry; target != NULL; target = target->next)

int instance_check_threads_stopped(struct instance_metadata_collection *target);
void instance_free_all_threads(struct instance_metadata_collection *target);
int instance_count_library_users (struct instance_metadata_collection *target, void *dl_ptr);
void instance_unload_all(struct instance_metadata_collection *target);
void instance_metadata_collection_destroy (struct instance_metadata_collection *target);
int instance_metadata_collection_new (struct instance_metadata_collection **target);

int instance_add_senders (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
);
int instance_load_and_save (
		struct instance_metadata_collection *target,
		struct rrr_config *all_config,
		struct rrr_instance_config *instance_config
);
struct instance_metadata *instance_find (
		struct instance_metadata_collection *target,
		const char *name
);

#endif /* RRR_INSTANCES_H */
