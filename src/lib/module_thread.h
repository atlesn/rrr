/*

Voltage Logger

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef MODULE_THREAD_H
#define MODULE_THREAD_H

/* TODO: Don't include this */
#include "../modules.h"


#include "../global.h"
#include "threads.h"

/* TODO : Rename to instance_** */

struct rrr_instance_config;
struct cmd_data;

struct module_dynamic_data {
	const char *instance_name;
	const char *module_name;
	unsigned int type;
	struct module_operations operations;
	void *dl_ptr;
	void *private_data;
	void (*unload)(struct module_dynamic_data *data);
};

struct module_thread_init_data {
	struct cmd_data *cmd_data;
	struct rrr_instance_config *instance_config;
	struct rrr_config *global_config;
	struct module_dynamic_data *module;
	struct instance_metadata *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
};

struct module_thread_data {
	struct module_thread_init_data init_data;

	struct vl_thread *thread;
	void *private_data;
	char private_memory[VL_MODULE_PRIVATE_MEMORY_SIZE];
};

/* TODO : Rename functions, they have something to do with instances */
void rrr_threads_init();
void rrr_threads_stop();
void rrr_threads_destroy();
void rrr_free_thread(struct module_thread_data *data);
struct module_thread_data *rrr_init_thread(struct module_thread_init_data *init_data);
int rrr_restart_thread(struct module_thread_data *data);
int rrr_start_thread(struct module_thread_data *data);

#endif /* MODULE_THREAD_H */
