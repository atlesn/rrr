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

struct module_dynamic_data {
	const char *instance_name;
	const char *module_name;
	unsigned int type;
	struct module_operations operations;
	void *dl_ptr;
	void *private_data;
	void (*unload)(struct module_dynamic_data *data);
};

struct module_thread_data {
	struct vl_thread *thread;
	struct module_thread_data *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
	struct module_dynamic_data *module;
	void *private_data;
	char private_memory[VL_MODULE_PRIVATE_MEMORY_SIZE];
};

struct module_thread_init_data {
	struct module_dynamic_data *module;
	struct module_metadata *senders[VL_MODULE_MAX_SENDERS];
	unsigned long int senders_count;
};

struct module_metadata {
	struct module_dynamic_data *dynamic_data;
	struct module_thread_data *thread_data;
	struct module_metadata *senders[VL_MODULE_MAX_SENDERS];
	struct rrr_instance_config *config;
	unsigned long int senders_count;
};

/* TODO : Rename functions, they have something to do with instances */
void rrr_threads_init();
void rrr_threads_stop();
void rrr_threads_destroy();
void rrr_free_thread(struct module_thread_data *data);
struct module_thread_data *rrr_init_thread(struct module_thread_init_data *init_data);
int rrr_restart_thread(struct module_thread_data *data, struct cmd_data *cmd);
int rrr_start_thread(struct module_thread_data *data, struct cmd_data *cmd);

#endif /* MODULE_THREAD_H */
