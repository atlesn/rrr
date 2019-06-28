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

#include "module_thread.h"

#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "threads.h"
#include "crypt.h"

void rrr_threads_init() {
	vl_crypt_initialize_locks();
	threads_init();
}

void rrr_threads_stop() {
	threads_stop();
}

void rrr_threads_destroy() {
	threads_destroy();
	vl_crypt_free_locks();
}

void rrr_free_thread(struct module_thread_data *data) {
	if (data == NULL) {
		return;
	}

	free(data);
}

struct module_thread_data *rrr_init_thread(struct module_thread_init_data *init_data) {
	VL_DEBUG_MSG_1 ("Init thread %s\n", init_data->module->instance_name);
	struct module_thread_data *data = malloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	data->module = init_data->module;
	data->senders_count = init_data->senders_count;

	return data;
}

int rrr_restart_thread(struct module_thread_data *data, struct cmd_data *cmd) {
	VL_DEBUG_MSG_1 ("Restarting thread %s\n", data->module->instance_name);
	if (data->thread != NULL) {
		free(data->thread);
	}

	data->thread = thread_start (data->module->operations.thread_entry, data, cmd, data->module->instance_name);

	if (data->thread == NULL) {
		VL_MSG_ERR ("Error while starting thread for instance %s\n", data->module->instance_name);
		free(data);
		return 1;
	}

	return 0;
}

int rrr_start_thread(struct module_thread_data *data, struct cmd_data *cmd) {
	VL_DEBUG_MSG_1 ("Starting thread %s\n", data->module->instance_name);
	data->thread = thread_start (data->module->operations.thread_entry, data, cmd, data->module->instance_name);

	if (data->thread == NULL) {
		VL_MSG_ERR ("Error while starting thread for instance %s\n", data->module->instance_name);
		free(data);
		return 1;
	}

	return 0;
}
