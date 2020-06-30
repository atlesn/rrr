/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_PYTHON3_H
#define RRR_PYTHON3_H

#define PY_SSIZE_T_CLEAN

#include <sys/types.h>
#include <pthread.h>

#include "python3_headers.h"
#include "../linked_list.h"
#include "../../../build_directory.h"

struct rrr_setting_packed;
struct rrr_ip_buffer_entry;
struct rrr_fork_handler;
struct rrr_message;
struct rrr_address_msg;
struct rrr_mmap_channel;
struct rrr_cmodule_worker;

#define RRR_PYTHON3_OBJECT_CACHE_FULL 2
#define RRR_PYTHON3_OBJECT_CACHE_ERR 1
#define RRR_PYTHON3_OBJECT_CACHE_OK 0

#define RRR_PYTHON3_PERSISTENT_PROCESS_INPUT_MAX 12
#define RRR_PYTHON3_EXTRA_SYS_PATH RRR_BUILD_DIR

#define RRR_PYTHON3_CONTROL_MSG_CONFIG_COMPLETE RRR_SOCKET_MSG_CTRL_F_USR_A

#define RRR_PY_PASTE(a,b,c) a ## b ## v

struct python3_fork_runtime {
	PyThreadState *istate;

	PyObject *py_main;
	PyObject *py_main_dict;

	PyObject *socket;
};

int rrr_py_cmodule_call_application_raw (
		PyObject *function,
		PyObject *arg1,
		PyObject *arg2
);
int rrr_py_cmodule_runtime_init (
		struct python3_fork_runtime *runtime,
		struct rrr_cmodule_worker *worker,
		const char *module_path_in
);
void rrr_py_cmodule_runtime_cleanup (struct python3_fork_runtime *runtime);


#endif /* RRR_PYTHON3_H */
