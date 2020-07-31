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

// Put first to avoid problems with other files including sys/time.h
#include "util/rrr_time.h"

#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <stdlib.h>

#include "python3_cmodule.h"
#include "python3_common.h"
#include "python3_array.h"
#include "python3_module.h"
#include "python3_socket.h"
#include "../array.h"
#include "../settings.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_msg.h"
#include "../buffer.h"
#include "../messages.h"
#include "../message_addr.h"
#include "../fork.h"
#include "../rrr_mmap.h"
#include "../mmap_channel.h"
#include "../rrr_strerror.h"
#include "../log.h"
#include "../ip/ip_buffer_entry.h"
#include "../util/linked_list.h"
#include "../util/posix.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"

static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static PyThreadState *main_python_tstate = NULL;
static int python_users = 0;

#define PYTHON3_MMAP_SIZE (1024*1024*2)

static void __rrr_py_global_lock(void) {
	pthread_mutex_lock(&main_python_lock);
}

static void __rrr_py_global_unlock(void *dummy) {
	(void)(dummy);
	pthread_mutex_unlock(&main_python_lock);
}

static int __rrr_py_initialize_increment_users(void) {
	int ret = 0;
	__rrr_py_global_lock();

	if (++python_users == 1) {
		RRR_DBG_1 ("python3 initialize\n");

		if (rrr_python3_module_append_inittab() != 0) {
			RRR_MSG_0("Could not append python3 rrr_helper module to inittab before initializing\n");
			ret = 1;
			goto out;
		}

		//Py_NoSiteFlag = 1;
		Py_InitializeEx(0); // 0 = no signal registering
		//Py_NoSiteFlag = 0;

#ifdef RRR_PYTHON_VERSION_LT_3_7
		PyEval_InitThreads();
#endif

		main_python_tstate = PyEval_SaveThread();
	}

	out:
	if (ret != 0) {
		python_users--;
	}
	__rrr_py_global_unlock(NULL);
	return ret;
}

static void __rrr_py_finalize_decrement_users(void) {
	__rrr_py_global_lock();

	/* If we are not last, only clean up after ourselves. */
	if (--python_users == 0) {
		RRR_DBG_1 ("python3 finalize\n");
		PyEval_RestoreThread(main_python_tstate);
		Py_Finalize();
		main_python_tstate = NULL;
	}
	__rrr_py_global_unlock(NULL);
}

static void __rrr_py_destroy_thread_state(PyThreadState *tstate) {
	__rrr_py_global_lock();
	PyEval_RestoreThread(tstate);
	Py_EndInterpreter(tstate);
	PyThreadState_Swap(main_python_tstate);
	PyEval_SaveThread();
	__rrr_py_global_unlock(NULL);

	__rrr_py_finalize_decrement_users();
}

static PyThreadState *__rrr_py_new_thread_state(void) {
	PyThreadState *ret = NULL;

	if (__rrr_py_initialize_increment_users() != 0) {
		return NULL;
	}

	__rrr_py_global_lock();

	PyEval_RestoreThread(main_python_tstate);
	ret = Py_NewInterpreter();
	PyEval_SaveThread();

	__rrr_py_global_unlock(NULL);

	return ret;
}

static int __rrr_py_get_rrr_objects (
		PyObject *dictionary,
		const char **extra_module_paths,
		int module_paths_length
) {
	PyObject *res = NULL;
	PyObject *rrr_helper_module = NULL;
	char *rrr_py_import_final = NULL;
	int ret = 0;

	// FIX IMPORT PATHS AND IMPORT STUFF. INITIALIZE GLOBAL OBJECTS.
	int module_paths_total_size = 0;
	for (int i = 0; i < module_paths_length; i++) {
		module_paths_total_size += strlen(extra_module_paths[i]) + strlen("sys.path.append('')\n");
	}

	char extra_module_paths_concat[module_paths_total_size+1];
	*extra_module_paths_concat = '\0';
	for (int i = 0; i < module_paths_length; i++) {
		sprintf(extra_module_paths_concat + strlen(extra_module_paths_concat), "sys.path.append('%s')\n", extra_module_paths[i]);
	}

	if ((rrr_helper_module = PyImport_ImportModule("rrr_helper")) == NULL) {
		RRR_MSG_0("Could not add rrr_helper module to current thread state dict:\n");
		PyErr_Print();
		ret = 1;
		goto out;
	}

	//printf ("RRR helper module: %p refcount %li\n", rrr_helper_module, rrr_helper_module->ob_refcnt);
//	Py_XDECREF(rrr_helper_module);

	// RUN STARTUP CODE
	const char *rrr_py_import_template =
			"import sys\n"
#ifdef RRR_PYTHON3_EXTRA_SYS_PATH
			"sys.path.append('.')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "/src/python')\n"
			"sys.path.append('" RRR_PYTHON3_EXTRA_SYS_PATH "/src/tests')\n"
#endif /* RRR_PYTHON3_EXTRA_SYS_PATH */
#ifdef RRR_PYTHON3_PKGDIR
			"sys.path.append('" RRR_PYTHON3_PKGDIR "')\n"
#endif /* RRR_PYTHON3_PKGDIR */
#ifdef RRR_PYTHON3_SITE_PACKAGES_DIR
			"sys.path.append('" RRR_PYTHON3_SITE_PACKAGES_DIR "')\n"
#endif /* RRR_PYTHON3_PKGDIR */
			"%s"
//			"import rrr_helper\n"
//			"from rrr_helper import *\n"
	;

	rrr_py_import_final = malloc(strlen(rrr_py_import_template) + strlen(extra_module_paths_concat) + 1);
	sprintf(rrr_py_import_final, rrr_py_import_template, extra_module_paths_concat);

	res = PyRun_String(rrr_py_import_final, Py_file_input, dictionary, dictionary);
	if (res == NULL) {
		RRR_MSG_0("Could not run initial python3 code to set up RRR environment: \n");
		ret = 1;
		PyErr_Print();
		goto out;
	}
	RRR_Py_XDECREF(res);

	// DEBUG
	if (RRR_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE ==============================\n");
		rrr_python3_module_dump_dict_keys();
		printf ("=== PYTHON3 DUMPING RRR HELPER MODULE END ==========================\n\n");
	}

	if (RRR_DEBUGLEVEL_1) {
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES =================================\n");
		rrr_py_dump_global_modules();
		printf ("=== PYTHON3 DUMPING GLOBAL MODULES END =============================\n\n");
	}

	out:
	RRR_FREE_IF_NOT_NULL(rrr_py_import_final);

	return ret;
}

int rrr_py_cmodule_runtime_init (
		struct python3_fork_runtime *runtime,
		struct rrr_cmodule_worker *worker,
		const char *module_path_in
) {
	memset(runtime, '\0', sizeof(*runtime));

	int ret = 0;

	if ((runtime->istate = __rrr_py_new_thread_state()) == NULL) {
		goto out;
	}

	PyEval_RestoreThread(runtime->istate);

	// LOAD PYTHON MAIN DICTIONARY
	PyObject *py_main = PyImport_AddModule("__main__"); // Borrowed reference
	if (py_main == NULL) {
		RRR_MSG_0("Could not get python3 __main__ in __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	PyObject *py_main_dict = PyModule_GetDict(py_main); // Borrowed reference
	if (py_main_dict == NULL) {
		RRR_MSG_0("Could not get python3 main dictionary in __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	// PREPARE RRR ENVIRONMENT
	const char *module_path_array[1];
	int module_path_length = 0;
	if (module_path_in != NULL) {
		module_path_array[0] = module_path_in;
		module_path_length = 1;
	}

	if (__rrr_py_get_rrr_objects(py_main_dict, (const char **) module_path_array, module_path_length) != 0) {
		RRR_MSG_0("Could not get rrr objects  __rrr_py_fork_runtime_init\n");
		PyErr_Print();
		ret = 1;
		goto out_cleanup_istate;
	}

	if ((runtime->socket = rrr_python3_socket_new (worker)) == NULL) {
		RRR_MSG_0("Could not create socket PyObject in  __rrr_py_fork_runtime_init\n");
		goto out_cleanup_istate;
	}

	PyEval_SaveThread();

	goto out;
	out_cleanup_istate:
		PyEval_SaveThread();
		__rrr_py_destroy_thread_state(runtime->istate);
	out:
		return ret;
}

void rrr_py_cmodule_runtime_cleanup (struct python3_fork_runtime *runtime) {
	PyEval_RestoreThread(runtime->istate);
	Py_XDECREF(runtime->socket);
	PyEval_SaveThread();
	__rrr_py_destroy_thread_state(runtime->istate);
}

int rrr_py_cmodule_call_application_raw (
		PyObject *function,
		PyObject *arg1,
		PyObject *arg2
) {
	int ret = 0;

	PyObject *result = PyObject_CallFunctionObjArgs(function, arg1, arg2, NULL);

	if (result == NULL) {
		RRR_MSG_0("Error while calling python3 function in __rrr_py_persistent_process_call_application_raw pid %i\n",
				getpid());
		PyErr_Print();
		ret = 1;
		goto out;

	}
	if (!PyObject_IsTrue(result)) {
		RRR_MSG_0("Non-true returned from python3 function in __rrr_py_persistent_process_call_application_raw pid %i\n",
				getpid());
		ret = 1;
		goto out;
	}

	out:
	RRR_Py_XDECREF(result);
	return ret;
}
