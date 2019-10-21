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

#include <unistd.h>
#include <stdio.h>

#include <Python.h>

#include "../lib/python3_module.h"

int main (int argc, const char **argv) {
	(void)(argc); (void)(argv);
	rrr_python3_module_append_inittab();

	while (1) {
		printf ("\n=== Initialize ===============================================\n");
		Py_InitializeEx(0);

//		PyThreadState *state = PyEval_SaveThread();
//		PyEval_RestoreThread(state);

		PyThreadState *main_tstate = PyThreadState_Get();

		PyObject *res = NULL;

		PyThreadState *tstate = Py_NewInterpreter();
		PyThreadState_Swap(tstate);

		printf ("Add main to thread dict\n");
		PyObject *main_module = PyImport_AddModule("__main__");
		PyObject *main_dict = PyModule_GetDict(main_module);


		printf ("Import rrr_helper to thread dict\n");
		PyObject *rrr_helper_module = NULL;
		if ((rrr_helper_module = PyImport_ImportModule("rrr_helper")) == NULL) {
			PyErr_Print();
			goto out;
		}

		printf ("Import rrr_helper to thread dict\n");
		res = PyRun_String("import rrr_helper", Py_file_input, main_dict, main_dict);
		if (res == NULL) {
			PyErr_Print();
			goto out;
		}
		Py_XDECREF(res);

		out:

		printf ("\n=== Finalize =================================================\n");

		Py_EndInterpreter(tstate);
		PyThreadState_Swap(main_tstate);
		Py_Finalize();
		usleep (1000000);
	}
}
