/*

Voltage Logger

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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>

#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/python3.h"
#include "../global.h"

//static PyThreadState *main_tstate = NULL;
static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static PyThreadState *main_python_tstate = NULL;
static int python_users = 0;

struct python3_preload_data {
	PyThreadState *istate;
};

struct python3_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	char *python3_file;

	char *source_function;
	char *process_function;
	char *config_function;
	PyObject *py_source_function;
	PyObject *py_process_function;
	PyObject *py_config_function;

	PyThreadState *istate;
	PyThreadState *tstate;

	PyObject *py_main;
	PyObject *py_main_dict;
	FILE *py_file;

	pthread_mutex_t python3_mutex;
};

void data_cleanup(void *arg) {
	struct python3_data *data = arg;
	fifo_buffer_invalidate (&data->input_buffer);
	fifo_buffer_invalidate (&data->output_buffer);

	RRR_FREE_IF_NOT_NULL(data->python3_file);
	RRR_FREE_IF_NOT_NULL(data->source_function);
	RRR_FREE_IF_NOT_NULL(data->process_function);
	RRR_FREE_IF_NOT_NULL(data->config_function);


	//PYTHON3_THREAD_IN(data->istate);

/*	Py_XDECREF(data->py_source_function);
	Py_XDECREF(data->py_process_function);
	Py_XDECREF(data->py_config_function);
	Py_XDECREF(data->py_main_dict);
	Py_XDECREF(data->py_main);*/

	if (data->tstate != NULL) {
		PyEval_RestoreThread(data->tstate);
		PyThreadState_Clear(data->tstate);
        PyThreadState_DeleteCurrent();
		data->tstate = NULL;
	}

	if (data->py_file != NULL) {
		fclose(data->py_file);
		data->py_file = NULL;
	}

	data->py_source_function = NULL;
	data->py_process_function = NULL;
	data->py_config_function = NULL;
	data->py_main = NULL;
	data->py_main_dict = NULL;

	//PYTHON3_THREAD_OUT();
}

int data_init(struct python3_data *data, const struct python3_preload_data *preload_data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));
	ret |= fifo_buffer_init (&data->input_buffer);
	ret |= fifo_buffer_init (&data->output_buffer);
	ret |= pthread_mutex_init(&data->python3_mutex, NULL);

	if (preload_data == NULL) {
		VL_MSG_ERR("Bug: No preload data in python3 data_init\n");
		exit(EXIT_FAILURE);
	}

	data->istate = preload_data->istate;
	data->tstate = PyThreadState_New(data->istate->interp);

	return ret;
}

int parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_file, config, "python3_file");

	if (ret != 0) {
		VL_MSG_ERR("No python3_file specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_function, config, "python3_source_function");
	rrr_instance_config_get_string_noconvert_silent (&data->process_function, config, "python3_process_function");
	rrr_instance_config_get_string_noconvert_silent (&data->config_function, config, "python3_config_function");

	out:
	return ret;
}

// Poll request from other modules
int python3_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct python3_data *py_data = data->private_data;

	return fifo_read_clear_forward(&py_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

int poll_callback (struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct python3_data *python3_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	VL_DEBUG_MSG_3 ("python3: Result from buffer (local): %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&python3_data->input_buffer, (char*) reading, sizeof(*reading));

	return 0;
}

int python3_start(struct python3_data *data) {
	int ret = 0;

	PYTHON3_THREAD_IN(data->tstate);
	if (!PYTHON3_THREAD_OK()) {
		VL_MSG_ERR("Could not swap python3 thread state in python3_start\n");
		ret = 1;
		goto out_unlock;
	}

	// LOAD PYTHON MAIN DICTIONARY
	data->py_main = PyImport_ImportModule("__main__");
    if (data->py_main == NULL) {
    	VL_MSG_ERR("Could not get python __main__ in python3_start\n");
    	ret = 1;
    	goto out_thread_out;
    }

    data->py_main_dict = PyModule_GetDict(data->py_main);
    if (data->py_main == NULL) {
    	VL_MSG_ERR("Could not get python main dictionary in python3_start\n");
    	ret = 1;
    	goto out_thread_out;
    }

    // OPEN PYTHON FILE
	data->py_file = fopen (data->python3_file, "r");

	if (data->py_file == NULL) {
		VL_MSG_ERR ("Could not open python file: %s\n", strerror(errno));
		ret = 1;
		goto out_thread_out;
	}

	// RUN PYTHON PROGRAM
	PyObject *result = PyRun_File (data->py_file, data->python3_file,
			Py_file_input,
			data->py_main_dict, data->py_main_dict
	);
	if (result == NULL) {
			PyErr_Print();
			goto out_thread_out;
	}
	Py_XDECREF(result);

	// LOAD FUNCTIONS FROM PYTHON PROGRAM
	if (data->config_function != NULL) {
		data->py_config_function = rrr_py_import_function (data->py_main, data->config_function);
		if (data->py_config_function == NULL) {
			VL_MSG_ERR("Could not get config function '%s' from python program:\n", data->config_function);
			PyErr_Print();
			ret = 1;
			goto out_thread_out;
		}
	}

	if (data->process_function != NULL) {
		data->py_process_function = rrr_py_import_function (data->py_main, data->process_function);
		if (data->py_process_function == NULL) {
			VL_MSG_ERR("Could not get process function '%s' from python program:\n", data->process_function);
			PyErr_Print();
			ret = 1;
			goto out_thread_out;
		}
	}

	if (data->source_function != NULL) {
		data->py_source_function = rrr_py_import_function (data->py_main, data->source_function);
		if (data->py_source_function == NULL) {
			VL_MSG_ERR("Could not get source function '%s' from python program:\n", data->source_function);
			PyErr_Print();
			ret = 1;
			goto out_thread_out;
		}
	}

	out_thread_out:
	PYTHON3_THREAD_OUT();

	out_unlock:

	return ret;
}

void python3_stop(void *_data) {
	struct python3_data *data = _data;

	(void)(*data);
}

static void thread_poststop_python3 (const struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;

	pthread_mutex_lock(&main_python_lock);

	if (preload_data->istate != NULL) {
		PyEval_RestoreThread(preload_data->istate);
		Py_EndInterpreter(preload_data->istate);
		PyThreadState_Swap(main_python_tstate);
		PyEval_SaveThread();

		preload_data->istate = NULL;
	}

	if (--python_users == 0) {
		PyEval_RestoreThread(main_python_tstate);
		VL_DEBUG_MSG_1 ("python3 finalize\n");
		Py_Finalize();
		main_python_tstate = NULL;
	}

	pthread_mutex_unlock(&main_python_lock);
}

static int thread_preload_python3 (struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;
	VL_ASSERT(VL_MODULE_PRELOAD_MEMORY_SIZE >= sizeof(*preload_data),python3_preload_data_size_ok);

	pthread_mutex_lock(&main_python_lock);

	if (++python_users == 1) {
		VL_DEBUG_MSG_1 ("python3 initialize\n");

		Py_InitializeEx(0);
#ifdef RRR_PYTHON_VERSION_LT_3_7
		PyEval_InitThreads();
#endif

		main_python_tstate = PyThreadState_Get();
		PyEval_SaveThread();
	}

	PyEval_RestoreThread(main_python_tstate);
	preload_data->istate = Py_NewInterpreter();
	PyEval_SaveThread();

	pthread_mutex_unlock(&main_python_lock);

	return 0;
}

static void *thread_entry_python3 (struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;
	struct python3_preload_data *preload_data = thread_data->preload_data;
	struct poll_collection poll;

	thread_data->thread = start_data->thread;

	VL_DEBUG_MSG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	if (data_init(data, preload_data) != 0) {
		VL_MSG_ERR("Could not initalize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1("python3 instance %s tstate: %p\n", INSTANCE_D_NAME(thread_data), data->tstate);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("Python3 instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	pthread_cleanup_push(python3_stop, data);
	if (python3_start(data) != 0) {
		VL_MSG_ERR("Python3 instance %s failed to start python program\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread python3 %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct python3_data data;
	int ret = 0;
	if ((ret = data_init(&data, NULL)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct module_operations module_operations = {
		thread_preload_python3,
		thread_entry_python3,
		thread_poststop_python3,
		NULL,
		NULL,
		NULL,
		python3_poll_delete,
		test_config,
		NULL
};

static const char *module_name = "python3";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy python3 module\n");
}

