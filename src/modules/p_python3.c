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

#define P_PYTHON3_MESSAGE_CACHE_MAX 100

//static PyThreadState *main_tstate = NULL;
static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static PyThreadState *main_python_tstate = NULL;
static int python_users = 0;

void p_python3_global_lock(void) {
	pthread_mutex_lock(&main_python_lock);
}

void p_python3_global_unlock(void *dummy) {
	(void)(dummy);
	pthread_mutex_unlock(&main_python_lock);
}

struct python3_preload_data {
	PyThreadState *istate;
};

struct python3_data {
	struct instance_thread_data *thread_data;

	struct fifo_buffer output_buffer;

	char *python3_module;
	char *source_function;
	char *process_function;
	char *config_function;

	struct python3_thread_state python3_thread_ctx;
	struct python3_object_cache python3_object_cache;

	PyObject *py_instance_settings;

	PyThreadState *tstate;

	PyObject *py_main;
	PyObject *py_main_dict;

	PyObject *processing_pipe;
	PyObject *allocating_pipe;

	struct python3_rrr_objects rrr_objects;
};

static int thread_preload_python3 (struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;
	VL_ASSERT(VL_MODULE_PRELOAD_MEMORY_SIZE >= sizeof(*preload_data),python3_preload_data_size_ok);

	p_python3_global_lock();

	if (++python_users == 1) {
		VL_DEBUG_MSG_1 ("python3 initialize\n");

		Py_NoSiteFlag = 1;
		Py_InitializeEx(0);
		Py_NoSiteFlag = 0;

#ifdef RRR_PYTHON_VERSION_LT_3_7
		PyEval_InitThreads();
#endif

		main_python_tstate = PyEval_SaveThread();
	}


	PyEval_RestoreThread(main_python_tstate);
	preload_data->istate = Py_NewInterpreter();
	PyEval_SaveThread();

	p_python3_global_unlock(NULL);

	return 0;
}

int data_init(struct python3_data *data, struct python3_preload_data *preload_data, struct instance_thread_data *thread_data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	ret |= fifo_buffer_init (&data->output_buffer);
	ret |= rrr_py_object_cache_init(&data->python3_object_cache, P_PYTHON3_MESSAGE_CACHE_MAX);

	if (preload_data == NULL) {
		VL_MSG_ERR("Bug: No preload data in python3 data_init\n");
		exit(EXIT_FAILURE);
	}

	data->thread_data = thread_data;
	data->tstate = preload_data->istate;

	return ret;
}

int python3_start(struct python3_data *data) {
	int ret = 0;

	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	// LOAD PYTHON MAIN DICTIONARY
	// Not to be DECREF'ed, borrowed reference
	data->py_main = PyImport_AddModule("__main__");
    if (data->py_main == NULL) {
    	VL_MSG_ERR("Could not get python3 __main__ in python3_start in instance %s:\n",
				INSTANCE_D_NAME(data->thread_data));
    	PyErr_Print();
    	ret = 1;
    	goto out_thread_out;
    }
	Py_INCREF(data->py_main);

    // Not to be DECREF'ed, borrowed reference
    data->py_main_dict = PyModule_GetDict(data->py_main);
    if (data->py_main == NULL) {
    	VL_MSG_ERR("Could not get python3 main dictionary in python3_start in instance %s:\n",
				INSTANCE_D_NAME(data->thread_data));
    	PyErr_Print();
    	ret = 1;
    	goto out_thread_out;
    }
    Py_INCREF(data->py_main_dict);

    // PREPARE RRR ENVIRONMENT
	if (rrr_py_get_rrr_objects(&data->rrr_objects, data->py_main_dict) != 0) {
		VL_MSG_ERR("Could not get rrr objects function in python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	// CALL CONFIG FUNCTION IF DEFINED
	data->py_instance_settings = rrr_py_new_settings (
			&data->rrr_objects,
			data->thread_data->init_data.instance_config->settings
	);

	if (data->py_instance_settings == NULL) {
		VL_MSG_ERR("Could not save settings for instance %s to python3:\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out_thread_out;
	}

	if (data->config_function != NULL) {
		PyObject *new_py_instance_settings = NULL;
		PyObject *arglist = NULL;

	    ret = rrr_py_call_object_async (
	    		&new_py_instance_settings,
				&data->rrr_objects,
				data->python3_module,
				data->config_function,
				data->py_instance_settings
		);
		if (ret != 0) {
			VL_MSG_ERR("Could not run python3 config function in instance %s:\n",
					INSTANCE_D_NAME(data->thread_data));
			PyErr_Print();
			ret = 1;
			goto out_py_config;
		}

		if (strcmp(new_py_instance_settings->ob_type->tp_name, "rrr_instance_settings") != 0) {
			VL_MSG_ERR ("Returned settings object of wrong type %s, expected rrr_instance_settings in instance %s\n",
					new_py_instance_settings->ob_type->tp_name,
					INSTANCE_D_NAME(data->thread_data)
			);
			ret = 1;
			goto out_py_config;

		}

		if (rrr_py_settings_update_used (
				&data->rrr_objects,
				data->thread_data->init_data.instance_config->settings,
				new_py_instance_settings
		) != 0) {
			VL_MSG_ERR("Could not check whether settings for instance %s was used or not after python3 config function\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out_py_config;
		}

		out_py_config:
		Py_XDECREF(new_py_instance_settings);
		Py_XDECREF(arglist);

		if (ret != 0) {
			goto out_thread_out;
		}
	}

	// START PROCESSING THREAD
	if (data->process_function != NULL) {
		if ((ret = rrr_py_start_persistent_thread (
				&data->processing_pipe,
				&data->rrr_objects,
				data->python3_module,
				data->process_function
		)) != 0) {
			VL_MSG_ERR("Could not start python3 process function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_start_process;
		}

		out_start_process:

		if (ret != 0) {
			goto out_thread_out;
		}
	}

	// START ALLOCATING THREAD
	if ((ret = rrr_py_start_persistent_thread (
			&data->allocating_pipe,
			&data->rrr_objects,
			"rrr_objects",
			"vl_message_new"
	)) != 0) {
		VL_MSG_ERR("Could not start python3 allocator function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_thread_out;
	}

	out_thread_out:
	if (python3_swap_thread_out(&data->python3_thread_ctx)) {
		ret = 1;
	}

	return ret;
}

void python3_stop(void *arg) {
	struct python3_data *data = arg;

	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	rrr_py_terminate_threads(&data->rrr_objects);
	rrr_py_destroy_rrr_objects(&data->rrr_objects);

	Py_XDECREF(data->py_main_dict);
	Py_XDECREF(data->py_main);
	data->py_main = NULL;
	data->py_main_dict = NULL;

	python3_swap_thread_out(&data->python3_thread_ctx);

	if (data->tstate == NULL) {
		return;
	}
}

void data_cleanup(void *arg) {
	struct python3_data *data = arg;
	fifo_buffer_invalidate (&data->output_buffer);

	RRR_FREE_IF_NOT_NULL(data->python3_module);
	RRR_FREE_IF_NOT_NULL(data->source_function);
	RRR_FREE_IF_NOT_NULL(data->process_function);
	RRR_FREE_IF_NOT_NULL(data->config_function);

	rrr_py_object_cache_destroy(&data->python3_object_cache);

	if (python3_swap_thread_out(&data->python3_thread_ctx) == 0) {
		if (data->tstate != NULL) {
			python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

			python3_swap_thread_out(&data->python3_thread_ctx);
		}
	}
}

static void thread_poststop_python3 (const struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;

	p_python3_global_lock();

//	PyEval_AcquireLock()
//	PyEval_ReleaseLock
	VL_DEBUG_MSG_1 ("python3 stop thread instance %s\n", INSTANCE_D_NAME(thread_data));

	PyEval_RestoreThread(preload_data->istate);
	Py_EndInterpreter(preload_data->istate);
	PyThreadState_Swap(main_python_tstate);
	PyEval_SaveThread();

	/* If we are not last, only clean up after ourselves. */
	if (--python_users == 0) {
		VL_DEBUG_MSG_1 ("python3 finalize\n");
		PyEval_RestoreThread(main_python_tstate);
		Py_Finalize();
		main_python_tstate = NULL;
	}

	preload_data->istate = NULL;

	p_python3_global_unlock(NULL);
}

int parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_module, config, "python3_module");

	if (ret != 0) {
		VL_MSG_ERR("No python3_module specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_function, config, "python3_source_function");
	rrr_instance_config_get_string_noconvert_silent (&data->process_function, config, "python3_process_function");
	rrr_instance_config_get_string_noconvert_silent (&data->config_function, config, "python3_config_function");

	out:
	return ret;
}

int read_from_processor_callback (PyObject *message, void *arg) {
	struct python3_data *python3_data = (struct python3_data *) arg;

	int ret = 0;

	struct vl_message *new_message = NULL;
	ret = rrr_py_message_to_internal(&new_message, message);
	if (ret != 0) {
		VL_MSG_ERR("Could not convert message from python3 to internal message.\n");
		goto out;
	}

	VL_DEBUG_MSG_3("python3 instance %s writing message with timestamp %" PRIu64 " to output buffer\n",
			INSTANCE_D_NAME(python3_data->thread_data), new_message->timestamp_from);

	fifo_buffer_write(&python3_data->output_buffer, (char*) new_message, sizeof(*new_message));

	out:
	Py_XDECREF(message);
	return ret;
}

int read_from_processor(struct python3_data *data) {
	int ret = 0;

	// Main loop calls python3_swap_thread_out, also in case of pthread_cancel
	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	ret = rrr_py_persistent_receive_message (
			&data->rrr_objects,
			data->processing_pipe,
			read_from_processor_callback,
			data
	);

	return ret;
}

// Poll request from other modules
int python3_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct python3_data *py_data = data->private_data;

	return fifo_read_clear_forward(&py_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

int process_input_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	(void)(size);

	struct instance_thread_data *thread_data = (struct instance_thread_data *) poll_data->source;
	struct python3_data *python3_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	update_watchdog_time(python3_data->thread_data->thread);

	// Main loop calls python3_swap_thread_out, also in case of pthread_cancel
	python3_swap_thread_in(&python3_data->python3_thread_ctx, python3_data->tstate);

	VL_DEBUG_MSG_3("python3 instance %s processing message with timestamp %" PRIu64 " from input buffer\n",
			INSTANCE_D_NAME(python3_data->thread_data), message->timestamp_from);

	ret = rrr_py_persistent_process_new_message (
			&(python3_data->rrr_objects),
			python3_data->processing_pipe,
			message
	);
	if (ret != 0) {
		VL_MSG_ERR("Error returned from rrr_py_persistent_process_new_message in instance %s\n",
				INSTANCE_D_NAME(python3_data->thread_data));
		ret = 1;
	}

	free(data);

	VL_DEBUG_MSG_3("python3 instance %s return from callback: %i\n", INSTANCE_D_NAME(python3_data->thread_data), ret);

	return ret;
}


static int thread_cancel_python3 (struct vl_thread *thread) {
	int ret = 0;

	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data;

	VL_MSG_ERR ("Custom cancel function for thread %s/%p running\n", thread->name, thread);

	PyEval_RestoreThread(main_python_tstate);
	ret = rrr_py_terminate_threads (&data->rrr_objects);

	if (ret != 0) {
		VL_MSG_ERR("Could not terminate threads in thread_cancel_python3\n");
		PyErr_Print();
		return 1;
	}
	PyEval_SaveThread();

	VL_MSG_ERR ("Custom cancel function done for %s/%p\n", thread->name, thread);

	return ret;
}

void debug_tstate (void *dummy) {
	(void)(dummy);
	PyThreadState *current_tstate = _PyThreadState_UncheckedGet();
	printf ("Pop from cleanup stack: Current tstate: %p\n", current_tstate);
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
	pthread_cleanup_push(python3_stop, data);
	pthread_cleanup_push(debug_tstate,NULL);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	if (data_init(data, preload_data, thread_data) != 0) {
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

	if (python3_start(data) != 0) {
		VL_MSG_ERR("Python3 instance %s failed to start python program\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	// Check after python3 has started, maybe the script uses some settings which will
	// then be tagged as used to avoid warnings
	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	uint64_t accumulated_polling = 0;
	uint64_t accumulated_reading = 0;

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int output_buffer_size = fifo_buffer_get_entry_count(&data->output_buffer);

		if (output_buffer_size > 500) {
			usleep(1000);
		}
		else {
			uint64_t now;
			int res;

			now = time_get_64();
			if ((res = poll_do_poll_delete_simple (&poll, thread_data, process_input_callback, 50)) != 0) {
				VL_MSG_ERR("python3 return from poll was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}
			accumulated_polling += time_get_64() - now;

			now = time_get_64();
			if ((res = read_from_processor(data)) != 0) {
				VL_MSG_ERR("python3 return from read from processor was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}
			accumulated_reading += time_get_64() - now;

			if ((res = python3_swap_thread_out(&data->python3_thread_ctx))) {
				VL_MSG_ERR("python3 return from thread swap out was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		update_watchdog_time(thread_data->thread);
	}

	VL_DEBUG_MSG_1("python3 instance %s time spent polling %" PRIu64 " time spent reading %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), accumulated_polling, accumulated_reading);

	out_message:
	VL_DEBUG_MSG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct python3_data data;
	int ret = 0;
	if ((ret = data_init(&data, NULL, NULL)) != 0) {
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
		python3_poll_delete,
		NULL,
		test_config,
		NULL,
		thread_cancel_python3
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

