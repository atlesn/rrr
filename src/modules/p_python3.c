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
#include <signal.h>

#include <Python.h>

#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/python3.h"
#include "../global.h"

#define P_PYTHON3_MESSAGE_CACHE_MAX 100

static sig_atomic_t sigchld_pending = 0;

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
	char *module_path;

	struct python3_thread_state python3_thread_ctx;

	PyThreadState *tstate;

	PyObject *py_main;
	PyObject *py_main_dict;

	struct python3_fork *processing_fork;
	struct python3_fork *source_fork;

	struct python3_rrr_objects rrr_objects;

	int messages_pending;
};

static int thread_preload_python3 (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;
	VL_ASSERT(VL_MODULE_PRELOAD_MEMORY_SIZE >= sizeof(*preload_data),python3_preload_data_size_ok);

	if ((preload_data->istate = rrr_py_new_thread_state()) == NULL) {
		VL_MSG_ERR("Could not get thread state in python3 preload function\n");
		return 1;
	}

	return 0;
}

int data_init(struct python3_data *data, struct python3_preload_data *preload_data, struct instance_thread_data *thread_data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	ret |= fifo_buffer_init (&data->output_buffer);

	if (preload_data == NULL) {
		VL_MSG_ERR("Bug: No preload data in python3 data_init\n");
		exit(EXIT_FAILURE);
	}

	data->thread_data = thread_data;
	data->tstate = preload_data->istate;

	return ret;
}

struct python3_send_config_callback_data {
	struct python3_data *data;
};

int python3_send_config_callback (struct rrr_setting_packed *setting_packed, void *callback_arg) {
	struct python3_send_config_callback_data *data = callback_arg;

	int ret = 0;
	struct rrr_socket_msg *result = NULL;

	ret = rrr_py_start_onetime_rw_thread (
			&result,
			&data->data->rrr_objects,
			data->data->python3_module,
			data->data->config_function,
			rrr_setting_safe_cast(setting_packed)
	);
	if (ret != 0) {
		VL_MSG_ERR("Could not run python3 config function in instance %s:\n",
				INSTANCE_D_NAME(data->data->thread_data));
		ret = 1;
		goto out;
	}

	if (!RRR_SOCKET_MSG_IS_SETTING(result)) {
		VL_MSG_ERR("Warning: Received back message of unknown type from python3 config function, expected rrr_setting\n");
		ret = 0;
		goto out;
	}

	struct rrr_setting_packed *setting = (struct rrr_setting_packed *) result;

	rrr_settings_update_used (
			data->data->thread_data->init_data.instance_config->settings,
			setting->name,
			setting->was_used,
			rrr_settings_iterate_nolock
	);

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

int python3_send_config (struct python3_data *data) {
	int ret = 0;

	struct python3_send_config_callback_data callback_data = { data };
	ret = rrr_settings_iterate_packed (
			data->thread_data->init_data.instance_config->settings,
			python3_send_config_callback,
			&callback_data
	);

	return ret;
}

int python3_start(struct python3_data *data) {
	int ret = 0;

	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	// LOAD PYTHON MAIN DICTIONARY
	data->py_main = PyImport_AddModule("__main__"); // Borrowed reference
	if (data->py_main == NULL) {
		VL_MSG_ERR("Could not get python3 __main__ in python3_start in instance %s:\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	data->py_main_dict = PyModule_GetDict(data->py_main); // Borrowed reference
	if (data->py_main == NULL) {
		VL_MSG_ERR("Could not get python3 main dictionary in python3_start in instance %s:\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	// PREPARE RRR ENVIRONMENT
	char *module_path[1];
	int module_path_length = 0;
	if (data->module_path != NULL) {
		module_path[0] = data->module_path;
		module_path_length = 1;
	}
	if (rrr_py_get_rrr_objects(&data->rrr_objects, data->py_main_dict, (const char **) module_path, module_path_length) != 0) {
		VL_MSG_ERR("Could not get rrr objects function in python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	if (data->config_function != NULL) {
		if (python3_send_config(data) != 0) {
			ret = 1;
			goto out_thread_out;
		}
	}

	// START PROCESSING THREAD
	if (data->process_function != NULL) {
		if ((ret = rrr_py_start_persistent_rw_thread (
				&data->processing_fork,
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

	// START SOURCE THREAD
	if (data->source_function != NULL) {
		if ((ret = rrr_py_start_persistent_ro_thread (
				&data->source_fork,
				&data->rrr_objects,
				data->python3_module,
				data->source_function
		)) != 0) {
			VL_MSG_ERR("Could not start python3 source function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_start_source;
		}

		out_start_source:

		if (ret != 0) {
			goto out_thread_out;
		}
	}

	out_thread_out:
	return ret;
}

void python3_stop(void *arg) {
	struct python3_data *data = arg;

	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	// This will invalidate the forks
	rrr_py_terminate_threads(&data->rrr_objects);

	data->processing_fork = NULL;
	data->source_fork = NULL;

	rrr_py_destroy_rrr_objects(&data->rrr_objects);

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
	RRR_FREE_IF_NOT_NULL(data->module_path);

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

	VL_DEBUG_MSG_1 ("python3 stop thread instance %s\n", INSTANCE_D_NAME(thread_data));

	if (preload_data->istate) {
		rrr_py_destroy_thread_state(preload_data->istate);
	}

	preload_data->istate = NULL;
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
	rrr_instance_config_get_string_noconvert_silent (&data->module_path, config, "python3_module_path");

	if (data->source_function == NULL && data->process_function == NULL) {
		VL_MSG_ERR("No source or processor function defined for python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct read_from_processor_callback_data {
	struct python3_data *data;
	int message_count;
};

int read_from_processor_callback (struct rrr_socket_msg *message, void *arg) {
	struct read_from_processor_callback_data *callback_data = arg;
	struct python3_data *python3_data = callback_data->data;

	int ret = 0;

	if (!RRR_SOCKET_MSG_IS_VL_MESSAGE(message)) {
		VL_MSG_ERR("Warning: Received non vl_message from python3 processor function, discarding it.\n");
		ret = 1;
		goto out;
	}

	struct vl_message *vl_message = (struct vl_message *) message;

	VL_DEBUG_MSG_3("python3 instance %s writing message with timestamp %" PRIu64 " to output buffer\n",
			INSTANCE_D_NAME(python3_data->thread_data), vl_message->timestamp_from);

	callback_data->message_count++;
	fifo_buffer_write(&python3_data->output_buffer, (char*) vl_message, sizeof(*vl_message));

	out:
	return ret;
}

int process_input_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	(void)(size);

	struct instance_thread_data *thread_data = (struct instance_thread_data *) poll_data->source;
	struct python3_data *python3_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	update_watchdog_time(python3_data->thread_data->thread);

	VL_DEBUG_MSG_3("python3 instance %s processing message with timestamp %" PRIu64 " from input buffer\n",
			INSTANCE_D_NAME(python3_data->thread_data), message->timestamp_from);

	// Main loop calls python3_swap_thread_out, also in case of pthread_cancel
	// python3_swap_thread_in(&python3_data->python3_thread_ctx, python3_data->tstate);

	ret = rrr_py_persistent_process_message (
			python3_data->processing_fork,
			rrr_vl_message_safe_cast(message)
	);
	if (ret != 0) {
		VL_MSG_ERR("Error returned from rrr_py_persistent_process_message in instance %s\n",
				INSTANCE_D_NAME(python3_data->thread_data));
		ret = 1;
		goto out;
	}

	// Read messages in between while python works
	python3_data->messages_pending++;
	if (python3_data->messages_pending > 20) {
		ret |= FIFO_SEARCH_STOP;
	}

	VL_DEBUG_MSG_3("python3 instance %s return from process input callback callback: %i\n", INSTANCE_D_NAME(python3_data->thread_data), ret);

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int process_input (struct instance_thread_data *thread_data) {
	struct fifo_callback_args fifo_args = { thread_data, NULL, 0 };

	int ret = 0;

	ret = process_input_callback (&fifo_args, NULL, 0);
	ret = ret & ~(FIFO_SEARCH_STOP);

	return ret;
}

int read_from_processor_and_poll(struct python3_data *data, struct poll_collection *poll) {
	int ret = 0;

	if (data->process_function == NULL) {
		return 0;
	}

	if (data->messages_pending < 50) {
		if ((ret = poll_do_poll_delete_simple (poll, data->thread_data, process_input_callback, 50)) != 0) {
			VL_MSG_ERR("python3 return from fifo_read_clear_forward was not 0 but %i in instance %s\n",
					ret, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	}

	// Main loop calls python3_swap_thread_out, also in case of pthread_cancel
	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	struct read_from_processor_callback_data callback_data = {data, 0};
	ret = rrr_py_persistent_receive_message (
			data->processing_fork,
			read_from_processor_callback,
			&callback_data
	);

	data->messages_pending -= callback_data.message_count;

	if (data->messages_pending < 0) {
		VL_DEBUG_MSG_1("Python3 instance %s generated %i extra messages in the program\n",
				INSTANCE_D_NAME(data->thread_data), -(data->messages_pending));
		data->messages_pending = 0;
	}

	out:
	return ret;
}

int read_from_source(struct python3_data *data) {
	int ret = 0;

	if (data->source_function == NULL) {
		return 0;
	}

	// Main loop calls python3_swap_thread_out, also in case of pthread_cancel
	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	struct read_from_processor_callback_data callback_data = {data, 0};
	ret |= rrr_py_persistent_receive_message (
			data->source_fork,
			read_from_processor_callback,
			&callback_data
	);

	if (ret == 0) {
		VL_DEBUG_MSG_3("Python3 instance %s generated source messages in the program\n",
				INSTANCE_D_NAME(data->thread_data));
	}

	return ret;
}

// Poll request from other modules
int python3_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct python3_data *py_data = data->private_data;

	return fifo_read_clear_forward(&py_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

int thread_cancel_callback(void *arg) {
	struct python3_data *data = arg;
	rrr_py_terminate_threads (&data->rrr_objects);
	return 0;
}

static int thread_cancel_python3 (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data;

	(void)(data);

	VL_MSG_ERR ("Custom cancel function for thread %s/%p running\n", thread->name, thread);

	/*if (rrr_py_with_global_tstate_do(thread_cancel_callback, data) != 0) {
		VL_MSG_ERR("Could not terminate threads in thread_cancel_python3\n");
		PyErr_Print();
		return 1;
	}*/

	VL_MSG_ERR ("Custom cancel function done for %s/%p\n", thread->name, thread);

	return 0;
}

void debug_tstate (void *dummy) {
	(void)(dummy);
//	PyThreadState *current_tstate = _PyThreadState_UncheckedGet();
}

// Fork system is locked in this context
void child_exit_handler (pid_t pid, void *arg) {
	struct python3_data *data = arg;
	int res = rrr_py_invalidate_fork_unlocked(&data->rrr_objects, pid);
	if (res == 0) {
		VL_DEBUG_MSG_1("A fork was invalidated in child_exit_handler\n");
	}
}

static void *thread_entry_python3 (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;
	struct python3_preload_data *preload_data = thread_data->preload_data;
	struct poll_collection poll;

	VL_DEBUG_MSG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	// Set back to running again after we have no forks left from python
	pthread_cleanup_push(python3_stop, data);
	pthread_cleanup_push(debug_tstate,NULL);
	pthread_cleanup_push(thread_set_stopping, thread);

	if (data_init(data, preload_data, thread_data) != 0) {
		VL_MSG_ERR("Could not initalize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1("python3 instance %s tstate: %p\n", INSTANCE_D_NAME(thread_data), data->tstate);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("Python3 instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (poll_collection_count (&poll) > 0 && !data->process_function) {
		VL_MSG_ERR("Python3 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (python3_start(data) != 0) {
		VL_MSG_ERR("Python3 instance %s failed to start python program\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	thread_set_state(thread, VL_THREAD_STATE_RUNNING_FORKED);

	// Check after python3 has started, maybe the script uses some settings which will
	// then be tagged as used to avoid warnings
	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int output_buffer_size = fifo_buffer_get_entry_count(&data->output_buffer);

		if (output_buffer_size > 500) {
			usleep(1000);
		}
		else {
			int res;

			if (sigchld_pending) {
				rrr_py_handle_sigchld(child_exit_handler, data);
				sigchld_pending = 0;
			}

			if ((res = read_from_processor_and_poll(data, &poll)) != 0) {
				VL_MSG_ERR("python3 return from read from processor was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}

			if ((res = read_from_source(data)) != 0) {
				VL_MSG_ERR("python3 return from read from source was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}

			if ((res = python3_swap_thread_out(&data->python3_thread_ctx))) {
				VL_MSG_ERR("python3 return from thread swap out was not 0 but %i in instance %s\n",
						res, INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		update_watchdog_time(thread_data->thread);
	}

	out_message:
	VL_DEBUG_MSG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	rrr_py_handle_sigchld(child_exit_handler, data);

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

int signal_handler(int signal, void *private_arg) {
	int ret = 1;

	(void)(private_arg);

	VL_DEBUG_MSG_1("Python got signal %i\n", signal);
	if (signal == SIGCHLD) {
		sigchld_pending = 1;
		ret = 0;
		VL_DEBUG_MSG_1("Python took SIGCHLD signal\n");
	}
	else {
		VL_DEBUG_MSG_1("Python did not take signal\n");
	}

	return ret;
}
__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = VL_THREAD_START_PRIORITY_FORK;
	data->signal_handler = signal_handler;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy python3 module\n");
}

