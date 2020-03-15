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

static sig_atomic_t sigchld_pending = 0;

struct python3_preload_data {
	PyThreadState *istate;
};

struct python3_reader_data {
	struct python3_fork *fork;
	struct python3_data *data;
	struct rrr_fifo_buffer *output_buffer;
	struct rrr_thread *thread;
	int message_counter;
};

struct python3_data {
	struct rrr_instance_thread_data *thread_data;

	struct rrr_fifo_buffer output_buffer;

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

	struct rrr_thread_collection *thread_collection;
	struct python3_reader_data source_thread;
	struct python3_reader_data process_thread;

	int reader_thread_became_ghost;
};

static int thread_preload_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;
	RRR_ASSERT(RRR_MODULE_PRELOAD_MEMORY_SIZE >= sizeof(*preload_data),python3_preload_data_size_ok);

	if ((preload_data->istate = rrr_py_new_thread_state()) == NULL) {
		RRR_MSG_ERR("Could not get thread state in python3 preload function\n");
		return 1;
	}

	return 0;
}

int data_init(struct python3_data *data, struct python3_preload_data *preload_data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	ret |= rrr_fifo_buffer_init (&data->output_buffer);

	if (preload_data == NULL) {
		RRR_MSG_ERR("Bug: No preload data in python3 data_init\n");
		exit(EXIT_FAILURE);
	}

	data->thread_data = thread_data;
	data->tstate = preload_data->istate;

	return ret;
}

struct python3_send_config_callback_data {
	struct python3_data *data;
	struct python3_fork *target;
};

int python3_send_config_callback (struct rrr_setting_packed *setting_packed, void *callback_arg) {
	struct python3_send_config_callback_data *data = callback_arg;

	int ret = 0;

	if (rrr_py_persistent_process_message(data->target, rrr_setting_safe_cast(setting_packed)) != 0) {
		RRR_MSG_ERR("Could not send setting to python3 config function in instance %s:\n",
				INSTANCE_D_NAME(data->data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int python3_send_config (struct python3_data *data, struct python3_fork *target) {
	int ret = 0;

	struct python3_send_config_callback_data callback_data = { data, target };
	ret = rrr_settings_iterate_packed (
			data->thread_data->init_data.instance_config->settings,
			python3_send_config_callback,
			&callback_data
	);

	return ret;
}

int python3_send_start_sourcing (struct python3_fork *target) {
	return rrr_py_persistent_start_sourcing (target);
}

int python3_start(struct python3_data *data) {
	int ret = 0;

	python3_swap_thread_in(&data->python3_thread_ctx, data->tstate);

	// LOAD PYTHON MAIN DICTIONARY
	data->py_main = PyImport_AddModule("__main__"); // Borrowed reference
	if (data->py_main == NULL) {
		RRR_MSG_ERR("Could not get python3 __main__ in python3_start in instance %s:\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	data->py_main_dict = PyModule_GetDict(data->py_main); // Borrowed reference
	if (data->py_main == NULL) {
		RRR_MSG_ERR("Could not get python3 main dictionary in python3_start in instance %s:\n",
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
		RRR_MSG_ERR("Could not get rrr objects function in python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		PyErr_Print();
		ret = 1;
		goto out_thread_out;
	}

	// START PROCESSING THREAD
	if (data->process_function != NULL) {
		if ((ret = rrr_py_start_persistent_rw_thread (
				&data->processing_fork,
				&data->rrr_objects,
				data->python3_module,
				data->process_function,
				data->config_function
		)) != 0) {
			RRR_MSG_ERR("Could not start python3 process function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_thread_out;
		}

		if (python3_send_config(data, data->processing_fork) != 0) {
			RRR_MSG_ERR("Could not send configuration to processing thread in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out_thread_out;
		}
	}

	// START SOURCE THREAD
	if (data->source_function != NULL) {
		if ((ret = rrr_py_start_persistent_rw_thread (
				&data->source_fork,
				&data->rrr_objects,
				data->python3_module,
				data->source_function,
				data->config_function
		)) != 0) {
			RRR_MSG_ERR("Could not start python3 source function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_thread_out;
		}

		if (python3_send_config(data, data->source_fork) != 0) {
			RRR_MSG_ERR("Could not send configuration to source thread in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out_thread_out;
		}

		// This stops read/write behavior and initiates source only behavior
		if ((ret = python3_send_start_sourcing(data->source_fork)) != 0) {
			RRR_MSG_ERR("Could not start sourcing in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
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
	rrr_fifo_buffer_invalidate (&data->output_buffer);

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

static void thread_poststop_python3 (const struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_preload_data *preload_data = thread_data->preload_data = thread_data->preload_memory;

	RRR_DBG_1 ("python3 stop thread instance %s\n", INSTANCE_D_NAME(thread_data));

	if (preload_data->istate) {
		rrr_py_destroy_thread_state(preload_data->istate);
	}

	preload_data->istate = NULL;
}

int parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_module, config, "python3_module");

	if (ret != 0) {
		RRR_MSG_ERR("No python3_module specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_function, config, "python3_source_function");
	rrr_instance_config_get_string_noconvert_silent (&data->process_function, config, "python3_process_function");
	rrr_instance_config_get_string_noconvert_silent (&data->config_function, config, "python3_config_function");
	rrr_instance_config_get_string_noconvert_silent (&data->module_path, config, "python3_module_path");

	if (data->source_function == NULL && data->process_function == NULL) {
		RRR_MSG_ERR("No source or processor function defined for python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int process_input_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	(void)(size);

	struct rrr_instance_thread_data *thread_data = (struct rrr_instance_thread_data *) poll_data->source;
	struct python3_data *python3_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;

	rrr_update_watchdog_time(python3_data->thread_data->thread);

	RRR_DBG_3("python3 instance %s processing message with timestamp %" PRIu64 " from input buffer\n",
			INSTANCE_D_NAME(python3_data->thread_data), message->timestamp_from);

	ret = rrr_py_persistent_process_message (
			python3_data->processing_fork,
			rrr_message_safe_cast(message)
	);
	if (ret != 0) {
		RRR_MSG_ERR("Error returned from rrr_py_persistent_process_message in instance %s\n",
				INSTANCE_D_NAME(python3_data->thread_data));
		ret = 1;
		goto out;
	}
	out:
	RRR_FREE_IF_NOT_NULL(message);
	return (ret == 0 ? 0 : RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR);
}

int python3_poll(struct python3_data *data, struct poll_collection *poll) {
	int ret = 0;

	if ((ret = poll_do_poll_delete_simple (poll, data->thread_data, process_input_callback, 1000)) != 0) {
		RRR_MSG_ERR("python3 return from fifo_read_clear_forward was not 0 but %i in instance %s\n",
				ret, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	return ret;
}

// Poll request from other modules
int python3_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct python3_data *py_data = data->private_data;

	int ret = 0;

	ret |= rrr_fifo_read_clear_forward(&py_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);

	return ret;
}

int thread_cancel_callback(void *arg, PyThreadState *tstate_orig) {
	(void)(tstate_orig);

	struct python3_data *data = arg;
	rrr_py_terminate_threads (&data->rrr_objects);
	return 0;
}

static int thread_cancel_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data;

	(void)(data);

	RRR_MSG_ERR ("Custom cancel function for thread %s/%p running\n", thread->name, thread);

	if (rrr_py_with_global_tstate_do(thread_cancel_callback, data) != 0) {
		RRR_MSG_ERR("Could not terminate threads in thread_cancel_python3\n");
		PyErr_Print();
		return 1;
	}

	RRR_MSG_ERR ("Custom cancel function done for %s/%p\n", thread->name, thread);

	return 0;
}

// Fork system is locked in this context
void child_exit_handler (pid_t pid, void *arg) {
	struct python3_data *data = arg;
	int res = rrr_py_invalidate_fork_unlocked(&data->rrr_objects, pid);
	if (res == 0) {
		RRR_DBG_1("A fork was invalidated in child_exit_handler\n");
	}
}

struct read_from_processor_callback_data {
	struct python3_data *data;
	struct rrr_fifo_buffer *output_buffer;
	int message_count;
};

int read_from_source_or_processor_callback (struct rrr_socket_msg *message, void *arg) {
	struct read_from_processor_callback_data *callback_data = arg;
	struct python3_data *python3_data = callback_data->data;

	int ret = 0;

	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(message)) {
		struct rrr_message *rrr_message = (struct rrr_message *) message;

		RRR_DBG_3("python3 instance %s writing message with timestamp %" PRIu64 " to output buffer\n",
				INSTANCE_D_NAME(python3_data->thread_data), rrr_message->timestamp_from);

		callback_data->message_count++;
		rrr_fifo_buffer_write(callback_data->output_buffer, (char*) rrr_message, sizeof(*rrr_message));
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message)) {
		struct rrr_setting_packed *setting = (struct rrr_setting_packed *) message;
		rrr_settings_update_used (
				python3_data->thread_data->init_data.instance_config->settings,
				setting->name,
				setting->was_used,
				rrr_settings_iterate_nolock
		);
	}
	else {
		RRR_MSG_ERR("Warning: Received non rrr_message and non rrr_settigns from python3 processor function, discarding it.\n");
		ret = 1;
		goto out;
	}

	out:
	if (ret != 0) {
		free(message);
	}
	return ret;
}

int read_from_source_or_processor(struct python3_reader_data *data) {
	struct python3_data *python3_data = data->data;
	int ret = 0;

	struct read_from_processor_callback_data callback_data = {python3_data, data->output_buffer, 0};
	ret |= rrr_py_persistent_receive_message (
			data->fork,
			read_from_source_or_processor_callback,
			&callback_data
	);

	data->message_counter += callback_data.message_count;

//	printf ("%s read %i messages\n", data->thread->name, callback_data.message_count);


//	if (ret == 0) {
//		VL_DEBUG_MSG_3("Python3 instance %s generated source messages in the program in thread '%s'\n",
//				INSTANCE_D_NAME(python3_data->thread_data), data->thread->name);
//	}

	return ret;
}

static void *thread_entry_python3_reader (struct rrr_thread *thread) {
	struct python3_reader_data *data = thread->private_data;
	struct python3_data *python3_data = data->data;

	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	uint64_t start_time = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(data->thread) == 0) {
		rrr_update_watchdog_time(data->thread);

		if (read_from_source_or_processor(data) != 0) {
			RRR_MSG_ERR("Error while reading in python3 instance %s thread '%s'\n",
					INSTANCE_D_NAME(python3_data->thread_data), data->thread->name);
			break;
		}

		uint64_t now_time = rrr_time_get_64();
		if (now_time - start_time > 1000000) {
			RRR_DBG_1("python3 read thread '%s' messages per second: %i\n",
					data->thread->name, data->message_counter);
			data->message_counter = 0;
			start_time = rrr_time_get_64();
		}
	}

	usleep(50000);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

int preload_reader_thread (
		struct python3_reader_data *reader_data,
		struct rrr_thread_collection *collection,
		struct python3_data *python3_data,
		struct python3_fork *fork,
		struct rrr_fifo_buffer *output_buffer,
		const char *name
) {
	int ret = 0;
	struct rrr_thread *thread = NULL;

	reader_data->message_counter = 0;
	reader_data->data = python3_data;
	reader_data->fork = fork;
	reader_data->output_buffer = output_buffer;
	thread = rrr_thread_preload_and_register (
			collection,
			thread_entry_python3_reader,
			NULL,
			NULL,
			NULL,
			RRR_THREAD_START_PRIORITY_NORMAL,
			reader_data,
			name
	);

	if (thread == NULL) {
		RRR_MSG_ERR("Could not preload thread '%s' in python3 instance %s\n",
				name, INSTANCE_D_NAME(python3_data->thread_data));
		ret = 1;
		goto out;
	}

	reader_data->thread = thread;

	out:
	return ret;
}

static int threads_start(struct python3_data *data) {
	int ret = 0;

	char name[128];
	const char *name_template = "%s %s read thread";

	if (strlen(data->thread_data->thread->name) > sizeof(name) - strlen(name_template)) {
		RRR_BUG("thread name was too long in python3 threads_start\n");
	}

	if ((ret = rrr_thread_new_collection(&data->thread_collection)) != 0) {
		RRR_MSG_ERR("Could not create thread collection in python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (data->source_function != NULL && *(data->source_function) != '\0') {
		sprintf(name, name_template, data->thread_data->thread->name, "source");
		if (preload_reader_thread(
				&data->source_thread,
				data->thread_collection,
				data,
				data->source_fork,
				&data->output_buffer,
				name
		) != 0) {
			goto out_destroy_collection;
		}
	}

	if (data->process_function != NULL && *(data->process_function) != '\0') {
		sprintf(name, name_template, data->thread_data->thread->name, "process");
		if (preload_reader_thread(
				&data->process_thread,
				data->thread_collection,
				data,
				data->processing_fork,
				&data->output_buffer,
				name
		) != 0) {
			goto out_destroy_collection;
		}
	}

	if (data->source_thread.thread != NULL && rrr_thread_start(data->source_thread.thread) != 0) {
		RRR_MSG_ERR("Could not start source read thread collection in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}

	if (data->process_thread.thread != NULL && rrr_thread_start(data->process_thread.thread) != 0) {
		RRR_MSG_ERR("Could not start process read thread collection in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}

	if (rrr_thread_start_all_after_initialized(data->thread_collection) != 0) {
		RRR_MSG_ERR("Error while waiting for threads to initialize in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		return (EXIT_FAILURE);
	}

	goto out;
	out_destroy_collection:
		rrr_thread_destroy_collection(data->thread_collection);

	out:
	return ret;
}

// We shouldn't really end up here, but...
void python3_ghost_handler (struct rrr_thread *thread) {
	struct python3_reader_data *data = thread->private_data;

	// See threads_cleanup()-function
	data->data->reader_thread_became_ghost = 1;
}

void threads_cleanup(void *arg) {
	struct python3_data *data = arg;

	if (data->thread_collection != NULL) {
		rrr_threads_stop_and_join(data->thread_collection, python3_ghost_handler);
		rrr_thread_destroy_collection(data->thread_collection);
		data->thread_collection = NULL;
	}

	// Since the reader threads might continue to use our memory after they
	// begin to run again, we cannot proceed.
	if (data->reader_thread_became_ghost != 0) {
		RRR_MSG_ERR("Could not stop reader threads in python3 module instance %s. Can't continue.",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}
}

static void *thread_entry_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;
	struct python3_preload_data *preload_data = thread_data->preload_data;
	struct poll_collection poll;

	RRR_DBG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(python3_stop, data);
	// Reader threads MUST be stopped before we clean up other data
	pthread_cleanup_push(threads_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	if (data_init(data, preload_data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("python3 instance %s tstate: %p\n", INSTANCE_D_NAME(thread_data), data->tstate);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK) != 0) {
		RRR_MSG_ERR("Python3 instance %s requires poll_delete from senders\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	int no_polling = 1;
	if (poll_collection_count (&poll) > 0) {
		if (!data->process_function) {
			RRR_MSG_ERR("Python3 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	if (python3_start(data) != 0) {
		RRR_MSG_ERR("Python3 instance %s failed to start python program\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	int res = 0;
	if ((res = python3_swap_thread_out(&data->python3_thread_ctx))) {
		RRR_MSG_ERR("python3 return from thread swap out was not 0 but %i in instance %s\n",
				res, INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);

	if (threads_start(data) != 0) {
		RRR_MSG_ERR("Python3 instance %s failed to start reader threads\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	// This must be delayed as the results from any config functions are
	// asynchronously received
	uint64_t check_settings_used_time = rrr_time_get_64() + 1000000;

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_update_watchdog_time(thread_data->thread);

		if (check_settings_used_time != 0 && check_settings_used_time > rrr_time_get_64()) {
			rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);
			check_settings_used_time = 0;
		}

		int output_buffer_size = rrr_fifo_buffer_get_entry_count(&data->output_buffer);

		if (output_buffer_size > 500) {
			usleep(1000);
		}
		else {
			if (sigchld_pending) {
				rrr_py_handle_sigchld(child_exit_handler, data);
				sigchld_pending = 0;
			}

			if (no_polling) {
				usleep (10000);
			}
			else {
				if ((res = python3_poll(data, &poll)) != 0) {
					RRR_MSG_ERR("python3 return from read from processor was not 0 but %i in instance %s\n",
							res, INSTANCE_D_NAME(thread_data));
					break;
				}
			}

			if (rrr_thread_check_any_stopped (data->thread_collection) != 0) {
				RRR_MSG_ERR("One or more reader threads have stopped in python3 instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}
	}

	out_message:
	RRR_DBG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

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

static struct rrr_module_operations module_operations = {
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

	RRR_DBG_1("Python got signal %i\n", signal);
	if (signal == SIGCHLD) {
		sigchld_pending = 1;
		ret = 0;
		RRR_DBG_1("Python took SIGCHLD signal\n");
	}
	else {
		RRR_DBG_1("Python did not take signal\n");
	}

	return ret;
}
__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_FORK;
	data->signal_handler = signal_handler;
}

void unload(void) {
	RRR_DBG_1 ("Destroy python3 module\n");
}

