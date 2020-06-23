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

#include "../lib/python3/python3.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/message_addr.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/log.h"

struct rrr_fork_handler;

struct python3_reader_data {
	struct python3_fork *fork;
	struct python3_data *data;
	struct rrr_ip_buffer_entry_collection output_buffer;
	struct rrr_thread *thread;
	struct rrr_message_addr previous_address_msg;
	int message_counter;
	int loop_count;
};

struct python3_data {
	struct rrr_instance_thread_data *thread_data;

	char *python3_module;
	char *source_function;
	char *process_function;
	char *config_function;
	char *module_path;

	struct python3_fork *processing_fork;
	struct python3_fork *source_fork;

	struct rrr_thread_collection *thread_collection;
	struct python3_reader_data source_thread;
	struct python3_reader_data process_thread;

	int reader_thread_became_ghost;
};

int data_init (
		struct python3_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return ret;
}

void data_cleanup(void *arg) {
	struct python3_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->python3_module);
	RRR_FREE_IF_NOT_NULL(data->source_function);
	RRR_FREE_IF_NOT_NULL(data->process_function);
	RRR_FREE_IF_NOT_NULL(data->config_function);
	RRR_FREE_IF_NOT_NULL(data->module_path);
}

struct python3_send_config_callback_data {
	struct python3_data *data;
	struct python3_fork *target;
};

int python3_send_config_callback (struct rrr_setting_packed *setting_packed, void *callback_arg) {
	struct python3_send_config_callback_data *data = callback_arg;

	RRR_DBG_3("python3 instance %s sending configuration parameter %s to application\n",
			INSTANCE_D_NAME(data->data->thread_data), setting_packed->name);

	int ret = rrr_py_persistent_process_setting(data->target, setting_packed);
	if (ret != 0) {
		RRR_MSG_0("Could not send setting to python3 config function in instance %s:\n",
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

	// START PROCESSING THREAD
	if (data->process_function != NULL) {
		if ((ret = rrr_py_start_persistent_rw_fork (
				&data->processing_fork,
				INSTANCE_D_FORK(data->thread_data),
				data->module_path,
				data->python3_module,
				data->process_function,
				data->config_function
		)) != 0) {
			RRR_MSG_0("Could not start python3 process function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_thread_out;
		}

		if (python3_send_config(data, data->processing_fork) != 0) {
			RRR_MSG_0("Could not send configuration to processing thread in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out_thread_out;
		}
	}

	// START SOURCE THREAD
	if (data->source_function != NULL) {
		if ((ret = rrr_py_start_persistent_rw_fork (
				&data->source_fork,
				INSTANCE_D_FORK(data->thread_data),
				data->module_path,
				data->python3_module,
				data->source_function,
				data->config_function
		)) != 0) {
			RRR_MSG_0("Could not start python3 source function thread in instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out_thread_out;
		}

		if (python3_send_config(data, data->source_fork) != 0) {
			RRR_MSG_0("Could not send configuration to source thread in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out_thread_out;
		}

		// This stops read/write behavior and initiates source only behavior
		if ((ret = python3_send_start_sourcing(data->source_fork)) != 0) {
			RRR_MSG_0("Could not start sourcing in instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out_thread_out;
		}
	}

	out_thread_out:
	return ret;
}

void python3_stop(void *arg) {
	struct python3_data *data = arg;

	rrr_py_fork_terminate_and_destroy(data->processing_fork);
	rrr_py_fork_terminate_and_destroy(data->source_fork);

	data->processing_fork = NULL;
	data->source_fork = NULL;
}

int parse_config(struct python3_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->python3_module, config, "python3_module");

	if (ret != 0) {
		RRR_MSG_0("No python3_module specified for python module\n");
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_function, config, "python3_source_function");
	rrr_instance_config_get_string_noconvert_silent (&data->process_function, config, "python3_process_function");
	rrr_instance_config_get_string_noconvert_silent (&data->config_function, config, "python3_config_function");
	rrr_instance_config_get_string_noconvert_silent (&data->module_path, config, "python3_module_path");

	if (data->source_function == NULL && data->process_function == NULL) {
		RRR_MSG_0("No source or processor function defined for python3 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int python3_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	struct python3_data *python3_data = thread_data->private_data;

	rrr_thread_update_watchdog_time(python3_data->thread_data->thread);

	const struct rrr_message *message = entry->message;

	RRR_DBG_3("python3 instance %s processing message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(python3_data->thread_data), message->timestamp);

	ret = rrr_py_persistent_process_message (
			python3_data->processing_fork,
			entry
	);
	if (ret != 0) {
		RRR_MSG_0("Error returned from rrr_py_persistent_process_message in instance %s\n",
				INSTANCE_D_NAME(python3_data->thread_data));
		ret = 1;
		goto out;
	}
	out:
	rrr_ip_buffer_entry_unlock(entry);
	return (ret == 0 ? 0 : RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR);
}
/*
int thread_cancel_callback(void *arg, PyThreadState *tstate_orig) {
	(void)(tstate_orig);

	// Might also kill forks from other threads
	rrr_py_terminate_forks (&data->rrr_objects);

	struct python3_data *data = arg;
	rrr_py_terminate_forks (&data->rrr_objects);
	return 0;
}
*/
/*
static int thread_cancel_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data;
	RRR_MSG_0 ("Custom cancel function for thread %s/%p running\n", thread->name, thread);

	// No need to hold GIL
	rrr_py_terminate_forks (&data->rrr_objects);

	if (rrr_py_with_global_tstate_do(thread_cancel_callback, data, 1) != 0) {
		RRR_MSG_0("Could not terminate threads in thread_cancel_python3\n");
		PyErr_Print();
		return 1;
	}

	pthread_cancel(thread->thread);

	RRR_MSG_0 ("Custom cancel function done for %s/%p\n", thread->name, thread);

	return 0;
}
*/

struct read_from_processor_callback_data {
	struct python3_data *data;
	struct rrr_message_addr *previous_addr_msg;
	int message_count;
};

int read_from_source_or_processor_finalize (
		struct rrr_ip_buffer_entry *entry,
		struct read_from_processor_callback_data *callback_data
) {
	// Entry must be pre-filled with socket message

	struct rrr_message *message = entry->message;

	struct python3_data *python3_data = callback_data->data;
	struct rrr_message_addr *previous_address_msg = callback_data->previous_addr_msg;

	int ret = 0;

	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(message)) {
		struct rrr_message *rrr_message = (struct rrr_message *) message;

		RRR_DBG_3("python3 instance %s writing message with timestamp %" PRIu64 " to output buffer\n",
				INSTANCE_D_NAME(python3_data->thread_data), rrr_message->timestamp);

		callback_data->message_count++;

		entry->message = message;
		if (entry->data_length != MSG_TOTAL_SIZE(message)) {
			RRR_BUG("Size mismatch in read_from_source_or_processor_finalize %u<>%u\n",
					entry->data_length, MSG_TOTAL_SIZE(message));
		}

		uint64_t addr_len_tmp = RRR_MSG_ADDR_GET_ADDR_LEN(previous_address_msg);
		if (addr_len_tmp > 0) {
			if (addr_len_tmp > sizeof(previous_address_msg->addr)) {
				RRR_BUG("BUG: Address length too long in read_from_source_or_processor_finalize\n");
			}
			memcpy(&entry->addr, &previous_address_msg->addr, addr_len_tmp);
			entry->addr_len = addr_len_tmp;
			RRR_MSG_ADDR_SET_ADDR_LEN(previous_address_msg, 0);
		}
	}
	else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_ADDR(message)) {
		*(callback_data->previous_addr_msg) = *((struct rrr_message_addr *) message);
		goto out_clear_message;
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(message)) {
		struct rrr_setting_packed *setting = (struct rrr_setting_packed *) message;
		rrr_settings_update_used (
				python3_data->thread_data->init_data.instance_config->settings,
				setting->name,
				setting->was_used,
				rrr_settings_iterate_nolock
		);
		goto out_clear_message;
	}
	else {
		RRR_MSG_0("Warning: Received non rrr_message, non rrr_settings and non address msg from python3 source/processor function, discarding it.\n");
		ret = 1;
		goto out;
	}

	out:
		return ret;
	out_clear_message:
		RRR_FREE_IF_NOT_NULL(entry->message);
		return ret;
}

int read_from_source_or_processor_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct python3_reader_data *data = arg;
	struct python3_data *python3_data = data->data;
	struct python3_fork *fork = data->fork;

	int ret = 0;

	struct read_from_processor_callback_data callback_data = {
			python3_data,
			&data->previous_address_msg,
			0
	};

	if (fork->invalid == 1) {
		RRR_MSG_0("Fork was invalid in rrr_py_persistent_receive_message, child has exited\n");
		ret = 1;
		goto out;
	}

	size_t target_size = 0;
	ret = rrr_py_persistent_process_read_from_fork(&entry->message, &target_size, fork);
	if (ret != 0) {
		RRR_MSG_0("Error while receiving message from python3 child\n");
		ret = 1;
		goto out;
	}

	if (entry->message == NULL) {
		ret = RRR_MESSAGE_BROKER_DROP;
		goto out;
	}

	entry->data_length = target_size;

	data->message_counter += callback_data.message_count;

	RRR_DBG_3("rrr_py_persistent_receive_message got a message\n");

	// Might remove the message from the entry, checked for below
	ret = read_from_source_or_processor_finalize(entry, &callback_data);
	if (ret != 0) {
		RRR_MSG_0("Error from callback function while receiving message from python3 child\n");
		ret = 1;
		goto out;
	}

	if (data->loop_count <= 0) {
		data->loop_count = 500;
	}

	ret = 0;
	if (entry->message == NULL) {
		ret |= RRR_MESSAGE_BROKER_DROP;
	}

	if (--(data->loop_count) >= 0) {
		ret |= RRR_MESSAGE_BROKER_AGAIN;
	}

	out:
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static void *thread_entry_python3_reader (struct rrr_thread *thread) {
	struct python3_reader_data *data = thread->private_data;
	struct python3_data *python3_data = data->data;

//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	uint64_t start_time = rrr_time_get_64();
	unsigned int tick = 0;
	while (rrr_thread_check_encourage_stop(data->thread) == 0) {
		rrr_thread_update_watchdog_time(data->thread);

//		printf("python3 reader tick: %u\n", tick);

		int message_counter_old = data->message_counter;

		if (rrr_message_broker_write_entry (
				INSTANCE_D_BROKER(python3_data->thread_data),
				INSTANCE_D_HANDLE(python3_data->thread_data),
				NULL,
				0,
				0,
				read_from_source_or_processor_callback,
				data
		) != 0) {
			RRR_MSG_0("Error while reading in python3 instance %s thread '%s'\n",
					INSTANCE_D_NAME(python3_data->thread_data), data->thread->name);
			break;
		}

//		printf("python3 reader tick: %u write done\n", tick);

		if (data->message_counter == message_counter_old) {
			rrr_posix_usleep(10000);
		}

		uint64_t now_time = rrr_time_get_64();
		if (now_time - start_time > 1000000) {
			RRR_DBG_1("python3 read thread '%s' messages per second: %i\n",
					data->thread->name, data->message_counter);
			data->message_counter = 0;
			start_time = rrr_time_get_64();
		}

		tick++;
	}

//	pthread_cleanup_pop(1);
	pthread_exit(0);
}

int preload_reader_thread (
		struct python3_reader_data *reader_data,
		struct rrr_thread_collection *collection,
		struct python3_data *python3_data,
		struct python3_fork *fork,
		const char *name
) {
	int ret = 0;
	struct rrr_thread *thread = NULL;

	reader_data->message_counter = 0;
	reader_data->data = python3_data;
	reader_data->fork = fork;

	thread = rrr_thread_preload_and_register (
			collection,
			thread_entry_python3_reader,
			NULL,
			NULL,
			NULL,
			NULL, // We don't call cleanup_ghost_data, so this can be NULL
			RRR_THREAD_START_PRIORITY_NORMAL,
			reader_data,
			name
	);

	if (thread == NULL) {
		RRR_MSG_0("Could not preload thread '%s' in python3 instance %s\n",
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
		RRR_MSG_0("Could not create thread collection in python3 instance %s\n",
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
				name
		) != 0) {
			goto out_destroy_collection;
		}
	}

	if (data->source_thread.thread != NULL && rrr_thread_start(data->source_thread.thread) != 0) {
		RRR_MSG_0("Could not start source read thread collection in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}

	if (data->process_thread.thread != NULL && rrr_thread_start(data->process_thread.thread) != 0) {
		RRR_MSG_0("Could not start process read thread collection in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}

	if (rrr_thread_start_all_after_initialized(data->thread_collection, NULL, NULL) != 0) {
		RRR_MSG_0("Error while waiting for threads to initialize in python3 instance %s, can't continue.\n",
				INSTANCE_D_NAME(data->thread_data));
		return (EXIT_FAILURE);
	}

	goto out;
	out_destroy_collection:
		rrr_thread_destroy_collection(data->thread_collection, 0);

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
		rrr_thread_stop_and_join_all(data->thread_collection, python3_ghost_handler);
		rrr_thread_destroy_collection(data->thread_collection, 0);
		data->thread_collection = NULL;
	}

	// Since the reader threads might continue to use our memory after they
	// begin to run again, we cannot proceed.
	if (data->reader_thread_became_ghost != 0) {
		RRR_MSG_0("Could not stop reader threads in python3 module instance %s. Can't continue.",
				INSTANCE_D_NAME(data->thread_data));
		exit(EXIT_FAILURE);
	}
}

static void *thread_entry_python3 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct python3_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll;

	RRR_DBG_1 ("python3 thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	rrr_poll_collection_init(&poll);
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(python3_stop, data);
	// Reader threads MUST be stopped before we clean up other data
	pthread_cleanup_push(threads_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initalize data in python3 instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1("python3 instance %s\n", INSTANCE_D_NAME(thread_data));

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	rrr_poll_add_from_thread_senders(&poll, thread_data);

	int no_polling = 1;
	if (rrr_poll_collection_count (&poll) > 0) {
		if (!data->process_function) {
			RRR_MSG_0("Python3 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	if (python3_start(data) != 0) {
		RRR_MSG_0("Python3 instance %s failed to start python program\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	int res = 0;

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);

	if (threads_start(data) != 0) {
		RRR_MSG_0("Python3 instance %s failed to start reader threads\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	// This must be delayed as the results from any config functions are
	// asynchronously received
	uint64_t check_settings_used_time = rrr_time_get_64() + 1000000;
	uint64_t prev_stats_time = 0;

	unsigned int tick = 0;
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);
		uint64_t time_now = rrr_time_get_64();

//		printf ("Python 3 ticks: %u\n", tick);

		if (check_settings_used_time != 0 && check_settings_used_time > rrr_time_get_64()) {
			rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);
			check_settings_used_time = 0;
		}

		if (no_polling) {
			rrr_posix_usleep (10000);
		}
		else {
			if ((res = rrr_poll_do_poll_delete(thread_data, &poll, python3_poll_callback, 50)) != 0) {
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

		if (time_now - prev_stats_time > 1000000) {
			int delivery_entry_count  = 0;
			int delivery_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&delivery_entry_count,
					&delivery_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_ERR("Error while setting ratelimit in python3 instance %s\n",
					INSTANCE_D_NAME(thread_data));
				break;
			}

			prev_stats_time = rrr_time_get_64();

			rrr_py_call_fork_notifications_if_needed(INSTANCE_D_FORK(thread_data));
		}

		tick++;
	}

	out_message:
	RRR_DBG_1 ("python3 instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
//	pthread_cleanup_pop(1);
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

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_python3,
		NULL,
		test_config,
		NULL,
		//thread_cancel_python3
		NULL
};

static const char *module_name = "python3";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_FORK;
}

void unload(void) {
	RRR_DBG_1 ("Destroy python3 module\n");
}

