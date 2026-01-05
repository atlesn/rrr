/*

Read Route Record

Copyright (C) 2018-2023 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../lib/log.h"

#include "../lib/allocator.h"
#include "../lib/array.h"
#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/read.h"
#include "../lib/send_loop.h"
#include "../lib/event/event.h"
#include "../lib/event/event_collection.h"
#include "../lib/event/event_collection_struct.h"
#include "../lib/socket/rrr_socket_common.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/rrr_readdir.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/fs.h"
#include "../lib/socket/rrr_socket_client.h"

#define RRR_DIRECTORY_DEFAULT_PROBE_INTERVAL_S 5LLU

struct directory_data;

struct directory_data {
	struct rrr_instance_runtime_data *thread_data;

	char *directory;
	char *prefix;

	rrr_setting_uint probe_interval_s;

	struct rrr_event_collection events;
	rrr_event_handle event_probe;
};

static int directory_data_init(struct directory_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));

	return 0;
}

static void directory_data_cleanup(void *arg) {
	struct directory_data *data = (struct directory_data *) arg;
	rrr_event_collection_clear(&data->events);
	RRR_FREE_IF_NOT_NULL(data->directory);
	RRR_FREE_IF_NOT_NULL(data->prefix);
}

static int directory_parse_config (struct directory_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;
	int ret_keep = 0;

	/* Don't goto out in non-critical errors, check all possible errors first. */

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("directory_probe_interval_s", probe_interval_s, RRR_DIRECTORY_DEFAULT_PROBE_INTERVAL_S);
	if (data->probe_interval_s == 0) {
		RRR_MSG_0("Parameter 'directory_probe_interval_s' cannot be zero for instance %s\n", config->name_debug);
		ret_keep = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("directory_prefix", prefix);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("directory_directory", directory);
	if (data->directory == NULL) {
		RRR_MSG_0("Required parameter 'directory_directory' missing for instance %s\n", config->name_debug);
		ret_keep = 1;
	}
	for (size_t i = strlen(data->directory) - 1; i > 0; i--) {
		if (data->directory[i] == '/')
			data->directory[i] = '\0';
		else
			break;
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret | ret_keep;
}

struct directory_probe_callback_data {
	struct directory_data *data;
	struct rrr_array *array;
	char directory_tmp[PATH_MAX + 1];
	char name_tmp[PATH_MAX + 1];
	int file_count;
};

static int directory_read_all_to_message_write_callback_file_basename_callback (
		const char *path,
		const char *dir,
		const char *name,
		void *arg
) {
	struct directory_probe_callback_data *callback_data = arg;

	(void)(path);

	if (strlen(dir) > sizeof(callback_data->directory_tmp) - 1 || strlen(name) > sizeof(callback_data->name_tmp) - 1) {
		RRR_BUG("Directory or name length exceeds maximum\n");
	}

	strcpy(callback_data->directory_tmp, dir);
	strcpy(callback_data->name_tmp, name);

	return 0;
}

static int directory_probe_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct directory_probe_callback_data *callback_data = private_data;

	(void)(entry);

	int ret = 0;

	if ((ret = rrr_util_fs_basename (
			orig_path,
			directory_read_all_to_message_write_callback_file_basename_callback,
			callback_data
	)) != 0) {
		goto out;
	}

	assert(strcmp(callback_data->data->directory, callback_data->directory_tmp) == 0 && "Directory mismatch");

	if (type != DT_REG) {
		RRR_DBG_3("Found non-file entry %s->%s in directory %s in directory instance %s, ignoring\n",
			callback_data->name_tmp, resolved_path, callback_data->directory_tmp, INSTANCE_D_NAME(callback_data->data->thread_data));
		goto out;
	}

	RRR_DBG_3("Found file %s->%s in directory %s in directory instance %s\n",
		callback_data->name_tmp, resolved_path, callback_data->directory_tmp, INSTANCE_D_NAME(callback_data->data->thread_data));

	if ((ret = rrr_array_push_value_str_with_tag(callback_data->array, "file_name", callback_data->name_tmp)) != 0) {
		RRR_MSG_0("Failed to push array value in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_str_with_tag(callback_data->array, "file_path_resolved", orig_path)) != 0) {
		RRR_MSG_0("Failed to push array value in %s\n", __func__);
		goto out;
	}

	callback_data->file_count++;

	out:
	return ret;
}

static int directory_probe_message_broker_callback(struct rrr_msg_holder *entry, void *arg) {
	struct directory_probe_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_array_new_message_from_array(&msg, callback_data->array, rrr_time_get_64(), NULL, 0)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	entry->message = msg;
	entry->data_length = MSG_TOTAL_SIZE(msg);

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int directory_probe (struct directory_data *data, const char *directory, const char *prefix) {
	int ret = 0;

	struct rrr_array array = {0};

	struct directory_probe_callback_data callback_data = {
		data,
		&array,
		{0},
		{0},
		0
	};

	if ((ret = rrr_array_push_value_str_with_tag(&array, "file_directory", data->directory)) != 0) {
		RRR_MSG_0("Failed to push array value in %s\n", __func__);
		goto out;
	}

	RRR_DBG_2("Directory instance %s probing for files in '%s' using prefix '%s'\n",
		INSTANCE_D_NAME(data->thread_data), directory, prefix);

	if ((ret = rrr_readdir_foreach_prefix (
			directory,
			prefix, // NULL allowed
			directory_probe_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to probe directory in directory instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (callback_data.file_count == 0) {
		RRR_DBG_2("Directory instance %s found no matching files in directory %s while probing, not creating array message\n",
			INSTANCE_D_NAME(data->thread_data), directory);
		goto out;
	}

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			directory_probe_message_broker_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Could not create new message in file instance %s, return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	RRR_DBG_2("Directory instance %s created array message with %i found files in directory %s\n",
		INSTANCE_D_NAME(data->thread_data), callback_data.file_count, directory);

	out:
	rrr_array_clear(&array);
	return ret;
}

static void directory_event_probe (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct directory_data *data = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (directory_probe(data, data->directory, data->prefix) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static int directory_periodic(RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct directory_data *data = thread_data->private_data;

	(void)(data);

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		return RRR_EVENT_EXIT;
	}
	rrr_thread_watchdog_time_update(thread);

	return RRR_EVENT_OK;
}

static void *thread_entry_directory (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct directory_data *data = thread_data->private_data = thread_data->private_memory;

	if (directory_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in directory instance %s\n", INSTANCE_D_NAME(thread_data));
		return NULL;
	}

	RRR_DBG_1 ("Directory thread data is %p\n", thread_data);

	pthread_cleanup_push(directory_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (directory_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("Directory %p instance %s probe interval is %" PRIrrrbl "s in directory '%s' with prefix '%s'\n",
			thread_data,
			INSTANCE_D_NAME(thread_data),
			data->probe_interval_s,
			(data->directory != NULL ? data->directory : ""),
			(data->prefix != NULL ? data->prefix : "")
	);

	if (rrr_event_collection_push_periodic (
			&data->event_probe,
			&data->events,
			directory_event_probe,
			data,
			data->probe_interval_s * 1000 * 1000
	) != 0) {
		RRR_MSG_0("Failed to create probe event in directory instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	EVENT_ADD(data->event_probe);
	EVENT_ACTIVATE(data->event_probe); // Probe immediately when starting

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			directory_periodic,
			thread
	);

	out_cleanup:
	RRR_DBG_1 ("Thread directory instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	return NULL;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_directory,
	NULL
};

struct rrr_instance_event_functions event_functions = {
	NULL
};

static const char *module_name = "directory";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->private_data = NULL;
		data->event_functions = event_functions;
}

void unload(void) {
}
