/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/rrr_strerror.h"
#include "../lib/read.h"
#include "../lib/array_tree.h"
#include "../lib/read_constants.h"
#include "../lib/mqtt/mqtt_topic.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/socket/rrr_socket_common.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/rrr_readdir.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/linked_list.h"
#include "../lib/input/input.h"

#define RRR_FILE_DEFAULT_READ_STEP_MAX_SIZE 4096
#define RRR_FILE_DEFAULT_PROBE_INTERVAL_MS 5000LLU
#define RRR_FILE_MAX_MAX_OPEN 65536
#define RRR_FILE_DEFAULT_MAX_OPEN RRR_FILE_MAX_MAX_OPEN
#define RRR_FILE_DEFAULT_TIMEOUT 0
#define RRR_FILE_MAX_SIZE_MB 32

#define RRR_FILE_F_IS_KEYBOARD (1<<0)

#define RRR_FILE_STOP RRR_READ_EOF

struct file {
	RRR_LL_NODE(struct file);
	struct rrr_read_session_collection read_session_collection;
	unsigned char type; // DT_*
	int flags;
	char *orig_path;
	char *real_path;
	int fd;
	struct stat file_stat;
	uint64_t total_messages;
	uint64_t last_read_time;
};

struct file_collection {
	RRR_LL_HEAD(struct file);
};

enum file_read_method {
	FILE_READ_METHOD_TELEGRAMS,
	FILE_READ_METHOD_ALL_SIMPLE,
	FILE_READ_METHOD_ALL_STRUCTURED
};

struct file_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_array_tree *tree;
	int do_try_keyboard_input;
	int do_no_keyboard_hijack;
	int do_unlink_on_close;

	int do_read_all_to_message_;
	char *read_all_method;

	enum file_read_method read_method;

	char *directory;
	char *prefix;
	rrr_setting_uint probe_interval;
	rrr_setting_uint max_messages_per_file;
	rrr_setting_uint max_read_step_size;
	rrr_setting_uint max_open;
	rrr_setting_uint timeout_s;

	char *topic;
	size_t topic_len;

	uint64_t message_count;

	struct file_collection files;
};

static void file_destroy(struct file *file) {
	rrr_read_session_collection_clear(&file->read_session_collection);

	if (file->fd > 0) {
		rrr_socket_close(file->fd);
	}

	RRR_FREE_IF_NOT_NULL(file->orig_path);
	RRR_FREE_IF_NOT_NULL(file->real_path);
	free(file);
}

static int file_collection_has (const struct file_collection *files, const char *orig_path) {
	RRR_LL_ITERATE_BEGIN(files, struct file);
		if (strcmp(orig_path, node->orig_path) == 0) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

static int file_collection_count (const struct file_collection *files) {
	return RRR_LL_COUNT(files);
}

static int file_collection_push (
		struct file_collection *files,
		unsigned char type,
		int flags,
		const char *orig_path,
		const char *real_path,
		int fd,
		const struct stat *file_stat
) {
	int ret = 0;

	struct file *file = NULL;

	if ((file = malloc(sizeof(*file))) == NULL) {
		RRR_MSG_0("Could not allocate memory in file_collection_push\n");
		ret = 1;
		goto out;
	}

	memset(file, '\0', sizeof(*file));

	if ((file->orig_path = strdup(orig_path)) == NULL) {
		RRR_MSG_0("Could not allocate memory for path in file_collection_push");
		ret = 1;
		goto out;
	}

	if ((file->real_path = strdup(real_path)) == NULL) {
		RRR_MSG_0("Could not allocate memory for path in file_collection_push");
		ret = 1;
		goto out;
	}

	file->type = type;
	file->fd = fd;
	file->flags = flags;
	file->file_stat = *file_stat;

	RRR_LL_PUSH(files, file);
	file = NULL;

	out:
	if (file != NULL) {
		file_destroy(file);
	}
	return ret;
}

static int file_data_init(struct file_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
	return 0;
}

static void file_data_cleanup(void *arg) {
	struct file_data *data = (struct file_data *) arg;
	RRR_LL_DESTROY (&data->files, struct file, file_destroy(node));
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
	RRR_FREE_IF_NOT_NULL(data->read_all_method);
	RRR_FREE_IF_NOT_NULL(data->directory);
	RRR_FREE_IF_NOT_NULL(data->prefix);
	RRR_FREE_IF_NOT_NULL(data->topic);
}

static int file_parse_config (struct file_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_probe_interval_ms", probe_interval, RRR_FILE_DEFAULT_PROBE_INTERVAL_MS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_prefix", prefix);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_topic", topic);
	if (data->topic != NULL) {
		data->topic_len = strlen(data->topic);
		if (rrr_mqtt_topic_validate_name(data->topic) != 0) {
			RRR_MSG_0("Validation of parameter file_topic with value '%s' failed in file instance %s\n",
					data->topic, config->name);
			ret = 1;
			goto out;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_directory", directory);
	if (data->directory == NULL) {
		RRR_MSG_0("Required parameter 'file_directory' missing for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_parse_array_tree_definition_from_config_silent_fail(&data->tree, config, "file_input_types")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Failed to parse array definition in file_input_types in instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}


	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_read_all_to_message", do_read_all_to_message_, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_read_all_method", read_all_method);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_try_keyboard_input", do_try_keyboard_input, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_no_keyboard_hijack", do_no_keyboard_hijack, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_unlink_on_close", do_unlink_on_close, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_messages_per_file", max_messages_per_file, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_read_step_size", max_read_step_size, RRR_FILE_DEFAULT_READ_STEP_MAX_SIZE);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_open", max_open, RRR_FILE_DEFAULT_MAX_OPEN);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_timeout_s", timeout_s, RRR_FILE_DEFAULT_TIMEOUT);

	/* Don't goto out in errors, check all possible errors first. */

	if (data->do_read_all_to_message_) {
		data->read_method = FILE_READ_METHOD_ALL_SIMPLE;
	}
	else {
		data->read_method = FILE_READ_METHOD_TELEGRAMS;
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("file_read_all_method")) {
		if (!data->do_read_all_to_message_) {
			RRR_MSG_0("Parameter file_read_all_method was set while file_read_all_to_message was not 'yes' in file instance %s, this is a configuration error.\n",
					config->name);
			ret = 1;
		}

		if (rrr_posix_strcasecmp(data->read_all_method, "simple") == 0) {
			data->read_method = FILE_READ_METHOD_ALL_SIMPLE;
		}
		else if (rrr_posix_strcasecmp(data->read_all_method, "structured") == 0) {
			data->read_method = FILE_READ_METHOD_ALL_STRUCTURED;

		}
		else {
			RRR_MSG_0("Unknown value '%s' for file_read_all_method in file instance %s, valid options are 'simple' and 'structured'.\n",
					data->read_all_method, config->name);
			ret = 1;
		}
	}

	if (data->max_open > RRR_FILE_MAX_MAX_OPEN) {
		RRR_MSG_0("Parameter file_max_open out of range for file instance %s (%" PRIrrrbl ">%i).\n",
				config->name, data->max_open, RRR_FILE_MAX_MAX_OPEN);
		ret = 1;
	}

	if (	!RRR_INSTANCE_CONFIG_EXISTS("file_input_types") &&
			data->do_read_all_to_message_ == 0 &&
			data->do_unlink_on_close == 0
	) {
		RRR_MSG_0("No actions defined in configuration for file instance %s, one or more must be specified\n", config->name);
		ret = 1;
	}

	if (	RRR_INSTANCE_CONFIG_EXISTS("file_input_types") &&
			data->do_read_all_to_message_ != 0
	) {
		RRR_MSG_0("Both file_input_types and do_read_all_to_message was set in file instance %s, this is a configuration error.\n", config->name);
		ret = 1;
	}

	if (data->do_read_all_to_message_ && data->max_messages_per_file != 0) {
		RRR_MSG_0("Both file_do_read_all_to_message and file_max_messages_per_file was set in file instance %s, this is a configuration error.\n", config->name);
		ret = 1;
	}

	if (data->max_read_step_size == 0) {
		RRR_MSG_0("file_max_read_step_size was zero in file instance %s, this is a configuration error.\n", config->name);
		ret = 1;
	}

	if (	RRR_INSTANCE_CONFIG_EXISTS("file_max_read_step_size") &&
			data->do_read_all_to_message_ != 0
	) {
		RRR_MSG_0("Both file_max_read_step_size and do_read_all_to_message was set in file instance %s, this is a configuration error.\n", config->name);
		ret = 1;
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static int file_probe_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct file_data *data = private_data;

	(void)(entry);

	int ret = 0;

	int fd = 0;

	if (file_collection_has(&data->files, orig_path)) {
		goto out;
	}

	if (data->max_open > 0 && file_collection_count(&data->files) >= (int) data->max_open) {
		ret = RRR_FILE_STOP;
		goto out;
	}

	if (type == DT_SOCK) {
		RRR_DBG_3("file instance %s connecting to socket '%s'=>'%s'\n", INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);

		if (rrr_socket_unix_connect(&fd, INSTANCE_D_NAME(data->thread_data), orig_path, 1) != 0) {
			RRR_MSG_0("Warning: Could not connect to socket '%s' in file instance %s\n", orig_path, INSTANCE_D_NAME(data->thread_data));
			ret = 0;
			goto out;
		}
	}
	else {
		int flags = O_RDONLY;

		if (type == DT_CHR || type == DT_FIFO) {
			if (type == DT_CHR) {
				RRR_DBG_3("file instance %s opening character device '%s'=>'%s'\n",
						INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
			}
			else {
				RRR_DBG_3("file instance %s opening fifo device '%s'=>'%s'\n",
						INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
			}
			flags |= O_NONBLOCK;
		}
		else if (type == DT_BLK) {
			RRR_DBG_3("file instance %s opening block device '%s'=>'%s'\n",
					INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
		}
		else if (type == DT_REG) {
			RRR_DBG_3("file instance %s opening file '%s'=>'%s'\n",
					INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
		}
		else {
			goto out;
		}

		if ((fd = rrr_socket_open(orig_path, flags, 0, INSTANCE_D_NAME(data->thread_data), data->do_unlink_on_close)) <= 0) {
			RRR_DBG_1("Note: Failed to open '%s'=>'%s' for reading in file instance %s: %s\n",
					orig_path, resolved_path, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
			goto out;
		}
	}

	int flags = 0;

	if (data->do_try_keyboard_input && type == DT_CHR) {
		if (rrr_input_device_grab(fd, 1) == 0) {
			if (data->do_no_keyboard_hijack && (ret = rrr_input_device_grab(fd, 0)) != 0) {
				RRR_MSG_0("Could not ungrab keyboard device '%s'=>'%s' in file instance %s\n",
						 orig_path, resolved_path, INSTANCE_D_NAME(data->thread_data));
				goto out;
			}
			flags |= RRR_FILE_F_IS_KEYBOARD;
			RRR_DBG_3("file instance %s character device '%s'=>'%s' recognized as keyboard event device\n",
					INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
		}
	}

	struct stat file_stat = {0};
	if (fstat(fd, &file_stat) != 0) {
		RRR_MSG_0("Warning: Failed to stat file %s: %s\n",
				resolved_path, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if ((ret = file_collection_push(&data->files, type, flags, orig_path, resolved_path, fd, &file_stat)) != 0) {
		goto out;
	}

	fd = 0;

	out:
	if (fd > 0) {
		rrr_socket_close_no_unlink(fd);
	}
	return ret;
}

static int file_probe (struct file_data *data) {
	return rrr_readdir_foreach_prefix (
			data->directory,
			data->prefix, // NULL allowed
			file_probe_callback,
			data
	);
}

struct file_read_array_write_callback_data {
	struct file_data *data;
	const struct rrr_array *array_final;
};

static int file_read_array_write_callback (struct rrr_msg_holder *entry, void *arg) {
	struct file_read_array_write_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *new_message = NULL;

	uint64_t time = rrr_time_get_64();

	if ((ret = rrr_array_new_message_from_collection (
			&new_message,
			callback_data->array_final,
			time,
			callback_data->data->topic,
			callback_data->data->topic_len
	)) != 0) {
		RRR_MSG_0("Could not create message in file_read_array_write_callback\n");
		goto out;
	}

	entry->message = new_message;
	entry->data_length = MSG_TOTAL_SIZE(new_message);

	RRR_DBG_2("file instance %s created array message with %i elements and timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(callback_data->data->thread_data), RRR_LL_COUNT(callback_data->array_final), time);

	callback_data->data->message_count += 1;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

struct file_read_callback_data {
	struct file_data *file_data;
	struct file *file;
};

static int file_read_array_callback (struct rrr_read_session *read_session, struct rrr_array *array_final, void *arg) {
	struct file_read_callback_data *callback_data = arg;

	int ret = 0;

	(void)(read_session);

	struct file_read_array_write_callback_data write_callback_data = {
			callback_data->file_data,
			array_final
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->file_data->thread_data),
			NULL,
			0,
			0,
			file_read_array_write_callback,
			&write_callback_data
	)) != 0) {
		RRR_MSG_0("Could not create new array message in file instance %s, return was %i\n",
				INSTANCE_D_NAME(callback_data->file_data->thread_data), ret);
		return ret;
	}

	callback_data->file->total_messages++;
	if (callback_data->file_data->max_messages_per_file != 0 && callback_data->file->total_messages >= callback_data->file_data->max_messages_per_file) {
		RRR_DBG_3("file instance %s closing file '%s'=>'%s' after max messages received (%" PRIu64 "/%" PRIrrrbl ")\n",
				INSTANCE_D_NAME(callback_data->file_data->thread_data),
				callback_data->file->orig_path,
				callback_data->file->real_path,
				callback_data->file->total_messages,
				callback_data->file_data->max_messages_per_file
		);
		ret = RRR_READ_EOF;
	}

	return ret;
}

static int file_read_all_to_message_get_target_size_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	(void)(read_session);
	(void)(arg);

	read_session->read_complete_method = RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ;

	return RRR_READ_OK;
}

struct file_read_all_to_message_write_callback_data {
	struct file_data *file_data;
	struct file *file;
	const struct rrr_read_session *read_session;
};

static int file_read_all_to_message_write_callback_simple (
		struct rrr_msg_holder *entry,
		struct file_data *file_data,
		const struct rrr_read_session *read_session
) {
	int ret = 0;

	uint64_t time = rrr_time_get_64();

	struct rrr_msg_msg *reading = NULL;
	if ((ret = rrr_msg_msg_new_empty (
			&reading,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			time,
			file_data->topic_len,
			read_session->rx_buf_wpos
	)) != 0) {
		RRR_MSG_0("Could not create message in file_read_all_to_message_write_callback_simple\n");
		goto out;
	}

	if (file_data->topic != NULL && *(file_data->topic) != '\0') {
		memcpy(MSG_TOPIC_PTR(reading), file_data->topic, file_data->topic_len);
	}

	memcpy(MSG_DATA_PTR(reading), read_session->rx_buf_ptr, read_session->rx_buf_wpos);

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	RRR_DBG_2("file instance %s created message with raw file_data of size %lu and timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(file_data->thread_data), read_session->rx_buf_wpos, time);

	out:
	return ret;
}

static int file_read_all_to_message_write_callback_structured (
		struct rrr_msg_holder *entry,
		struct file_data *file_data,
		const struct rrr_read_session *read_session,
		struct file *file
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	if ((ret = rrr_array_push_value_blob_with_tag_with_size (
			&array_tmp, "data", read_session->rx_buf_ptr, read_session->rx_buf_wpos
	)) != 0) {
		RRR_MSG_0("Failed to push file data to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag (
			&array_tmp, "size", read_session->rx_buf_wpos
	)) != 0) {
		RRR_MSG_0("Failed to push file size to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_str_with_tag (
			&array_tmp, "path_original", file->orig_path
	)) != 0) {
		RRR_MSG_0("Failed to push file original path to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_str_with_tag (
			&array_tmp, "path_resolved", file->real_path
	)) != 0) {
		RRR_MSG_0("Failed to push file resolved path to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp, "atime", file->file_stat.st_atim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file atime to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp, "mtime", file->file_stat.st_mtim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file mtime to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			&array_tmp, "ctime", file->file_stat.st_ctim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file ctime to array in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	uint64_t time = rrr_time_get_64();

	struct rrr_msg_msg *reading = NULL;
	if ((ret = rrr_array_new_message_from_collection (
			&reading,
			&array_tmp,
			time,
			file_data->topic,
			file_data->topic_len
	)) != 0) {
		RRR_MSG_0("Could not create array message in file_read_all_to_message_write_callback_structured\n");
		goto out;
	}

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	RRR_DBG_2("file instance %s created message with structured raw file_data of size %lu and timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(file_data->thread_data), read_session->rx_buf_wpos, time);

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int file_read_all_to_message_write_callback (struct rrr_msg_holder *entry, void *arg) {
	struct file_read_all_to_message_write_callback_data *callback_data = arg;

	int ret = 0;

	if (callback_data->file_data->read_method == FILE_READ_METHOD_ALL_SIMPLE) {
		if ((ret = file_read_all_to_message_write_callback_simple (
				entry,
				callback_data->file_data,
				callback_data->read_session
		)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = file_read_all_to_message_write_callback_structured (
				entry,
				callback_data->file_data,
				callback_data->read_session,
				callback_data->file
		)) != 0) {
			goto out;
		}
	}

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int file_read_all_to_message_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct file_read_callback_data *callback_data = arg;
	struct file_data *data = callback_data->file_data;

	int ret = 0;

	struct file_read_all_to_message_write_callback_data write_callback_data = {
			data,
			callback_data->file,
			read_session
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			file_read_all_to_message_write_callback,
			&write_callback_data
	)) != 0) {
		RRR_MSG_0("Could not create new message in file instance %s, return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	data->message_count++;

	out:
	return ret;
}

static int file_read (uint64_t *bytes_read, struct file_data *data, struct file *file) {
	int ret = 0;

	struct rrr_array array_final = {0};

	if (data->timeout_s != 0) {
		uint64_t time_min = rrr_time_get_64() - (data->timeout_s * 1000 * 1000);
		if (file->last_read_time == 0) {
			file->last_read_time = rrr_time_get_64();
		}
		else if (file->last_read_time < time_min) {
			RRR_DBG_1("Timeout for file %s in instance %s, closing.\n",
					file->orig_path, INSTANCE_D_NAME(data->thread_data));
			ret = RRR_READ_EOF;
			goto out;
		}
	}

	int socket_flags = RRR_SOCKET_READ_METHOD_READ_FILE | RRR_SOCKET_READ_NO_GETSOCKOPTS;

	if (file->type == DT_CHR || file->type == DT_SOCK || file->type == DT_FIFO) {
		// For devices without any end
		socket_flags |= RRR_SOCKET_READ_CHECK_POLLHUP;
	}
	else {
		// For devices with finite size or files
		socket_flags |= RRR_SOCKET_READ_CHECK_EOF;
	}

	if (file->flags & RRR_FILE_F_IS_KEYBOARD) {
		socket_flags |= RRR_SOCKET_READ_INPUT_DEVICE;
	}

	struct file_read_callback_data read_callback_data = {
		data,
		file
	};

	if (data->read_method == FILE_READ_METHOD_TELEGRAMS) {
		if (data->tree == NULL) {
			RRR_BUG("BUG: No array tree was present for read method TELEGRAMS in file_read\n");
		}
		if ((ret = rrr_socket_common_receive_array_tree (
				bytes_read,
				&file->read_session_collection,
				file->fd,
				socket_flags,
				&array_final,
				data->tree,
				0,
				data->max_read_step_size,
				RRR_FILE_MAX_SIZE_MB * 1024 * 1024,
				file_read_array_callback,
				&read_callback_data
		)) != 0) {
			if (ret == RRR_READ_INCOMPLETE) {
				ret = 0;
				goto out;
			}
			if (ret != RRR_READ_EOF) {
				RRR_MSG_0("Warning: Failed while reading array data from file '%s'=>'%s' in file instance %s\n",
						file->orig_path, file->real_path, INSTANCE_D_NAME(data->thread_data));
			}
			goto out;
		}
	}
	else if (data->read_method == FILE_READ_METHOD_ALL_SIMPLE ||
			data->read_method == FILE_READ_METHOD_ALL_STRUCTURED
	) {
		if (data->tree != NULL) {
			RRR_BUG("BUG: Two methods was specified in file_read, config parser should check for this\n");
		}

		if ((ret = rrr_socket_read_message_default (
				bytes_read,
				&file->read_session_collection,
				file->fd,
				65536,
				65536,
				RRR_FILE_MAX_SIZE_MB * 1024 * 1024,
				socket_flags,
				file_read_all_to_message_get_target_size_callback,
				NULL,
				file_read_all_to_message_complete_callback,
				&read_callback_data
		)) != 0) {
			if (ret == RRR_READ_EOF) {
				// Close file
				ret = RRR_READ_SOFT_ERROR;
			}
			else if (ret == RRR_READ_INCOMPLETE) {
				ret = 0;
			}
			else {
				RRR_MSG_0("Error while reading from '%s'=>'%s' in file instance %s, return was %i\n",
						file->orig_path, file->real_path, INSTANCE_D_NAME(data->thread_data), ret);
				goto out;
			}
		}
		else {
			// Return soft error to close file
			ret = RRR_READ_SOFT_ERROR;
		}
	}
	else {
		RRR_BUG("BUG: Unknown read_method %i in file_read\n", data->read_method);
	}

	file->last_read_time = rrr_time_get_64();

	out:
	rrr_array_clear(&array_final);
	return ret;
}

static int file_read_all (uint64_t *bytes_read_accumulator, struct file_data *data) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&data->files, struct file);
		uint64_t bytes_read_tmp = 0;
		if ((ret = file_read(&bytes_read_tmp, data, node)) != 0) {
			if (ret & RRR_SOCKET_HARD_ERROR) {
				goto out;
			}
			RRR_LL_ITERATE_SET_DESTROY();
			ret = 0;
		}
		(*bytes_read_accumulator) += bytes_read_tmp;
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->files, 0; file_destroy(node));

	out:
	return ret;
}

static void *thread_entry_file (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct file_data *data = thread_data->private_data = thread_data->private_memory;

	if (file_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in file instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("File thread data is %p\n", thread_data);

	pthread_cleanup_push(file_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (file_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("File %p instance %s probe interval is %" PRIrrrbl " ms in directory '%s' with prefix '%s'\n",
			thread_data,
			INSTANCE_D_NAME(thread_data),
			data->probe_interval,
			(data->directory != NULL ? data->directory : ""),
			(data->prefix != NULL ? data->prefix : "")
	);

	const uint64_t probe_interval = data->probe_interval * 1000;

	uint64_t time_prev_stats = rrr_time_get_64();
	uint64_t time_next_probe = time_prev_stats;

	uint64_t bytes_read_accumulator = 0;
	uint64_t messages_count_prev = 0;

	int ticks = 0;
	uint64_t messages_count_prev_stats = 0;

	int consecutive_nothing_happened = 0;

	while (!rrr_thread_check_encourage_stop(thread)) {
		rrr_thread_update_watchdog_time(thread);

		ticks++;

		uint64_t time_now = rrr_time_get_64();

		if (time_now >= time_next_probe) {
//			printf("probe interval %" PRIu64 "\n", probe_interval);
			int ret_tmp;
			if ((ret_tmp = file_probe(data)) != 0) {
				if (ret_tmp != RRR_FILE_STOP) {
					break;
				}
			}
			time_next_probe = time_now + probe_interval;
		}

		uint64_t bytes_read_tmp = 0;
		if (file_read_all(&bytes_read_tmp, data) != 0) {
			break;
		}
		bytes_read_accumulator += bytes_read_tmp;

		if (bytes_read_tmp == 0 && messages_count_prev == data->message_count) {
			consecutive_nothing_happened++;
		}
		else {
			consecutive_nothing_happened = 0;
		}

		messages_count_prev = data->message_count;

		if (consecutive_nothing_happened > 1000) {
//			printf("Long sleep\n");
			rrr_posix_usleep (5000); // 5ms
		}
		else if (consecutive_nothing_happened > 100) {
//			printf("Short sleep %i bytes read %" PRIu64 "\n", consecutive_nothing_happened, bytes_read_tmp);
			rrr_posix_usleep (2000); // 2ms
		}

		if (time_now - time_prev_stats > 1000000) {
			RRR_DBG_1("file instance %s messages per second %" PRIu64 " total %" PRIu64"\n",
					INSTANCE_D_NAME(thread_data), data->message_count - messages_count_prev_stats, data->message_count);

			time_prev_stats = time_now;

			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 0, "generated", data->message_count - messages_count_prev_stats);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 1, "bytes", bytes_read_accumulator);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 2, "ticks", ticks);

			bytes_read_accumulator = 0;
			messages_count_prev_stats = data->message_count;
			ticks = 0;
		}
	}

	out_cleanup:
	RRR_DBG_1 ("Thread file instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_file,
	NULL,
	NULL,
	NULL
};

static const char *module_name = "file";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}


