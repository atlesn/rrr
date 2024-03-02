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

#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/rrr_strerror.h"
#include "../lib/event/event.h"
#include "../lib/event/event_collection.h"
#include "../lib/event/event_collection_struct.h"
#include "../lib/read.h"
#include "../lib/array_tree.h"
#include "../lib/read_constants.h"
#include "../lib/map.h"
#include "../lib/send_loop.h"
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
#include "../lib/util/posix.h"
#include "../lib/util/gnu.h"
#include "../lib/util/fs.h"
#include "../lib/input/input.h"
#include "../lib/serial/serial.h"
#include "../lib/socket/rrr_socket_client.h"

#define RRR_FILE_DEFAULT_READ_STEP_MAX_SIZE 4096
#define RRR_FILE_DEFAULT_PROBE_INTERVAL_MS 5000LLU
#define RRR_FILE_MAX_MAX_OPEN 65536
#define RRR_FILE_DEFAULT_MAX_OPEN RRR_FILE_MAX_MAX_OPEN
#define RRR_FILE_DEFAULT_TIMEOUT_S 0
#define RRR_FILE_DEFAULT_WRITE_TIMEOUT_MS 0
#define RRR_FILE_DEFAULT_TTL 0
#define RRR_FILE_MAX_SIZE_MB 32

#define RRR_FILE_F_IS_KEYBOARD (1<<0)
#define RRR_FILE_F_IS_SERIAL (1<<1)

#define RRR_FILE_BUSY RRR_READ_BUSY
#define RRR_FILE_STOP RRR_READ_EOF
#define RRR_FILE_SOFT_ERROR RRR_READ_SOFT_ERROR

#define RRR_FILE_DT_IS_INFINITE(type) \
    (type == DT_CHR || type == DT_SOCK || type == DT_FIFO)

#define RRR_FILE_DT_IS_SENDER_RELIANT(type) \
    (type == DT_SOCK || type == DT_FIFO)

struct file_data;

struct file {
	RRR_LL_NODE(struct file);
	struct file_data *data;
	unsigned char type; // DT_*
	int flags;
	char *orig_path;
	char *real_path;
	int fd;
	struct stat file_stat;
	uint64_t total_messages;
	rrr_biglength bytes_to_write;
	rrr_biglength bytes_written;
};

struct file_collection {
	RRR_LL_HEAD(struct file);
};

enum file_read_method {
	FILE_READ_METHOD_NONE,
	FILE_READ_METHOD_TELEGRAMS,
	FILE_READ_METHOD_ALL_SIMPLE,
	FILE_READ_METHOD_ALL_STRUCTURED,
	FILE_READ_METHOD_ALL_FILE
};

struct file_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_array_tree *tree;
	int do_add_metadata;
	int do_strip_array_separators;
	int do_try_keyboard_input;
	int do_no_keyboard_hijack;
	int do_unlink_on_close;
	int do_sync_byte_by_byte;
	int do_try_serial_input;
	int do_serial_no_raw;
	int do_serial_parity_even;
	int do_serial_parity_odd;
	int do_serial_parity_none;
	int do_serial_one_stop_bit;
	int do_serial_two_stop_bits;
	int do_no_probing;
	int do_write_allow_directory_override;
	int do_write_append;
	int do_write_multicast;

	int write_mode;

	char *serial_parity;

	int serial_bps_set;
	rrr_setting_uint serial_bps;

	int do_read_all_to_message_;
	char *read_all_method;

	enum file_read_method read_method;
	enum rrr_instance_config_write_method write_method;

	char *directory;
	char *prefix;

	rrr_setting_uint probe_interval;
	rrr_setting_uint max_messages_per_file;
	rrr_setting_uint max_read_step_size;
	rrr_setting_uint max_open;
	rrr_setting_uint timeout_s;
	rrr_setting_uint write_timeout_ms;
	rrr_setting_uint ttl_s;

	enum rrr_send_loop_action write_timeout_action;

	char *topic;
	uint16_t topic_len;

	struct rrr_map write_values_list;

	uint64_t message_count;
	uint64_t message_count_prev;
	uint64_t bytes_read_accumulator;

	struct file_collection files;

	struct rrr_event_collection events;
	rrr_event_handle event_probe;
	rrr_event_handle event_stats;

	struct rrr_socket_client_collection *write_only_sockets;
	struct rrr_socket_client_collection *read_write_sockets;
	struct rrr_send_loop *send_loop;
};

static void file_destroy(struct file *file) {
	RRR_FREE_IF_NOT_NULL(file->orig_path);
	RRR_FREE_IF_NOT_NULL(file->real_path);
	rrr_free(file);
}

static struct file *file_collection_get_by_orig_path (const struct file_collection *files, const char *orig_path) {
	RRR_LL_ITERATE_BEGIN(files, struct file);
		if (strcmp(orig_path, node->orig_path) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static struct file *file_collection_get_by_fd (const struct file_collection *files, int fd) {
	RRR_LL_ITERATE_BEGIN(files, struct file);
		if (node->fd == fd) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static void file_collection_remove (struct file_collection *files, struct file *file) {
	RRR_LL_ITERATE_BEGIN(files, struct file);
		if (node == file) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(files, 0; file_destroy(node));
}

static void file_collection_remove_by_fd (struct file_collection *files, int fd) {
	RRR_LL_ITERATE_BEGIN(files, struct file);
		if (node->fd == fd) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(files, 0; file_destroy(node));
}

static int file_collection_count (const struct file_collection *files) {
	return RRR_LL_COUNT(files);
}

static void file_collection_add_bytes_to_write (struct file_collection *files, int fd, rrr_biglength bytes) {
	struct file *file;
	if ((file = file_collection_get_by_fd(files, fd)) == NULL) {
		return;
	}
	file->bytes_to_write += bytes;
}

static void file_collection_add_bytes_written (struct file_collection *files, int fd, rrr_biglength bytes) {
	struct file *file;
	if ((file = file_collection_get_by_fd(files, fd)) == NULL) {
		return;
	}
	file->bytes_to_write += bytes;
}

static int file_collection_all_bytes_written (struct file_collection *files, int fd) {
	struct file *file;
	if ((file = file_collection_get_by_fd(files, fd)) == NULL) {
		return 0;
	}
	return file->bytes_written == file->bytes_to_write;
}

static int file_new (
		struct file **result,
		struct file_data *data,
		unsigned char type,
		int flags,
		const char *orig_path,
		const char *real_path,
		int fd,
		const struct stat *file_stat
) {
	int ret = 0;

	*result = NULL;

	struct file *file = NULL;

	if ((file = rrr_allocate_zero(sizeof(*file))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((file->orig_path = rrr_strdup(orig_path)) == NULL) {
		RRR_MSG_0("Could not allocate memory for path in %s\n", __func__);
		ret = 1;
		goto out_destroy;
	}

	if ((file->real_path = rrr_strdup(real_path)) == NULL) {
		RRR_MSG_0("Could not allocate memory for path in %s\n", __func__);
		ret = 1;
		goto out_destroy;
	}

	file->data = data;
	file->type = type;
	file->fd = fd;
	file->flags = flags;
	file->file_stat = *file_stat;

	*result = file;

	goto out;
	out_destroy:
		file_destroy(file);
	out:
		return ret;
}

static int file_collection_push (
		struct file_collection *files,
		struct file_data *data,
		unsigned char type,
		int flags,
		const char *orig_path,
		const char *real_path,
		int fd,
		const struct stat *file_stat
) {
	int ret = 0;

	struct file *file = NULL;

	if ((ret = file_new (
			&file,
			data,
			type,
			flags,
			orig_path,
			real_path,
			fd,
			file_stat
	)) != 0) {
		goto out;
	}

	RRR_LL_PUSH(files, file);

	out:
	return ret;
}

static int file_data_init(struct file_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));

	return 0;
}

static void file_data_cleanup(void *arg) {
	struct file_data *data = (struct file_data *) arg;
	rrr_event_collection_clear(&data->events);
	if (data->write_only_sockets != NULL) {
		rrr_socket_client_collection_destroy(data->write_only_sockets);
	}
	if (data->read_write_sockets != NULL) {
		rrr_socket_client_collection_destroy(data->read_write_sockets);
	}
	if (data->send_loop != NULL) {
		rrr_send_loop_destroy(data->send_loop);
	}
	RRR_LL_DESTROY (&data->files, struct file, file_destroy(node));
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
	RRR_FREE_IF_NOT_NULL(data->read_all_method);
	RRR_FREE_IF_NOT_NULL(data->directory);
	RRR_FREE_IF_NOT_NULL(data->prefix);
	RRR_FREE_IF_NOT_NULL(data->topic);
	RRR_FREE_IF_NOT_NULL(data->serial_parity);
	rrr_map_clear(&data->write_values_list);
}

static int file_parse_write_mode_callback (const char *value, void *arg) {
	struct file_data *data = arg;

	if      (strcmp("S_ISUID", value) == 0) { data->write_mode |= S_ISUID; }
	else if (strcmp("S_ISGID", value) == 0) { data->write_mode |= S_ISGID; }
	else if (strcmp("S_ISVTX", value) == 0) { data->write_mode |= S_ISVTX; }
	else if (strcmp("S_IRUSR", value) == 0) { data->write_mode |= S_IRUSR; }
	else if (strcmp("S_IWUSR", value) == 0) { data->write_mode |= S_IWUSR; }
	else if (strcmp("S_IXUSR", value) == 0) { data->write_mode |= S_IXUSR; }
	else if (strcmp("S_IRGRP", value) == 0) { data->write_mode |= S_IRGRP; }
	else if (strcmp("S_IWGRP", value) == 0) { data->write_mode |= S_IWGRP; }
	else if (strcmp("S_IXGRP", value) == 0) { data->write_mode |= S_IXGRP; }
	else if (strcmp("S_IROTH", value) == 0) { data->write_mode |= S_IROTH; }
	else if (strcmp("S_IWOTH", value) == 0) { data->write_mode |= S_IWOTH; }
	else if (strcmp("S_IXOTH", value) == 0) { data->write_mode |= S_IXOTH; }
	else {
		RRR_MSG_0("Unknown mode '%s' in parameter file_write_mode in file instance %s. Ensure that modes are separated by commas.\n",
			value, INSTANCE_D_NAME(data->thread_data));
		return 1;
	}

	return 0;
}

static int file_parse_config (struct file_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;
	int ret_keep = 0;
	int ret_tmp;

	/* Don't goto out in non-critical errors, check all possible errors first. */

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_no_probing", do_no_probing, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_probe_interval_ms", probe_interval, RRR_FILE_DEFAULT_PROBE_INTERVAL_MS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_prefix", prefix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("file_topic", topic, topic_len);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_directory", directory);
	if (data->directory == NULL) {
		RRR_MSG_0("Required parameter 'file_directory' missing for instance %s\n", config->name);
		ret_keep = 1;
	}

	data->read_method = FILE_READ_METHOD_NONE;

	if ((ret_tmp = rrr_instance_config_parse_array_tree_definition_from_config_silent_fail(&data->tree, config, "file_input_types")) != 0) {
		if (ret_tmp != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Failed to parse array definition in file_input_types in instance %s\n", config->name);
			ret_keep = 1;
			goto out;
		}
	}
	else {
		data->read_method = FILE_READ_METHOD_TELEGRAMS;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_strip_array_separators", do_strip_array_separators, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_add_metadata", do_add_metadata, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_read_all_to_message", do_read_all_to_message_, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_read_all_method", read_all_method);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_try_serial_input", do_try_serial_input, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_serial_no_raw", do_serial_no_raw, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_serial_two_stop_bits", do_serial_two_stop_bits, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_try_keyboard_input", do_try_keyboard_input, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_no_keyboard_hijack", do_no_keyboard_hijack, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_unlink_on_close", do_unlink_on_close, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_sync_byte_by_byte", do_sync_byte_by_byte, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_serial_bps", serial_bps, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("file_serial_parity", serial_parity);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_messages_per_file", max_messages_per_file, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_read_step_size", max_read_step_size, RRR_FILE_DEFAULT_READ_STEP_MAX_SIZE);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_max_open", max_open, RRR_FILE_DEFAULT_MAX_OPEN);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_timeout_s", timeout_s, RRR_FILE_DEFAULT_TIMEOUT_S);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_write_timeout_ms", write_timeout_ms, RRR_FILE_DEFAULT_WRITE_TIMEOUT_MS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("file_ttl_seconds", ttl_s, RRR_FILE_DEFAULT_TTL);

	if (data->timeout_s != 0 && data->timeout_s * 1000 < data->write_timeout_ms) {
		RRR_MSG_0("Value for parameter file_timeout_s was less than file_write_timeout_ms in file instance %s, this is an invalid configuration.\n", config->name);
		ret_keep = 1;
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("file_serial_two_stop_bits")) {
		if (!data->do_serial_two_stop_bits) {
			data->do_serial_one_stop_bit = 1;
		}
	}

	if (data->serial_parity != 0) {
		if (rrr_posix_strcasecmp(data->serial_parity, "even") == 0) {
			data->do_serial_parity_even = 1;
		}
		else if (rrr_posix_strcasecmp(data->serial_parity, "odd") == 0) {
			data->do_serial_parity_odd = 1;
		}
		else if (rrr_posix_strcasecmp(data->serial_parity, "none") == 0) {
			data->do_serial_parity_none = 1;
		}
		else {
			RRR_MSG_0("Invalid value '%s' for file_serial_parity in file instance %s, possible values are even, odd, none\n",
					data->serial_parity, config->name);
			ret_keep = 1;
		}
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("file_serial_bps")) {
		// 0 value is allowed for serial_bps, we need a separate value to check
		// if it was set or not
		data->serial_bps_set = 1;

		if (rrr_serial_speed_check(data->serial_bps) != 0) {
			RRR_MSG_0("Invalid value '%llu' for file_serial_bps in file instance %s, possible values are 19200, 38400 etc.\n",
					(unsigned long long) data->serial_bps, config->name);
			ret_keep = 1;
		}
	}

	if (data->do_strip_array_separators && !RRR_INSTANCE_CONFIG_EXISTS("file_input_types")) {
		RRR_MSG_0("file_strip_array_separators was 'yes' while no array definition was set in file_input_type in file instance %s, this is a configuration error.\n",
				config->name);
		ret_keep = 1;
	}

	if (data->do_add_metadata && !RRR_INSTANCE_CONFIG_EXISTS("file_input_types")) {
		RRR_MSG_0("file_add_metadata was 'yes' while no array definition was set in file_input_type in file instance %s, this is a configuration error.\n",
				config->name);
		ret_keep = 1;
	}

	if (data->do_read_all_to_message_) {
		data->read_method = FILE_READ_METHOD_ALL_SIMPLE;
	}

	if (RRR_INSTANCE_CONFIG_EXISTS("file_read_all_method")) {
		if (!data->do_read_all_to_message_) {
			RRR_MSG_0("Parameter file_read_all_method was set while file_read_all_to_message was not 'yes' in file instance %s, this is a configuration error.\n",
					config->name);
			ret_keep = 1;
		}

		if (rrr_posix_strcasecmp(data->read_all_method, "simple") == 0) {
			data->read_method = FILE_READ_METHOD_ALL_SIMPLE;
		}
		else if (rrr_posix_strcasecmp(data->read_all_method, "structured") == 0) {
			data->read_method = FILE_READ_METHOD_ALL_STRUCTURED;
		}
		else if (rrr_posix_strcasecmp(data->read_all_method, "file") == 0) {
			data->read_method = FILE_READ_METHOD_ALL_FILE;
		}
		else {
			RRR_MSG_0("Unknown value '%s' for file_read_all_method in file instance %s, valid options are 'simple', 'structured' and 'file'.\n",
					data->read_all_method, config->name);
			ret_keep = 1;
		}
	}

	if (data->max_open > RRR_FILE_MAX_MAX_OPEN) {
		RRR_MSG_0("Parameter file_max_open out of range for file instance %s (%" PRIrrrbl ">%i).\n",
				config->name, data->max_open, RRR_FILE_MAX_MAX_OPEN);
		ret_keep = 1;
	}

	if (	RRR_INSTANCE_CONFIG_EXISTS("file_input_types") &&
			data->do_read_all_to_message_ != 0
	) {
		RRR_MSG_0("Both file_input_types and file_read_all_to_message was set in file instance %s, this is a configuration error.\n", config->name);
		ret_keep = 1;
	}

	if (data->do_read_all_to_message_ && data->max_messages_per_file != 0) {
		RRR_MSG_0("Both file_do_read_all_to_message and file_max_messages_per_file was set in file instance %s, this is a configuration error.\n", config->name);
		ret_keep = 1;
	}

	if (data->max_read_step_size == 0) {
		RRR_MSG_0("file_max_read_step_size was zero in file instance %s, this is a configuration error.\n", config->name);
		ret_keep = 1;
	}

	if (	RRR_INSTANCE_CONFIG_EXISTS("file_max_read_step_size") &&
			data->do_read_all_to_message_ != 0
	) {
		RRR_MSG_0("Both file_max_read_step_size and file_read_all_to_message was set in file instance %s, this is a configuration error.\n", config->name);
		ret_keep = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_write_allow_directory_override", do_write_allow_directory_override, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_write_append", do_write_append, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("file_write_multicast", do_write_multicast, 0);

	if (RRR_INSTANCE_CONFIG_EXISTS("file_write_mode")) {
		if (rrr_instance_config_traverse_split_commas_silent_fail (
				config,
				"file_write_mode",
				file_parse_write_mode_callback,
				data
		) != 0) {
			RRR_MSG_0("Failed to parse configuration parameter file_write_mode in file instance %s\n", config->name);
			ret_keep = 1;
		}
	}

	if (rrr_instance_config_parse_optional_write_method (
			&data->write_values_list,
			&data->write_method,
			config,
			NULL,
			"file_write_array_values"
	) == 0) {
		if (data->write_method == RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE) {
			if (RRR_INSTANCE_CONFIG_EXISTS("senders")) {
				if (rrr_map_parse_pair("file_data", &data->write_values_list, NULL) != 0) {
					RRR_MSG_0("Failed to add default arrray value in %s\n", __func__);
					ret_keep = 1;
					goto out;
				}
				data->write_method = RRR_INSTANCE_CONFIG_WRITE_METHOD_ARRAY_VALUES;
			}
			else if (data->do_no_probing) {
				RRR_MSG_0("Parameter file_no_probing was set to yes while also no write method was specified, hence no reading nor writing is possible in file instance %s. This is an invalid configuration.\n", config->name);
				ret_keep = 1;
				goto out;
			}
		}
		else if (!RRR_INSTANCE_CONFIG_EXISTS("senders")) {
			RRR_MSG_0("A write method was set in the configuration for file instance %s, but no senders were set. This is an invalid configuration.\n", config->name);
			ret_keep = 1;
			goto out;
		}
	}
	else {
		ret_keep = 1;
	}

	if ( data->read_method == FILE_READ_METHOD_NONE &&
	     data->write_method == RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE
	) {
		RRR_MSG_0("No read nor write action defined in configuration for file instance %s, this is a configuration error.\n", config->name);
		ret_keep = 1;
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret | ret_keep;
}

static int file_set_special_behaviour (
		int *flags,
		struct file_data *data,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		int fd
) {
	int ret = 0;

	if (type != DT_CHR) {
		goto out;
	}

	if (data->do_try_keyboard_input) {
		if (rrr_input_device_grab(fd, 1) == 0) {
			if (data->do_no_keyboard_hijack && (ret = rrr_input_device_grab(fd, 0)) != 0) {
				RRR_MSG_0("Could not ungrab keyboard device '%s'=>'%s' in file instance %s\n",
						 orig_path, resolved_path, INSTANCE_D_NAME(data->thread_data));
				goto out;
			}
			(*flags) |= RRR_FILE_F_IS_KEYBOARD;
			RRR_DBG_3("file instance %s character device '%s'=>'%s' recognized as keyboard event device\n",
					INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
		}
	}

	if (data->do_try_serial_input) {
		int is_serial = 0;
		rrr_serial_check(&is_serial, fd); // Ignore errors
		if (is_serial) {
			(*flags) |= RRR_FILE_F_IS_SERIAL;
			RRR_DBG_3("file instance %s character device '%s'=>'%s' recognized as serial device\n",
					INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);

			if (!data->do_serial_no_raw) {
				RRR_DBG_3("file instance %s setting raw mode for serial device '%s'=>'%s'\n",
						INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
				if ((ret = rrr_serial_raw_set(fd)) != 0) {
					RRR_MSG_0("File instance %s failed to set raw mode of serial device '%s'=>%s\n",
							INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
					goto out;
				}
			}

			if (data->serial_bps_set) {
				RRR_DBG_3("file instance %s setting speed %llu for serial device '%s'=>'%s'\n",
						INSTANCE_D_NAME(data->thread_data), (unsigned long long) data->serial_bps, orig_path, resolved_path);
				if ((ret = rrr_serial_speed_set(fd, data->serial_bps)) != 0) {
					RRR_MSG_0("File instance %s failed to set speed of serial device '%s'=>%s\n",
							INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
					goto out;
				}
			}

			if (data->do_serial_parity_even || data->do_serial_parity_odd) {
				RRR_DBG_3("file instance %s setting %s parity for serial device '%s'=>'%s'\n",
						INSTANCE_D_NAME(data->thread_data), (data->do_serial_parity_even ? "even" : "odd"), orig_path, resolved_path);
				if ((ret = rrr_serial_parity_set(fd, data->do_serial_parity_odd)) != 0) {
					RRR_MSG_0("File instance %s failed to set parity of serial device '%s'=>%s\n",
							INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
					goto out;
				}
			}
			else if (data->do_serial_parity_none) {
				if ((ret = rrr_serial_parity_unset(fd)) != 0) {
					RRR_MSG_0("File instance %s failed to unset parity of serial device '%s'=>%s\n",
							INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
					goto out;
				}
			}

			if (data->do_serial_one_stop_bit || data->do_serial_two_stop_bits) {
				if ((ret = rrr_serial_stop_bit_set(fd, data->do_serial_two_stop_bits)) != 0) {
					RRR_MSG_0("File instance %s failed to set stop bits on serial device '%s'=>%s\n",
							INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
					goto out;
				}
			}
		}
	}

	out:
	return ret;
}

static int file_open_or_connect (
		int *result_fd,
		struct file_data *data,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type
) {
	int ret = 0;

	*result_fd = 0;

	if (type == DT_SOCK) {
		RRR_DBG_3("file instance %s connecting to socket '%s'=>'%s'\n", INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);

		if (rrr_socket_unix_connect(result_fd, INSTANCE_D_NAME(data->thread_data), orig_path, 1) != 0) {
			RRR_MSG_0("Warning: Could not connect to socket '%s' in file instance %s\n", orig_path, INSTANCE_D_NAME(data->thread_data));
			ret = RRR_FILE_SOFT_ERROR;
			goto out;
		}
	}
	else {
		int flags = (data->write_method != RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE ? O_RDWR : O_RDONLY);

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
			// Unknown type
			ret = RRR_FILE_SOFT_ERROR;
			goto out;
		}

		if ((*result_fd = rrr_socket_open(orig_path, flags, 0, INSTANCE_D_NAME(data->thread_data), 0)) <= 0) {
			RRR_DBG_3("file instance %s failed to open '%s'=>'%s' for %s: %s\n",
				INSTANCE_D_NAME(data->thread_data),
				orig_path,
				resolved_path,
				flags & O_RDWR ? "reading/writing" : "reading",
				rrr_strerror(errno)
			);
			ret = RRR_FILE_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int file_open_as_needed (
		int *result_fd,
		struct file_data *data,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type
) {
	int ret = 0;

	*result_fd = 0;

	struct rrr_socket_client_collection *target_collection = data->read_write_sockets;
	struct file *file;
	int fd = 0;
	int flags = 0;

	if ((file = file_collection_get_by_orig_path(&data->files, orig_path)) != NULL) {
		fd = file->fd;
		goto set_result;
	}

	if (data->max_open > 0 && file_collection_count(&data->files) >= (int) data->max_open) {
		ret = RRR_FILE_BUSY;
		goto out;
	}

	if ((ret = file_open_or_connect (&fd, data, orig_path, resolved_path, type)) != 0) {
		goto out;
	}

	assert(fd > 0);

	if ((ret = file_set_special_behaviour (&flags, data, orig_path, resolved_path, type, fd)) != 0) {
		goto out_close;
	}

	if (data->read_method == FILE_READ_METHOD_NONE) {
		RRR_DBG_3("file instance %s file '%s'=>'%s' opening write-only as no read method is set.\n",
				INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
		target_collection = data->write_only_sockets;
	}
	else {
		if (RRR_FILE_DT_IS_INFINITE(type) && data->read_method != FILE_READ_METHOD_TELEGRAMS) {
			if (data->write_method == RRR_INSTANCE_CONFIG_WRITE_METHOD_NONE) {
				RRR_DBG_3("file instance %s file '%s'=>'%s' is not a file with finite size and no input types are set. Also, no writing is configured. Ignoring file.\n",
						INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
				goto out_close;
			}
			else {
				RRR_DBG_3("file instance %s file '%s'=>'%s' is not a file with finite size and no input types are set. Cannot read whole file, making the file write-only.\n",
						INSTANCE_D_NAME(data->thread_data), orig_path, resolved_path);
				target_collection = data->write_only_sockets;
			}
		}
	}

	struct stat file_stat = {0};
	if (fstat(fd, &file_stat) != 0) {
		RRR_MSG_0("Failed to stat file '%s'=>'%s': %s\n",
				orig_path, resolved_path, rrr_strerror(errno));
		ret = 1;
		goto out_close;
	}

	if ((ret = file_collection_push(&data->files, data, type, flags, orig_path, resolved_path, fd, &file_stat)) != 0) {
		goto out_close;
	}

	if ((ret = rrr_socket_client_collection_connected_fd_push (
			target_collection,
			fd,
			type == DT_SOCK
				? RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
				: RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_FILE

	)) != 0) {
		RRR_MSG_0("Failed to add fd to client collection in file instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_remove_from_file_collection;
	}

	set_result:
	*result_fd = fd;
	fd = 0;

	goto out;
	//out_remove_from_client_collection:
	out_remove_from_file_collection:
		file_collection_remove_by_fd(&data->files, fd);
	out_close:
		rrr_socket_close_no_unlink(fd);
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

	int fd;
	return ~(RRR_FILE_SOFT_ERROR) & file_open_as_needed(&fd, data, orig_path, resolved_path, type);
}

static int file_probe (struct file_data *data, const char *directory, const char *prefix) {
	return rrr_readdir_foreach_prefix (
			directory,
			prefix, // NULL allowed
			file_probe_callback,
			data
	);
}

struct file_probe_excact_callback_data {
	struct file_data *data;
	const char *expected_orig_path;
	int fd;
	unsigned char type;
};

static int file_probe_excact_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct file_probe_excact_callback_data *callback_data = private_data;
	struct file_data *data = callback_data->data;

	(void)(entry);

	int ret = 0;

	if (strcmp(callback_data->expected_orig_path, orig_path) != 0) {
		return 0;
	}

	int fd;
	if ((ret = file_open_as_needed(&fd, data, orig_path, resolved_path, type)) != 0) {
		goto out;
	}

	assert(fd > 0);
	callback_data->fd = fd;
	callback_data->type = type;

	// File found, no need to probe for more
	ret = RRR_FILE_STOP;

	out:
	return ret;
}

static int file_probe_excact_or_create (
		int *result_fd,
		unsigned char *result_type,
		struct file_data *data,
		const char *directory,
		const char *name
) {
	int ret = 0;

	*result_fd = 0;
	*result_type = 0;

	char *orig_path = NULL;
	int fd = -1;
	unsigned char type = 0;

	if (!(rrr_asprintf (&orig_path, "%s/%s", directory, name) > 0)) {
		RRR_MSG_0("Failed to make path in %s\n", __func__);
		ret = 1;
		goto out;

	}

	if ((fd = open(orig_path, O_CREAT|O_EXCL, 0660)) == -1) {
		if (errno != EEXIST) {
			RRR_MSG_0("Failed to create file %s in file instance %s: %s\n",
				orig_path, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
			ret = RRR_FILE_SOFT_ERROR;
			goto out;
		}
	}
	else {
		RRR_DBG_3("file instance %s created file '%s'\n",
			INSTANCE_D_NAME(data->thread_data), orig_path);
	}

	if (data->write_mode != 0) {
		RRR_DBG_3("file instance %s set mode on file '%s' to %i\n",
			INSTANCE_D_NAME(data->thread_data), orig_path, data->write_mode);

		if (chmod(orig_path, data->write_mode) == -1) {
			RRR_MSG_0("Failed to set mode on file '%s' in file instance %s: %s\n",
				orig_path, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
			ret = RRR_FILE_SOFT_ERROR;
			goto out;
		}
	}

	if (fd != -1) {
		close(fd);
	}

	struct file_probe_excact_callback_data callback_data = {
		data,
		orig_path,
		0,
		0
	};

	if ((ret = rrr_readdir_foreach_prefix (
			directory,
			name,
			file_probe_excact_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_FILE_STOP) {
			ret = 0;
		}
		else {
			goto out;
		}
	}

	fd = callback_data.fd;
	type = callback_data.type;

	if (!(fd > 0)) {
		RRR_MSG_0("Unable to open or create file %s in file instance %s\n",
				orig_path, INSTANCE_D_NAME(data->thread_data));
		ret = RRR_FILE_SOFT_ERROR;
		goto out;
	}

	*result_fd = fd;
	*result_type = type;

	out:
	RRR_FREE_IF_NOT_NULL(orig_path);
	return ret;
}

static int file_add_structured_metadata_to_array (
		struct rrr_array *array,
		const struct file *file
) {
	int ret = 0;

	if ((ret = rrr_array_push_value_str_with_tag (
			array, "path_original", file->orig_path
	)) != 0) {
		RRR_MSG_0("Failed to push file original path to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_str_with_tag (
			array, "path_resolved", file->real_path
	)) != 0) {
		RRR_MSG_0("Failed to push file resolved path to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			array, "atime", file->file_stat.st_atim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file atime to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			array, "mtime", file->file_stat.st_mtim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file mtime to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag (
			array, "ctime", file->file_stat.st_ctim.tv_sec
	)) != 0) {
		RRR_MSG_0("Failed to push file ctime to array in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
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

	if ((ret = rrr_array_new_message_from_array (
			&new_message,
			callback_data->array_final,
			time,
			callback_data->data->topic,
			callback_data->data->topic_len
	)) != 0) {
		RRR_MSG_0("Could not create message in %s\n", __func__);
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

static void file_read_set_flags_callback (RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS) {
	struct file *file = private_data;
	struct file_data *data = arg;

	(void)(data);

	*socket_read_flags = RRR_SOCKET_READ_METHOD_READ_FILE | RRR_SOCKET_READ_NO_GETSOCKOPTS;

	if (RRR_FILE_DT_IS_INFINITE(file->type)) {
		// For devices without any end like character devices
		*socket_read_flags |= RRR_SOCKET_READ_CHECK_POLLHUP;
		if (data->read_method == FILE_READ_METHOD_TELEGRAMS && !RRR_FILE_DT_IS_SENDER_RELIANT(file->type)) {
			// Continue reading in case of input data errors, don't close socket. If
			// socket is sender reliant, like fifo socket, we must close the socket
			// as soft error could mean that sender is no longer connected.
			*do_soft_error_propagates = 0;
		}
	}
	else {
		// For devices with finite size or files
		*socket_read_flags |= RRR_SOCKET_READ_CHECK_EOF;

		// Close a file with input data errors
		*do_soft_error_propagates = 1;
	}

	if (file->flags & RRR_FILE_F_IS_KEYBOARD) {
		*socket_read_flags |= RRR_SOCKET_READ_INPUT_DEVICE;
	}
}

static int file_read_array_callback (RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS) {
	struct file *file = private_data;
	struct file_data *data = arg;

	(void)(addr);
	(void)(addr_len);

	int ret = 0;

	struct file_read_array_write_callback_data write_callback_data = {
			data,
			array_final
	};

	if (data->do_strip_array_separators) {
		rrr_array_strip_type(array_final, &rrr_type_definition_sep);
	}

	if (data->do_add_metadata && (ret = file_add_structured_metadata_to_array (array_final, file)) != 0) {
		RRR_MSG_0("Could not add structured fields to array in %s\n", __func__);
		return ret;
	}

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			file_read_array_write_callback,
			&write_callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Could not create new array message in file instance %s, return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		return ret;
	}

	file->total_messages++;

	if (data->max_messages_per_file != 0 && file->total_messages >= data->max_messages_per_file) {
		RRR_DBG_3("file instance %s closing file '%s'=>'%s' after max messages received (%" PRIu64 "/%" PRIrrrbl ")\n",
				INSTANCE_D_NAME(data->thread_data),
				file->orig_path,
				file->real_path,
				file->total_messages,
				data->max_messages_per_file
		);
		ret = RRR_READ_EOF;
	}

	data->bytes_read_accumulator += read_session->target_size;

	return ret;
}

static int file_verify_wpos (
		struct file_data *file_data,
		const struct rrr_read_session *read_session
) {
	if (read_session->rx_buf_wpos > RRR_LENGTH_MAX) {
		RRR_MSG_0("Too many bytes read in file instance %s (%" PRIrrrbl ">%llu)",
			INSTANCE_D_NAME(file_data->thread_data),
			read_session->rx_buf_wpos,
			(unsigned long long) RRR_LENGTH_MAX
		);
		return 1;
	}
	return 0;
}

#define VERIFY_WPOS() do{ if((ret = file_verify_wpos(file_data, read_session)) != 0) goto out; } while(0)

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

	VERIFY_WPOS();

	uint64_t time = rrr_time_get_64();

	struct rrr_msg_msg *reading = NULL;
	if ((ret = rrr_msg_msg_new_empty (
			&reading,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			time,
			file_data->topic_len,
			rrr_length_from_biglength_bug_const(read_session->rx_buf_wpos)
	)) != 0) {
		RRR_MSG_0("Could not create message in %s\n", __func__);
		goto out;
	}

	if (file_data->topic != NULL && *(file_data->topic) != '\0') {
		memcpy(MSG_TOPIC_PTR(reading), file_data->topic, file_data->topic_len);
	}

	rrr_memcpy(MSG_DATA_PTR(reading), read_session->rx_buf_ptr, read_session->rx_buf_wpos);

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	RRR_DBG_2("file instance %s created message with raw file_data of size %" PRIrrrbl " and timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(file_data->thread_data), read_session->rx_buf_wpos, time);

	out:
	return ret;
}

static int file_read_all_to_message_write_callback_array_final (
		struct file_data *file_data,
		struct rrr_msg_holder *entry,
		const struct rrr_array *array,
		const struct rrr_read_session *read_session
) {
	int ret = 0;

	uint64_t time = rrr_time_get_64();

	struct rrr_msg_msg *reading = NULL;
	if ((ret = rrr_array_new_message_from_array (
			&reading,
			array,
			time,
			file_data->topic,
			file_data->topic_len
	)) != 0) {
		RRR_MSG_0("Could not create array message in %s\n", __func__);
		goto out;
	}

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	RRR_DBG_2("file instance %s created message with array data of size %" PRIrrrbl " and timestamp %" PRIu64 "\n",
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

	VERIFY_WPOS();

	if ((ret = rrr_array_push_value_blob_with_tag_with_size (
			&array_tmp,
			"data",
			read_session->rx_buf_ptr,
			rrr_length_from_biglength_bug_const(read_session->rx_buf_wpos)
	)) != 0) {
		RRR_MSG_0("Failed to push file data to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag (
			&array_tmp, "size", read_session->rx_buf_wpos
	)) != 0) {
		RRR_MSG_0("Failed to push file size to array in %s\n", __func__);
		goto out;
	}

	if ((ret = file_add_structured_metadata_to_array (&array_tmp, file)) != 0) {
		RRR_MSG_0("Could not add structured fields to array in %s\n", __func__);
		goto out;
	}

	if ((ret = file_read_all_to_message_write_callback_array_final (
			file_data,
			entry,
			&array_tmp,
			read_session
	)) != 0) {
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int file_read_all_to_message_write_callback_file_basename_callback (
		const char *path,
		const char *dir,
		const char *name,
		void *arg
) {
	struct rrr_array *array = arg;

	(void)(path);

	int ret = 0;

	if ((ret = rrr_array_push_value_str_with_tag (
			array, "file_directory", dir
	)) != 0) {
		RRR_MSG_0("Failed to push file dir to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_str_with_tag (
			array, "file_name", name
	)) != 0) {
		RRR_MSG_0("Failed to push file dir to array in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int file_read_all_to_message_write_callback_file (
		struct rrr_msg_holder *entry,
		struct file_data *file_data,
		const struct rrr_read_session *read_session,
		struct file *file
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	VERIFY_WPOS();

	if ((ret = rrr_array_push_value_str_with_tag (
			&array_tmp, "file_path_resolved", file->real_path
	)) != 0) {
		RRR_MSG_0("Failed to push file resolved path to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_util_fs_basename (
			file->orig_path,
			file_read_all_to_message_write_callback_file_basename_callback,
			&array_tmp
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_push_value_blob_with_tag_with_size (
			&array_tmp,
			"file_data",
			read_session->rx_buf_ptr,
			rrr_length_from_biglength_bug_const(read_session->rx_buf_wpos)
	)) != 0) {
		RRR_MSG_0("Failed to push file data to array in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag (
			&array_tmp,
			"file_size",
			read_session->rx_buf_wpos
	)) != 0) {
		RRR_MSG_0("Failed to push file size to array in %s\n", __func__);
		goto out;
	}

	if ((ret = file_read_all_to_message_write_callback_array_final (
			file_data,
			entry,
			&array_tmp,
			read_session
	)) != 0) {
		goto out;
	}

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
	else if (callback_data->file_data->read_method == FILE_READ_METHOD_ALL_FILE) {
		if ((ret = file_read_all_to_message_write_callback_file (
				entry,
				callback_data->file_data,
				callback_data->read_session,
				callback_data->file
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

static int file_read_all_to_message_complete (
		struct file_data *data,
		struct file *file,
		struct rrr_read_session *read_session
) {
	int ret = 0;

	struct file_read_all_to_message_write_callback_data write_callback_data = {
			data,
			file,
			read_session
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			file_read_all_to_message_write_callback,
			&write_callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Could not create new message in file instance %s, return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	data->message_count++;

	out:
	return ret;
}

static int file_client_private_data_new(void **target, int fd, void *private_arg) {
	struct file_data *data = private_arg;

	*target = file_collection_get_by_fd (&data->files, fd);
	assert(*target != NULL);

	return 0;
}

static void file_client_private_data_destroy(void *private_data) {
	struct file *file = private_data;
	file_collection_remove(&file->data->files, file);
}

static void file_send_chunk_private_data_new (void **chunk_private_data, void *arg) {
	struct rrr_msg_holder *entry = arg;
	rrr_msg_holder_incref(entry);
	*chunk_private_data = entry;
}

static void file_send_chunk_private_data_destroy (void *arg) {
	struct rrr_msg_holder *entry = arg;
	rrr_msg_holder_decref(entry);
}

static int file_read_raw_get_target_size(RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS) {
    	struct file *file = private_data;
	struct file_data *data = arg;

	(void)(file);
	(void)(addr);
	(void)(addr_len);
	(void)(data);

	read_session->read_complete_method = RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ;

	return RRR_READ_OK;
}

static void file_read_error_callback(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS) {
	struct file_data *data = arg;
	struct file *file = private_data;

	(void)(read_session);
	(void)(addr);
	(void)(addr_len);

	RRR_MSG_0("Failed while reading from file '%s'=>'%s' in file instance %s%s\n",
		file->orig_path,
		file->real_path,
		INSTANCE_D_NAME(data->thread_data),
		(is_hard_err ? " (hard error)" : "")
	);
}

static int file_read_raw_complete(RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS) {
    	struct file *file = private_data;
	struct file_data *data = arg;

	(void)(addr);
	(void)(addr_len);
	(void)(data);

	data->bytes_read_accumulator += read_session->target_size;

	return file_read_all_to_message_complete (file->data, file, read_session);
}

static void file_chunk_send_notify_callback (RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS) {
	struct file_data *file_data = callback_arg;
	struct rrr_msg_holder *entry = chunk_private_data;

	(void)(data);
	(void)(data_pos);

	assert(data_pos == data_size);

	struct file *file = file_collection_get_by_fd (&file_data->files, fd);

	if (file == NULL) {
		RRR_MSG_0("Warning: Send notify on fd %i which was not registered in file instance %s\n",
			fd, INSTANCE_D_NAME(file_data->thread_data));
		return;
	}

	if (!was_sent) {
		// Entry is NULL if multicast is used
		if (entry != NULL) {
			RRR_DBG_3("file instance %s send error, re-queing entry for fd %i orig path '%s'.\n",
					INSTANCE_D_NAME(file_data->thread_data), fd, file->orig_path);
			rrr_msg_holder_lock(entry);
			rrr_send_loop_unshift(file_data->send_loop, entry);
			rrr_msg_holder_unlock(entry);
		}
		else {
			RRR_DBG_3("file instance %s send error, but no entry is available for re-queue for fd %i orig path '%s'. Data is lost.\n",
					INSTANCE_D_NAME(file_data->thread_data), fd, file->orig_path);
		}
	}
	else {
		file_collection_add_bytes_written(&file_data->files, fd, data_size);
		if (file_collection_all_bytes_written (&file_data->files, fd)) {
			RRR_DBG_3("file instance %s all queued bytes written on fd %i orig path '%s'\n",
					INSTANCE_D_NAME(file_data->thread_data), fd, file->orig_path);
		}
	}
}

struct file_fd_close_notify_callback_data {
	struct file_data *data;
	struct rrr_socket_client_collection *collection;
};

static void file_fd_close_notify_callback (RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS) {
	struct file_fd_close_notify_callback_data *callback_data = arg;
	struct file_data *file_data = callback_data->data;
	struct rrr_socket_client_collection *collection = callback_data->collection;

	(void)(addr);
	(void)(addr_len);
	(void)(addr_string);
	(void)(create_type);
	(void)(was_finalized);

	struct file *file = file_collection_get_by_fd (&file_data->files, fd);

	if (file == NULL) {
		RRR_MSG_0("Warning: Close notify on fd %i which was not registered in file instance %s\n",
			fd, INSTANCE_D_NAME(file_data->thread_data));
		return;
	}

	RRR_DBG_3("file instance %s close notify on fd %i orig path '%s'\n",
			INSTANCE_D_NAME(file_data->thread_data), fd, file->orig_path);

	// Remove files not exclusively being written to if unlink on close is active
	if (file_data->do_unlink_on_close && collection != file_data->write_only_sockets) {
		RRR_DBG_3("file instance %s unlinking file per configuration fd %i path '%s'\n",
				INSTANCE_D_NAME(file_data->thread_data), fd, file->orig_path);
		rrr_socket_unlink(fd);
	}
}

static int file_send_to_fd (
		struct file_data *data,
		struct rrr_msg_holder *entry,
		int fd,
		const char *directory,
		const char *name,
		unsigned char type,
		char **write_data,
		rrr_biglength write_data_size
) {
	int ret = 0;

	rrr_length send_chunk_count = 0;

	switch (type) {
		case DT_REG:
			if (data->do_write_append) {
				RRR_DBG_3("file instance %s seeking to end of file '%s/%s'\n",
						INSTANCE_D_NAME(data->thread_data), directory, name);

				if (lseek(fd, 0, SEEK_END) == -1) {
					RRR_MSG_0("Failed to seek to beginning of file '%s/%s' in file instance %s: %s\n",
							directory, name, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
					ret = RRR_FILE_SOFT_ERROR;
					goto out_close;
				}
			}
			else {
				RRR_DBG_3("file instance %s truncating file '%s/%s'\n",
						INSTANCE_D_NAME(data->thread_data), directory, name);

				if (ftruncate(fd, 0) == -1 && errno != EINVAL) {
					RRR_MSG_0("Failed to truncate file '%s/%s' in file instance %s: %s\n",
							directory, name, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
					ret = RRR_FILE_SOFT_ERROR;
					goto out_close;
				}

				if (lseek(fd, 0, SEEK_SET) == -1 && errno != EINVAL) {
					RRR_MSG_0("Failed to seek to beginning of file '%s/%s' in file instance %s: %s\n",
							directory, name, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
					ret = RRR_FILE_SOFT_ERROR;
					goto out_close;
				}
			}

			// Prevent reading from the file by moving to write only collection. FD might already
			// be in correct client socket collection, which is OK.
			if ((ret = rrr_socket_client_collection_migrate_by_fd (data->write_only_sockets, data->read_write_sockets, fd)) != 0) {
				if (ret != RRR_SOCKET_SOFT_ERROR) {
					RRR_MSG_0("Failed to migrate socket in %s\n", __func__);
					goto out_close;
				}
				ret = 0;
				RRR_UNUSED(ret);
			}

			if ((ret = rrr_socket_client_collection_send_push_with_private_data (
					&send_chunk_count,
					data->write_only_sockets,
					fd,
					(void **) write_data,
					write_data_size,
					file_send_chunk_private_data_new,
					entry,
					file_send_chunk_private_data_destroy
			)) != 0) {
				RRR_MSG_0("Error %i while pushing data to client collection in %s\n", ret, __func__);
				goto out_close;
			}

			rrr_socket_client_collection_close_when_send_complete_by_fd (data->write_only_sockets, fd);

			break;
		case DT_FIFO:
		case DT_CHR:
		case DT_SOCK:
			RRR_DBG_3("file instance %s file '%s/%s' is not regular file, not seeking or truncating.\n",
					INSTANCE_D_NAME(data->thread_data), directory, name);

			if ((ret = rrr_socket_client_collection_send_push_with_private_data (
					&send_chunk_count,
					data->read_write_sockets,
					fd,
					(void **) write_data,
					write_data_size,
					file_send_chunk_private_data_new,
					entry,
					file_send_chunk_private_data_destroy
			)) != 0) {
				RRR_MSG_0("Error %i while pushing data to client collection in %s\n", ret, __func__);
				goto out_close;
			}

			break;
		default:
			RRR_MSG_0("Cannot write to file %s/%s of type %i in file instance %s, possible readdir problem or unknown type. Dropping message.\n",
					directory, name, type, INSTANCE_D_NAME(data->thread_data));
			goto out_close;
	};

	file_collection_add_bytes_to_write(&data->files, fd, write_data_size);

	goto out;
	out_close:
		rrr_socket_client_collection_close_by_fd(data->write_only_sockets, fd);
		rrr_socket_client_collection_close_by_fd(data->read_write_sockets, fd);

	out:
	return ret;
}

static void file_send_push_array_values_multicast (
		struct file_data *data,
		const char *write_data,
		rrr_biglength write_data_size
) {
	rrr_length send_chunk_count = 0;

	rrr_socket_client_collection_send_push_const_multicast (
			&send_chunk_count,
			data->write_only_sockets,
			write_data,
			write_data_size,
			RRR_FILE_MAX_MAX_OPEN	
	);

	rrr_socket_client_collection_send_push_const_multicast (
			&send_chunk_count,
			data->read_write_sockets,
			write_data,
			write_data_size,
			RRR_FILE_MAX_MAX_OPEN	
	);
}

static int file_send_push_array_values_unicast (
		struct file_data *data,
		struct rrr_msg_holder *entry,
		struct rrr_array *array,
		char **write_data,
		rrr_biglength write_data_size
) {
	int ret = 0;

	int fd = 0;
	unsigned char type = 0;
	char *directory_override = NULL;
	char *name = NULL;
	const char *directory = data->directory;

	const struct rrr_type_value *value_directory = rrr_array_value_get_by_tag_const(array, "file_directory");
	const struct rrr_type_value *value_name = rrr_array_value_get_by_tag_const(array, "file_name");

	if (value_directory != NULL) {
		if (!data->do_write_allow_directory_override) {
			RRR_DBG_3("Ignoring 'file_directory' field in message to file instance %s per configuration\n", INSTANCE_D_NAME(data->thread_data));
		}
		else if ((ret = rrr_type_value_to_str (&directory_override, value_directory)) != 0)  {
			RRR_MSG_0("Failed to get string value of directory value from array message in %s of file instance %ss\n",
					__func__, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		else {
			directory = directory_override;
		}
	}

	if (value_name == NULL) {
		RRR_MSG_0("Field 'file_name' missing in message to file instance %s, dropping it.\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_type_value_to_str (&name, value_name)) != 0)  {
		RRR_MSG_0("Failed to get string value of name value from array message in %s of file instance %ss\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (strlen(name) == 0) {
		RRR_MSG_0("Field 'file_name' was empty in file instance %s. Dropping message.\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (strchr(name, '/') != NULL) {
		RRR_MSG_0("Field 'file_name' contained illegal directory separator character / in file instance %s. Dropping message.\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = file_probe_excact_or_create (
			&fd,
			&type,
			data,
			directory,
			name
	)) != 0) {
		if (ret == RRR_FILE_BUSY) {
			ret = RRR_SEND_LOOP_NOT_READY;
		}
		else if (ret == RRR_FILE_SOFT_ERROR) {
			RRR_MSG_0("Dropping message after soft error in file instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 0;
		}
		goto out;
	}

	assert(fd > 0);

	if ((ret = file_send_to_fd (
			data,
			entry,
			fd,
			directory,
			name,
			type,
			write_data,
			write_data_size
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(directory_override);
	RRR_FREE_IF_NOT_NULL(name);
	return ret;
}

static int file_send_push_array_values (
		struct file_data *data,
		struct rrr_msg_holder *entry,
		const struct rrr_msg_msg *msg
) {
	struct rrr_array array = {0};

	int ret = 0;

	char *write_data = NULL;
	int found_tags = 0;
	rrr_biglength write_data_size = 0;

	if (!MSG_IS_ARRAY(msg)) {
		RRR_MSG_0("Received message in file instance %s was not an array message as expected\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	uint16_t version;
	if ((ret = rrr_array_message_append_to_array (&version, &array, msg)) != 0) {
		RRR_MSG_0("Failed to extract array from message in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_array_selected_tags_export (
			&write_data,
			&write_data_size,
			&found_tags,
			&array,
			&data->write_values_list
	)) != 0) {
		RRR_MSG_0("Failed to export array in %s\n", __func__);
		goto out;
	}

	if (found_tags != RRR_LL_COUNT(&data->write_values_list)) {
		RRR_MAP_ITERATE_BEGIN(&data->write_values_list);
			if (!rrr_array_has_tag(&array, node->tag)) {
				RRR_MSG_0("Data value with tag '%s' missing in message to file instance %s, dropping the message.\n",
						node->tag, INSTANCE_D_NAME(data->thread_data));
			}
		RRR_MAP_ITERATE_END();
		goto out;
	}

	if (data->do_write_multicast) {
		file_send_push_array_values_multicast (
				data,
				write_data,
				write_data_size
		);
	}
	else {
		if ((ret = file_send_push_array_values_unicast (
				data,
				entry,
				&array,
				&write_data,
				write_data_size
		)) != 0) {
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(write_data);
	rrr_array_clear(&array);
	return ret;
}

static int file_send_push_callback (
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct file_data *data = arg;

	int ret = 0;

	const struct rrr_msg_msg *msg = entry->message;

	switch (data->write_method) {
		case RRR_INSTANCE_CONFIG_WRITE_METHOD_ARRAY_VALUES:
			ret = file_send_push_array_values(data, entry, msg);
			break;
		case RRR_INSTANCE_CONFIG_WRITE_METHOD_RRR_MESSAGE:
			RRR_BUG("BUG: Write method was RRR_MESSAGE in %s, configuration must avoid this\n", __func__);
			break;
		default:
			RRR_BUG("BUG: Write method was NONE or unknown in %s, configuration must avoid this\n", __func__);
			break;
	}

	return ret;
}

static int file_send_return_callback (
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct file_data *data = arg;

	(void)(entry);
	(void)(data);

	assert(0);

	return 0;
}

static int file_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct file_data *data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	rrr_send_loop_entry_prepare(data->send_loop, entry);
	rrr_send_loop_push(data->send_loop, entry);

	RRR_DBG_2 ("file instance %s result from buffer timestamp %" PRIu64 " index %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp, entry->send_index);

	rrr_msg_holder_unlock(entry);

	return 0;
}

static int file_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, file_poll_callback);
}

static void file_event_probe (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct file_data *data = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (file_probe(data, data->directory, data->prefix) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static void file_event_stats (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct file_data *data = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	RRR_DBG_1("file instance %s messages per second %" PRIu64 " total %" PRIu64"\n",
			INSTANCE_D_NAME(data->thread_data), data->message_count - data->message_count_prev, data->message_count);

	rrr_stats_instance_update_rate (INSTANCE_D_STATS(data->thread_data), 0, "generated", data->message_count - data->message_count_prev);
	rrr_stats_instance_update_rate (INSTANCE_D_STATS(data->thread_data), 1, "bytes", data->bytes_read_accumulator);

	data->bytes_read_accumulator = 0;
	data->message_count_prev = data->message_count;
}

static int file_periodic(RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct file_data *data = thread_data->private_data;

	(void)(data);

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		return RRR_EVENT_EXIT;
	}
	rrr_thread_watchdog_time_update(thread);

	return RRR_EVENT_OK;
}

static void *thread_entry_file (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct file_data *data = thread_data->private_data = thread_data->private_memory;

	if (file_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in file instance %s\n", INSTANCE_D_NAME(thread_data));
		return NULL;
	}

	RRR_DBG_1 ("File thread data is %p\n", thread_data);

	pthread_cleanup_push(file_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (file_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("File %p instance %s probe interval is %" PRIrrrbl " ms%s in directory '%s' with prefix '%s'\n",
			thread_data,
			INSTANCE_D_NAME(thread_data),
			data->probe_interval,
			(data->do_no_probing ? " (but probing disabled)" : ""),
			(data->directory != NULL ? data->directory : ""),
			(data->prefix != NULL ? data->prefix : "")
	);

	if (rrr_socket_client_collection_new (
			&data->read_write_sockets,
			INSTANCE_D_EVENTS(thread_data),
			INSTANCE_D_NAME(thread_data)
	) != 0) {
		RRR_MSG_0("Failed to create client collection in file instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	if (rrr_socket_client_collection_new (
			&data->write_only_sockets,
			INSTANCE_D_EVENTS(thread_data),
			INSTANCE_D_NAME(thread_data)
	) != 0) {
		RRR_MSG_0("Failed to create client collection in file instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	{
		char tmp[256];
		snprintf(tmp, sizeof(tmp), "file instance %s", INSTANCE_D_NAME(thread_data));
		tmp[sizeof(tmp)-1] = '\0';
		if (rrr_send_loop_new (
				&data->send_loop,
				INSTANCE_D_EVENTS(thread_data),
				tmp,
				1, /* Preserve order */
				data->ttl_s * 1000 * 1000,
				data->write_timeout_ms * 1000,
				data->write_timeout_action,
				file_send_push_callback,
				file_send_return_callback,
				NULL, /* run callback not used */
				data
		) != 0) {
			RRR_MSG_0("Failed to create send loop in file instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_cleanup;
		}
	}

	rrr_socket_client_collection_set_idle_timeout (
			data->read_write_sockets,
			data->timeout_s * 1000 * 1000
	);

	rrr_socket_client_collection_set_idle_timeout (
			data->write_only_sockets,
			data->timeout_s * 1000 * 1000
	);

	// READ/WRITE SOCKETS

	if (data->read_method == FILE_READ_METHOD_TELEGRAMS) {
		rrr_socket_client_collection_event_setup_array_tree (
				data->read_write_sockets,
				file_client_private_data_new,
				file_client_private_data_destroy,
				data,
				0,
				file_read_set_flags_callback,
				data,
				data->tree,
				data->do_sync_byte_by_byte,
				data->max_read_step_size,
				RRR_FILE_MAX_SIZE_MB * 1024 * 1024,
				file_read_array_callback,
				data,
				file_read_error_callback,
				data,
				NULL,
				NULL
		);
	}
	else {
		rrr_socket_client_collection_event_setup_raw (
				data->read_write_sockets,
				file_client_private_data_new,
				file_client_private_data_destroy,
				data,
				data->max_read_step_size,
				0,
				file_read_set_flags_callback,
				data,
				file_read_raw_get_target_size,
				data,
				file_read_error_callback,
				data,
				file_read_raw_complete,
				data
		);
	}

	rrr_socket_client_collection_send_notify_setup (
			data->read_write_sockets,
			file_chunk_send_notify_callback,
			data
	);

	struct file_fd_close_notify_callback_data read_write_close_notify_callback_data = {
		data,
		data->read_write_sockets
	};
	rrr_socket_client_collection_fd_close_notify_setup (
			data->read_write_sockets,
			file_fd_close_notify_callback,
			&read_write_close_notify_callback_data
	);

	// WRITE ONLY SOCKETS

	rrr_socket_client_collection_event_setup_write_only (
			data->write_only_sockets,
			file_client_private_data_new,
			file_client_private_data_destroy,
			data
	);

	rrr_socket_client_collection_send_notify_setup (
			data->write_only_sockets,
			file_chunk_send_notify_callback,
			data
	);

	struct file_fd_close_notify_callback_data write_only_close_notify_callback_data = {
		data,
		data->write_only_sockets
	};
	rrr_socket_client_collection_fd_close_notify_setup (
			data->write_only_sockets,
			file_fd_close_notify_callback,
			&write_only_close_notify_callback_data
	);

	if (!data->do_no_probing) {
		if (rrr_event_collection_push_periodic (
				&data->event_probe,
				&data->events,
				file_event_probe,
				data,
				data->probe_interval * 1000
		) != 0) {
			RRR_MSG_0("Failed to create probe event in file instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_cleanup;
		}

		EVENT_ADD(data->event_probe);
		EVENT_ACTIVATE(data->event_probe); // Probe immediately when starting
	}

	if (rrr_event_collection_push_periodic (
			&data->event_stats,
			&data->events,
			file_event_stats,
			data,
			1 * 1000 * 1000 // 1 second
	) != 0) {
		RRR_MSG_0("Failed to create stats event in file instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	if (RRR_DEBUGLEVEL_1) {
		EVENT_ADD(data->event_stats);
	}

	rrr_event_function_periodic_set_and_dispatch (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000,
			file_periodic
	);

	out_cleanup:
	RRR_DBG_1 ("Thread file instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	return NULL;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_file,
	NULL,
	NULL,
	NULL
};

struct rrr_instance_event_functions event_functions = {
	file_event_broker_data_available
};

static const char *module_name = "file";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_FLEXIBLE;
		data->operations = module_operations;
		data->private_data = NULL;
		data->event_functions = event_functions;
}

void unload(void) {
}


