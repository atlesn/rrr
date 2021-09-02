/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <mysql/mysql.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../lib/log.h"
#include "../lib/event/event.h"
#include "../lib/event/event_collection.h"
#include "../lib/allocator.h"
#include "../lib/poll_helper.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/map.h"
#include "../lib/array.h"
#include "../lib/rrr_mysql.h"
#include "../lib/helpers/string_builder.h"
#include "../lib/message_broker.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/util/linked_list.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"

#define RRR_MYSQL_DEFAULT_SERVER "localhost"
#define RRR_MYSQL_DEFAULT_PORT 5506

#define RRR_MYSQL_INPUT_QUEUE_MAX 75000

//#define RRR_MYSQL_SQL_MAX 4096
//#define RRR_MYSQL_MAX_COLUMN_NAME_LENGTH 32

#define RRR_MYSQL_PASTE(x,y) x ## _ ## y

// TODO : Fix URI support

struct mysql_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_msg_holder_collection input_buffer;

	MYSQL mysql;
	MYSQL_BIND *bind;
	unsigned long *bind_string_lengths;
	size_t bind_max_current;
	int mysql_initialized;
	int mysql_connected;

	struct rrr_event_collection events;
	rrr_event_handle event_process_entries;

	/* These must be freed at thread end if not NULL */
	char *mysql_server;
	char *mysql_user;
	char *mysql_password;
	char *mysql_db;
	char *mysql_table;

	uint16_t mysql_port;

	int drop_unknown_messages;
	int colplan;
	int add_timestamp_col;
	int strip_array_separators;

	struct rrr_map columns;
	struct rrr_map column_tags;
	struct rrr_map special_columns;
	struct rrr_map blob_write_columns;

	/* Used by test module only */
	int generate_tag_messages;
};

static void mysql_bind_cleanup (struct mysql_data *data) {
	RRR_FREE_IF_NOT_NULL(data->bind);
	RRR_FREE_IF_NOT_NULL(data->bind_string_lengths);
	data->bind_max_current = 0;
}

static void data_cleanup(void *arg) {
	struct mysql_data *data = arg;

	rrr_event_collection_clear(&data->events);

	mysql_bind_cleanup(data);

	rrr_map_clear(&data->columns);
	rrr_map_clear(&data->special_columns);
	rrr_map_clear(&data->column_tags);
	rrr_map_clear(&data->blob_write_columns);

	rrr_msg_holder_collection_clear(&data->input_buffer);

	RRR_FREE_IF_NOT_NULL(data->mysql_server);
	RRR_FREE_IF_NOT_NULL(data->mysql_user);
	RRR_FREE_IF_NOT_NULL(data->mysql_password);
	RRR_FREE_IF_NOT_NULL(data->mysql_db);
	RRR_FREE_IF_NOT_NULL(data->mysql_table);
}

static int data_init (
		struct mysql_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));
	data->thread_data = thread_data;
	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));

	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

static int mysql_allocate_and_clear_bind_as_needed (
		struct mysql_data *data,
		size_t elements
) {
	if (data->bind != NULL && data->bind_max_current >= elements) {
		goto out_clear;
	}

	mysql_bind_cleanup(data);

	if ((data->bind = rrr_allocate(sizeof(*(data->bind)) * elements)) == NULL) {
		RRR_MSG_0("Could not allocate mysql bind structure in bind_allocate_if_needed\n");
		return 1;
	}

	if ((data->bind_string_lengths = rrr_allocate(sizeof(*(data->bind_string_lengths)) * elements)) == NULL) {
		RRR_MSG_0("Could not allocate mysql bind string lengths in bind_allocate_if_needed\n");
		return 1;
	}

	data->bind_max_current = elements;

	out_clear:
	memset(data->bind, '\0', sizeof(*(data->bind)) * data->bind_max_current);
	memset(data->bind_string_lengths, '\0', sizeof(*(data->bind_string_lengths)) * data->bind_max_current);
	return 0;
}

struct mysql_column_configurator {
	int (*create_sql)(char **target, size_t *column_count, struct mysql_data *data);
	int (*bind_and_execute)(struct mysql_data *mysql_data, MYSQL_STMT *stmt, size_t column_count, const struct rrr_msg_holder *entry);
};

/* Check order with function pointers */
#define COLUMN_PLAN_VOLTAGE 1
#define COLUMN_PLAN_ARRAY 2
#define COLUMN_PLAN_MAX 2
#define COLUMN_PLAN_NAME_VOLTAGE "voltage"
#define COLUMN_PLAN_NAME_ARRAY "array"

#define IS_COLPLAN_VOLTAGE(mysql_data) \
	(mysql_data->colplan == COLUMN_PLAN_VOLTAGE)
#define IS_COLPLAN_ARRAY(mysql_data) \
	(mysql_data->colplan == COLUMN_PLAN_ARRAY)

#define COLPLAN_OK(mysql_data) \
	(mysql_data->colplan > 0 && mysql_data->colplan <= COLUMN_PLAN_MAX)

#define COLUMN_PLAN_MATCH(str,name) \
	strcmp(str,RRR_MYSQL_PASTE(COLUMN_PLAN_NAME,name)) == 0
#define COLUMN_PLAN_INDEX(name) \
	RRR_MYSQL_PASTE(COLUMN_PLAN,name)

static int mysql_columns_check_blob_write (
		const struct mysql_data *data,
		const char *col_1
) {
	if (rrr_map_get_value(&data->blob_write_columns, col_1) != NULL) {
		return 1;
	}
	return 0;
}

static int mysql_bind_and_execute (
		struct mysql_data *data,
		MYSQL_STMT *stmt
) {
	MYSQL_BIND *bind = data->bind;

	if (mysql_stmt_bind_param(stmt, bind) != 0) {
		RRR_MSG_0 ("mysql: Failed to bind values to statement: Error: %s\n",
				mysql_error(&data->mysql));
		return 1;
	}

	if (mysql_stmt_execute(stmt) != 0) {
		RRR_MSG_0 ("mysql: Failed to execute statement: Error: %s\n",
				mysql_error(&data->mysql));
		return 1;
	}

	return 0;
}

static const char *append_error_string = "Error while appending to mysql query string builder\n";

#define APPEND_AND_CHECK(str) \
	RRR_STRING_BUILDER_APPEND_AND_CHECK(&string_builder,str,append_error_string)

#define RESERVE_AND_CHECK(size) \
	RRR_STRING_BUILDER_RESERVE_AND_CHECK(&string_builder,size,append_error_string)

#define APPEND_UNCHECKED(str) \
	rrr_string_builder_unchecked_append(&string_builder, str)

static int mysql_colplan_array_create_sql (
		char **target,
		size_t *column_count_result,
		struct mysql_data *data
) {
	struct rrr_string_builder string_builder = {0};

	*target = NULL;
	*column_count_result = 0;

	int ret = 0;

	APPEND_AND_CHECK("REPLACE INTO `");
	APPEND_AND_CHECK(data->mysql_table);
	APPEND_AND_CHECK("` (");

	const struct rrr_map *column_source = NULL;

	if (RRR_MAP_COUNT(&data->column_tags) > 0) {
		column_source = &data->column_tags;
	}
	else {
		column_source = &data->columns;
	}

	size_t columns_count = 0;

	RRR_MAP_ITERATE_BEGIN(column_source);
		const char *column_name = (node_value != NULL && *node_value != '\0' ? node_value : node_tag);
		RESERVE_AND_CHECK(strlen(column_name) + 3);
		if (!RRR_MAP_ITERATE_IS_FIRST()) {
			APPEND_UNCHECKED(",");
		}
		APPEND_UNCHECKED("`");
		APPEND_UNCHECKED(column_name);
		APPEND_UNCHECKED("`");
		columns_count++;
	RRR_MAP_ITERATE_END();

	RRR_MAP_ITERATE_BEGIN(&data->special_columns);
		RESERVE_AND_CHECK(strlen(node_tag) + 3);
		APPEND_UNCHECKED(",`");
		APPEND_UNCHECKED(node_tag);
		APPEND_UNCHECKED("`");
		columns_count++;
	RRR_MAP_ITERATE_END();

	if (data->add_timestamp_col != 0) {
		APPEND_AND_CHECK(",`timestamp`");
		columns_count++;
	}

	RESERVE_AND_CHECK(10 + 1 + columns_count * 2);
	APPEND_UNCHECKED(") VALUES (");
	for (size_t i = 0; i < columns_count; i++) {
		if (i == 0) {
			APPEND_UNCHECKED("?");
		}
		else {
			APPEND_UNCHECKED(",?");
		}
	}
	APPEND_UNCHECKED(")");

	*target = rrr_string_builder_buffer_takeover(&string_builder);
	*column_count_result = columns_count;

	out:
	rrr_string_builder_clear(&string_builder);
	return ret;
}

static int mysql_bind_value (
		struct mysql_data *data,
		MYSQL_BIND *bind,
		size_t bind_pos,
		struct rrr_type_value *definition,
		const char *column_name
) {
	if (	// Arrays must be inserted as blobs. They might be shorter than the
		// maximum length, the input definition decides.
		definition->element_count > 1 ||
		RRR_TYPE_IS_BLOB(definition->definition->type) ||
		mysql_columns_check_blob_write(data, column_name)
	) {
		data->bind_string_lengths[bind_pos] = definition->total_stored_length;
		bind[bind_pos].buffer = definition->data;
		bind[bind_pos].length = &data->bind_string_lengths[bind_pos];
		bind[bind_pos].buffer_type = MYSQL_TYPE_STRING;
	}
	else if (RRR_TYPE_IS_64(definition->definition->type)) {
		bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
		bind[bind_pos].buffer = definition->data;
		bind[bind_pos].is_unsigned = RRR_TYPE_FLAG_IS_UNSIGNED(definition->flags);
	}
	else {
		RRR_MSG_0("Unknown type %ul when binding with mysql\n", definition->definition->type);
		return 1;
	}
	return 0;
}

static int mysql_colplan_array_bind_execute (
		struct mysql_data *data,
		MYSQL_STMT *stmt,
		size_t column_count_from_prepare,
		const struct rrr_msg_holder *entry
) {
	int ret = 0;

	struct rrr_array collection = {0};
	pthread_cleanup_push(rrr_array_clear_void, &collection);

	uint16_t array_version = 0;

	if (rrr_array_message_append_to_array(&array_version, &collection, entry->message) != 0) {
		RRR_MSG_0("Could not convert array message to data collection in mysql\n");
		ret = 1;
		goto out_cleanup;
	}

	if (array_version != 7) {
		RRR_BUG("Array version mismatch in MySQL colplan_array_bind_execute (%u vs %i), module must be updated\n",
				collection.version, 7);
	}

	size_t column_count =
		(size_t) RRR_MAP_COUNT(&data->columns) +
		(size_t) RRR_MAP_COUNT(&data->column_tags) +
		(size_t) RRR_MAP_COUNT(&data->special_columns) +
		(data->add_timestamp_col != 0 ? 1 : 0);

	if (column_count != column_count_from_prepare) {
		RRR_BUG("BUG: Column count mismatch, %llu vs %llu in mysql colplan_array_bind_execute\n",
				(long long unsigned) column_count, (long long unsigned) column_count_from_prepare);
	}

	if (mysql_allocate_and_clear_bind_as_needed(data, column_count) != 0) {
		ret = 1;
		goto out_cleanup;
	}

	MYSQL_BIND *bind = data->bind;

	size_t bind_pos = 0;

	if (RRR_MAP_COUNT(&data->column_tags) > 0) {
		RRR_MAP_ITERATE_BEGIN(&data->column_tags);
			struct rrr_type_value *array_value = rrr_array_value_get_by_tag(&collection, node_tag);

			if (array_value == NULL) {
				RRR_MSG_0("Array tag '%s' not found when binding with MySQL\n", node_tag);
				ret = 1;
				goto out_cleanup;
			}

			if (mysql_bind_value(data, bind, bind_pos, array_value, node_value) != 0) {
				ret = 1;
				goto out_cleanup;
			}

			bind_pos++;
		RRR_MAP_ITERATE_END();
	}
	else {
		RRR_MAP_ITERATOR_CREATE(column_iterator, &data->columns);

		RRR_LL_ITERATE_BEGIN(&collection, struct rrr_type_value);
			struct rrr_type_value *definition = node;

			if (data->strip_array_separators != 0 && node->definition->type == RRR_TYPE_SEP) {
				RRR_LL_ITERATE_NEXT();
			}

			struct rrr_map_item *item = RRR_MAP_ITERATOR_NEXT(&column_iterator);
			if (item == NULL) {
				RRR_MSG_0("Warning: Incoming array message contains more array elements than configuration. The rest is discarded.\n");
				RRR_LL_ITERATE_BREAK();
			}

			if (mysql_bind_value (
					data,
					bind,
					bind_pos,
					definition,
					(item->value != NULL && *(item->value) != '\0' ? item->value : item->tag)
			) != 0) {
				ret = 1;
				goto out_cleanup;
			}

			bind_pos++;
		RRR_LL_ITERATE_END();
	}

	RRR_MAP_ITERATE_BEGIN(&data->special_columns);
		data->bind_string_lengths[bind_pos] = strlen(node_value);
		bind[bind_pos].buffer = (char *) node_value;
		bind[bind_pos].length = &data->bind_string_lengths[bind_pos];
		bind[bind_pos].buffer_type = MYSQL_TYPE_STRING;

		bind_pos++;
	RRR_MAP_ITERATE_END();

	unsigned long long int timestamp = rrr_time_get_64();
	if (data->add_timestamp_col) {
		bind[bind_pos].buffer = &timestamp;
		bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
		bind[bind_pos].is_unsigned = 1;

		bind_pos++;
	}

	if (bind_pos != column_count) {
		RRR_BUG("Bind items did not match column count in colplan_array_bind_execute\n");
	}

	ret = mysql_bind_and_execute(data, stmt);

	out_cleanup:
	if (ret != 0) {
		RRR_MSG_0("Could not save array message to mysql database\n");
	}
	pthread_cleanup_pop(1);

	return ret;
}

static int mysql_disconnect(struct mysql_data *data) {
	if (data->mysql_connected == 1) {
		mysql_close(&data->mysql);
		data->mysql_connected = 0;
	}
	return 0;
}

static int mysql_connect(struct mysql_data *data) {
	if (data->mysql_connected != 1) {
		void *ptr = mysql_init(&data->mysql);
		if (ptr == NULL) {
			RRR_MSG_0 ("Could not initialize MySQL\n");
			return 1;
		}

		void *ret = mysql_real_connect (
			&data->mysql,
			data->mysql_server,
			data->mysql_user,
			data->mysql_password,
			data->mysql_db,
			data->mysql_port,
			NULL,
			0
		);

		if (ret == NULL) {
			RRR_MSG_0 ("mysql: Failed to connect to database: Error: %s\n",
					mysql_error(&data->mysql));
			return 1;
		}

		data->mysql_connected = 1;
	}

	return 0;
}

// Check that blob write columns are also defined in mysql_columns or mysql_column_tags
static int mysql_verify_blob_write_colums (
		struct mysql_data *data
) {
	int ret = 0;

	RRR_MAP_ITERATE_BEGIN(&data->blob_write_columns);
		if (rrr_map_get_value(&data->columns, node_tag) == NULL) {
			if (rrr_map_get_value(&data->column_tags, node_tag) == NULL) {
				RRR_MSG_0("Column %s specified in blob write columns but is not defined as a column used to save data\n",
						node_tag);
				ret = 1;
			}
		}
	RRR_MAP_ITERATE_END();

	return ret;
}

/* Check index numbers with defines above */
struct mysql_column_configurator column_configurators[] = {
		{ .create_sql = NULL,                             .bind_and_execute = NULL },
		{ .create_sql = NULL,                             .bind_and_execute = NULL }, // Filler, don't remove
		{ .create_sql = &mysql_colplan_array_create_sql,  .bind_and_execute = &mysql_colplan_array_bind_execute }
};

static int mysql_save (
		struct mysql_data *data,
		const struct rrr_msg_holder *entry,
		MYSQL_STMT *stmt,
		size_t column_count
) {
	if (data->mysql_connected != 1) {
		return 1;
	}

	const struct rrr_msg_msg *message = entry->message;

	int is_unknown = 0;
	int colplan_index = COLUMN_PLAN_VOLTAGE;
	if (MSG_IS_MSG_ARRAY(message)) {
		if (!IS_COLPLAN_ARRAY(data)) {
			RRR_MSG_0("Received an array message in mysql but array column plan is not being used\n");
			is_unknown = 1;
			goto out;
		}
		colplan_index = COLUMN_PLAN_ARRAY;
	}
	else {
		RRR_MSG_0("Unknown message class/type %u/%u received in mysql_save\n", MSG_CLASS(message), MSG_TYPE(message));
		is_unknown = 1;
		goto out;
	}

	out:
	if (is_unknown) {
		return 1;
	}

	return column_configurators[colplan_index].bind_and_execute(data, stmt, column_count, entry);
}

static void mysql_process_entry (
		struct mysql_data *data,
		struct rrr_msg_holder *entry,
		MYSQL_STMT *stmt,
		size_t column_count
) {
	struct rrr_msg_msg *message = entry->message;

	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	RRR_DBG_3 ("mysql instance %s: processing message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(data->thread_data), message->timestamp);

	int mysql_save_res = mysql_save (data, entry, stmt, column_count);

	if (mysql_save_res != 0) {
		if (data->drop_unknown_messages) {
			RRR_MSG_0("mysql instance %s dropping message\n", INSTANCE_D_NAME(data->thread_data));
			// Will be destroyed below
		}
		else {
			// Put back in buffer
			RRR_DBG_3 ("mysql: Putting message with timestamp %" PRIu64 " back into the buffer\n", message->timestamp);
			rrr_msg_holder_incref_while_locked(entry);
			RRR_LL_APPEND(&data->input_buffer, entry);
		}
	}
	else if (data->generate_tag_messages != 0) {
		// Tag message as saved to sender, only done in test module
		RRR_DBG_3 ("mysql: generate tag message for entry with timestamp %" PRIu64 "\n", message->timestamp);
		MSG_SET_TYPE(message, MSG_TYPE_TAG);
		MSG_SET_CLASS(message, MSG_CLASS_ARRAY);

		// The entry is re-used, with 0 data length of message
		message->msg_size = MSG_TOTAL_SIZE(message) - MSG_DATA_LENGTH(message);
		entry->data_length = MSG_TOTAL_SIZE(message);

		if (rrr_message_broker_incref_and_write_entry_unsafe (
				INSTANCE_D_BROKER_ARGS(data->thread_data),
				entry,
				NULL,
				INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
		) != 0) {
			RRR_MSG_0("Warning: Could not write tag message to output buffer in mysql instance %s, message lost\n",
					INSTANCE_D_NAME(data->thread_data));
		}
	}

	rrr_msg_holder_decref_while_locked_and_unlock(entry);
}

static void mysql_close_stmt(void *arg) {
	mysql_stmt_close(arg);
}

static int mysql_process_entries (
		struct mysql_data *data,
		struct rrr_msg_holder_collection *source_buffer
) {
	if (mysql_connect(data) != 0) {
		return 1;
	}

	int ret = 0;

	size_t column_count = 0;
	char *query = NULL;

	MYSQL_STMT *stmt = mysql_stmt_init(&data->mysql);

	pthread_cleanup_push(mysql_close_stmt, stmt);

	if (!COLPLAN_OK(data)) {
		RRR_MSG_0("BUG: Mysql colplan was out of range in process_entries\n");
		exit (EXIT_FAILURE);
	}

	if (column_configurators[data->colplan].create_sql(&query, &column_count, data) != 0) {
		ret = 1;
		goto out;
	}

	if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
		RRR_MSG_0 ("mysql: Failed to prepare statement: Error: %s\n",
				mysql_error(&data->mysql));
		mysql_disconnect(data);
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		if (RRR_LL_COUNT(source_buffer) > 0) {
			RRR_MSG_3("mysql SQL: %s\n", query);
		}
	}

	RRR_LL_ITERATE_BEGIN(source_buffer, struct rrr_msg_holder);
		RRR_LL_VERIFY_NODE(source_buffer);
		rrr_msg_holder_lock(node);
		mysql_process_entry(data, node, stmt, column_count);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(source_buffer);

	out:
	RRR_FREE_IF_NOT_NULL(query);
	pthread_cleanup_pop(1);
	return ret;
}

static void mysql_event_process_entries (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct mysql_data *data = arg;

	struct rrr_msg_holder_collection process_buffer_tmp = {0};

	pthread_cleanup_push(rrr_msg_holder_collection_clear_void, &process_buffer_tmp);

	// Entries which are to be retried are written back to the input buffer
	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&process_buffer_tmp, &data->input_buffer);
	mysql_process_entries(data, &process_buffer_tmp);

	pthread_cleanup_pop(1);

	// Failing entries will be retried when this event runs again due to the
	// timer or when some other entry gets polled and this event gets activated
	if (RRR_LL_COUNT(&data->input_buffer) == 0) {
		EVENT_REMOVE(data->event_process_entries);
	}
}

static int mysql_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct mysql_data *mysql_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_3 ("mysql: Result from buffer: timestamp %" PRIu64 "\n", message->timestamp);

	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&mysql_data->input_buffer, entry);

	rrr_msg_holder_unlock(entry);

	return 0;
}

static int mysql_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mysql_data *mysql_data = thread_data->private_data;

	int ret = rrr_poll_do_poll_delete (amount, thread_data, mysql_poll_callback);

	EVENT_ADD(mysql_data->event_process_entries);
	EVENT_ACTIVATE(mysql_data->event_process_entries);

	return ret;
}
		
static void mysql_pause_check (
		int *do_pause,
		int is_paused,
		void *callback_arg
) {
	struct rrr_instance_runtime_data *thread_data = callback_arg;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;

	if (is_paused) {
		*do_pause = RRR_LL_COUNT(&data->input_buffer) > (RRR_MYSQL_INPUT_QUEUE_MAX * 0.75) ? 1 : 0;
	}
	else {
		*do_pause = RRR_LL_COUNT(&data->input_buffer) > RRR_MYSQL_INPUT_QUEUE_MAX ? 1 : 0;
	}	
}

static void mysql_stop(void *arg) {
	struct mysql_data *data = arg;
	if (data->mysql_initialized == 1) {
		mysql_thread_end();
	}
	mysql_disconnect(data);
}

static int mysql_start(struct mysql_data *data) {
	mysql_thread_init();
	data->mysql_initialized = 1;
	data->mysql_connected = 0;
	return 0;
}

static int mysql_parse_column_plan (
		struct mysql_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	int yesno = 0;

	char *mysql_colplan = rrr_strdup("array");

	// BLOB WRITE COLUMNS
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->blob_write_columns, config, "mysql_blob_write_columns");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing mysql_blob_write_columns of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i blob write columns specified for mysql instance %s\n", RRR_MAP_COUNT(&data->blob_write_columns), config->name);

	// SPECIAL COLUMNS AND THEIR VALUES
	ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->special_columns, config, "mysql_special_columns", "=");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing mysql_special_columns of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i special columns specified for mysql instance %s\n", RRR_MAP_COUNT(&data->special_columns), config->name);

	// STRIP OUT SEPARATORS
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "mysql_strip_array_separators")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not parse mysql_strip_array_separators of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		data->strip_array_separators = yesno;
	}

	// TABLE COLUMNS
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->columns, config, "mysql_columns");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing mysql_columns of instance %s\n", config->name);
		goto out;
	}

	ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->column_tags, config, "mysql_column_tags", "->");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing mysql_column_tags of instance %s\n", config->name);
		goto out;
	}

	if (COLUMN_PLAN_MATCH(mysql_colplan,ARRAY)) {
		data->colplan = COLUMN_PLAN_INDEX(ARRAY);

		if (RRR_MAP_COUNT(&data->columns) != 0 && RRR_MAP_COUNT(&data->column_tags) != 0) {
			RRR_MSG_0("mysql_column_tags and mysql_columns cannot be specified simultaneously in instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		RRR_DBG_1("%i ordinary columns specified for mysql instance %s\n",
				RRR_MAP_COUNT(&data->columns) + RRR_MAP_COUNT(&data->column_tags), config->name);

		if (RRR_MAP_COUNT(&data->columns) + RRR_MAP_COUNT(&data->column_tags) == 0) {
			RRR_MSG_0("No columns specified in mysql_columns or mysql_column_tags; needed when using array column plan for instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		if (mysql_verify_blob_write_colums (data) != 0) {
			RRR_MSG_0("Error in blob write column list for mysql instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		RRR_MSG_0("BUG: Reached end of colplan name tests in mysql for instance %s\n", config->name);
		exit(EXIT_FAILURE);
	}

	// Reset any NOT_FOUND
	ret = 0;

	out:
	RRR_FREE_IF_NOT_NULL(mysql_colplan);
	return ret;
}

static int mysql_parse_port (
		struct mysql_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	data->mysql_port = RRR_MYSQL_DEFAULT_PORT;

	if ((ret = rrr_instance_config_read_port_number (&data->mysql_port, config, "mysql_port")) != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_0("Could not parse mysql_port for instance %s\n", config->name);
			ret = 1;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
	}

	return ret;
}

static int parse_config (
		struct mysql_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	// These are free()d on thread exit, not here
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_server,   config, "mysql_server");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_user,     config, "mysql_user");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_password,	config, "mysql_password");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_db,       config, "mysql_db");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_table,    config, "mysql_table");

	if (data->mysql_user == NULL || data->mysql_password == NULL) {
		RRR_MSG_0 ("mysql_user or mysql_password not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_table == NULL) {
		RRR_MSG_0 ("mysql_table not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_server == NULL) {
		RRR_MSG_0 ("mysql_server not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_db == NULL) {
		RRR_MSG_0 ("mysql_db not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	// GENERATE TAG MESSAGES (UNDOCUMENTED, FOR TESTING)
	int yesno = 0;
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_generate_tag_messages") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_0 ("mysql: Could not understand argument mysql_generate_tag_messages of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->generate_tag_messages = (yesno == 0 || yesno == 1 ? yesno : 0);

	// DROP UNKNOWN MESSAGES
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_drop_unknown_messages") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_0 ("mysql: Could not understand argument mysql_drop_unknown_messages of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->drop_unknown_messages = (yesno == 0 || yesno == 1 ? yesno : 0);

	// ADD TIMESTAMP COL
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_add_timestamp_col") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_0 ("mysql: Could not understand argument mysql_add_timestamp_col of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->add_timestamp_col = (yesno == 0 || yesno == 1 ? yesno : 0);

	// MYSQL PORT
	if (mysql_parse_port(data, config) != 0) {
		RRR_MSG_0("Error while parsing mysql port for instance %s\n", config->name);
		ret = 1;
	}

	// COLUMN PLAN AND COLUMN LISTS
	if (mysql_parse_column_plan(data, config) != 0) {
		RRR_MSG_0("Error in mysql column plan for instance %s\n", config->name);
		ret = 1;
	}

	return ret;
}

static void *thread_entry_mysql (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in mysql instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("mysql thread data is %p, size of private data: %llu\n", thread_data, (long long unsigned) sizeof(*data));

	pthread_cleanup_push(mysql_stop, data);
	pthread_cleanup_push(data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (mysql_start(data) != 0) {
		goto out_message;
	}

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
			goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("mysql started thread %p\n", thread_data);

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS(thread_data),
			mysql_pause_check,
			thread_data
	);

	if (rrr_event_collection_push_periodic (
			&data->event_process_entries,
			&data->events,
			mysql_event_process_entries,
			data,
			1000 // 1000 ms
	) != 0) {
		RRR_MSG_0("Failed to create queue process event in mysql instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	RRR_DBG_1 ("Thread mysql %p exiting\n", thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mysql,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "mysql";

struct rrr_instance_event_functions event_functions = {
	mysql_event_broker_data_available
};

__attribute__((constructor)) void load(void) {
	rrr_mysql_library_init();
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy mysql module\n");
	rrr_mysql_library_end();
}
