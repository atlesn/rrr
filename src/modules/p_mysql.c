/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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
#include <src/lib/array.h>
#include <src/lib/rrr_mysql.h>

#include "../lib/poll_helper.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/linked_list.h"
#include "../lib/map.h"
#include "../lib/string_builder.h"
#include "../global.h"

#define RRR_MYSQL_DEFAULT_SERVER "localhost"
#define RRR_MYSQL_DEFAULT_PORT 5506

//#define RRR_MYSQL_SQL_MAX 4096
//#define RRR_MYSQL_MAX_COLUMN_NAME_LENGTH 32

#define RRR_PY_PASTE(x,y) x ## _ ## y

// TODO : Fix URI support

struct mysql_data {
	struct rrr_fifo_buffer input_buffer;
	struct rrr_fifo_buffer output_buffer_local;
	struct rrr_fifo_buffer output_buffer_ip;
	MYSQL mysql;
	MYSQL_BIND *bind;
	unsigned long *bind_string_lengths;
	ssize_t bind_max;
	int mysql_initialized;
	int mysql_connected;

	/* These must be freed at thread end if not NULL */
	char *mysql_server;
	char *mysql_user;
	char *mysql_password;
	char *mysql_db;
	char *mysql_table;

	unsigned int mysql_port;

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

static void bind_cleanup (struct mysql_data *data) {
	RRR_FREE_IF_NOT_NULL(data->bind);
	RRR_FREE_IF_NOT_NULL(data->bind_string_lengths);
	data->bind_max = 0;
}

static int allocate_and_clear_bind_as_needed (struct mysql_data *data, ssize_t elements) {
	if (data->bind != NULL && data->bind_max >= elements) {
		goto out_clear;
	}

	bind_cleanup(data);

	if ((data->bind = malloc(sizeof(*(data->bind)) * elements)) == NULL) {
		RRR_MSG_ERR("Could not allocate mysql bind structure in bind_allocate_if_needed\n");
		return 1;
	}

	if ((data->bind_string_lengths = malloc(sizeof(*(data->bind_string_lengths)) * elements)) == NULL) {
		RRR_MSG_ERR("Could not allocate mysql bind string lengths in bind_allocate_if_needed\n");
		return 1;
	}

	data->bind_max = elements;

	out_clear:
	memset(data->bind, '\0', sizeof(*(data->bind)) * data->bind_max);
	memset(data->bind_string_lengths, '\0', sizeof(*(data->bind_string_lengths)) * data->bind_max);
	return 0;
}

void data_cleanup(void *arg) {
	struct mysql_data *data = arg;

	bind_cleanup(data);

	rrr_map_clear(&data->columns);
	rrr_map_clear(&data->special_columns);
	rrr_map_clear(&data->column_tags);
	rrr_map_clear(&data->blob_write_columns);

	rrr_fifo_buffer_clear (&data->input_buffer);
	rrr_fifo_buffer_clear (&data->output_buffer_local);
	rrr_fifo_buffer_clear (&data->output_buffer_ip);

	RRR_FREE_IF_NOT_NULL(data->mysql_server);
	RRR_FREE_IF_NOT_NULL(data->mysql_user);
	RRR_FREE_IF_NOT_NULL(data->mysql_password);
	RRR_FREE_IF_NOT_NULL(data->mysql_db);
	RRR_FREE_IF_NOT_NULL(data->mysql_table);
}

int data_init(struct mysql_data *data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));
	ret |= rrr_fifo_buffer_init_custom_free (&data->input_buffer, rrr_ip_buffer_entry_destroy_void);
	ret |= rrr_fifo_buffer_init (&data->output_buffer_local);
	ret |= rrr_fifo_buffer_init_custom_free (&data->output_buffer_ip, rrr_ip_buffer_entry_destroy_void);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

struct process_entries_data {
	struct mysql_data *data;
	ssize_t column_count;
	MYSQL_STMT *stmt;
};

struct column_configurator {
	int (*create_sql)(char **target, ssize_t *column_count, struct mysql_data *data);
	int (*bind_and_execute)(struct process_entries_data *data, struct rrr_ip_buffer_entry *entry);
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
	strcmp(str,RRR_PY_PASTE(COLUMN_PLAN_NAME,name)) == 0
#define COLUMN_PLAN_INDEX(name) \
	RRR_PY_PASTE(COLUMN_PLAN,name)

int mysql_columns_check_blob_write(const struct mysql_data *data, const char *col_1) {
	if (rrr_map_get_value(&data->blob_write_columns, col_1) != NULL) {
		return 1;
	}
	return 0;
}

int mysql_bind_and_execute(struct process_entries_data *data) {
	MYSQL_BIND *bind = data->data->bind;

	if (mysql_stmt_bind_param(data->stmt, bind) != 0) {
		RRR_MSG_ERR ("mysql: Failed to bind values to statement: Error: %s\n",
				mysql_error(&data->data->mysql));
		return 1;
	}

	if (mysql_stmt_execute(data->stmt) != 0) {
		RRR_MSG_ERR ("mysql: Failed to execute statement: Error: %s\n",
				mysql_error(&data->data->mysql));
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
	RRR_STRING_BUILDER_UNCHECKED_APPEND(&string_builder,str)
/*
int colplan_voltage_create_sql(char **target, ssize_t *column_count, struct mysql_data *data) {
	struct rrr_string_builder string_builder = {0};

	*column_count = 0;

	int ret = 0;

	APPEND_AND_CHECK("REPLACE INTO `");
	APPEND_AND_CHECK(data->mysql_table);
	APPEND_AND_CHECK("` (`timestamp`, `source`, `class`, `time_from`, `time_to`, `value`, `message`, `message_length`) ");
	APPEND_AND_CHECK("VALUES (?,?,?,?,?,?,?,?)");

	*target = rrr_string_builder_buffer_takeover(&string_builder);
	*column_count = 8;

	out:
	rrr_string_builder_clear(&string_builder);
	return ret;
}

int colplan_voltage_bind_execute(struct process_entries_data *data, struct rrr_ip_buffer_entry *entry) {
	if (allocate_and_clear_bind_as_needed (data->data, 8) != 0) {
		return 1;
	}

	MYSQL_BIND *bind = data->data->bind;

	struct sockaddr_in *ipv4_in = (struct sockaddr_in*) &entry->addr;

	// TODO : not thread safe
	char *ipv4_string_tmp = inet_ntoa(ipv4_in->sin_addr);
	char ipv4_string[strlen(ipv4_string_tmp)+1];
	sprintf(ipv4_string, "%s", ipv4_string_tmp);

	struct rrr_message *message = entry->message;

	RRR_DBG_2 ("mysql: Saving message type/class %" PRIu32 " with timestamp %" PRIu64 "\n",
			message->type_and_class, message->timestamp);

	// TODO : Check that message length fits in unsigned long
	// TODO : We are not very careful with int sizes here

	// Timestamp
	bind[0].buffer = &message->timestamp;
	bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[0].is_unsigned = 1;

	// Source
	unsigned long source_length = strlen(ipv4_string);
	bind[1].buffer = ipv4_string;
	bind[1].length = &source_length;
	bind[1].buffer_type = MYSQL_TYPE_STRING;

	// Type and class
	bind[2].buffer = &message->type_and_class;
	bind[2].buffer_type = MYSQL_TYPE_LONG;
	bind[2].is_unsigned = 1;

	// Time
	bind[3].buffer = &message->timestamp;
	bind[3].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[3].is_unsigned = 1;

	// Time to
	bind[4].buffer = &message->timestamp_to;
	bind[4].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[4].is_unsigned = 1;

	// Value
	bind[5].buffer = &message->data_numeric;
	bind[5].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[5].is_unsigned = 1;

	// Message
	unsigned long message_length_a = MSG_DATA_LENGTH(message);
	bind[6].buffer = MSG_DATA_PTR(message);
	bind[6].length = &message_length_a;
	bind[6].buffer_type = MYSQL_TYPE_STRING;

	// Message length
	unsigned long message_length_b = MSG_DATA_LENGTH(message);
	bind[7].buffer = &message_length_b;
	bind[7].buffer_type = MYSQL_TYPE_LONG;
	bind[7].is_unsigned = 1;

	return mysql_bind_and_execute(data);
}
*/
int colplan_array_create_sql(char **target, ssize_t *column_count_result, struct mysql_data *data) {
	struct rrr_string_builder string_builder = {0};

	*target = NULL;

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

	int columns_count = 0;

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
	for (int i = 0; i < columns_count; i++) {
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

//	printf ("%s", *target);

	out:
	rrr_string_builder_clear(&string_builder);
	return ret;
}

void free_collection(void *arg) {
	rrr_array_clear(arg);
}

static int bind_value (
		MYSQL_BIND *bind,
		int bind_pos,
		struct rrr_type_value *definition,
		const char *column_name,
		struct mysql_data *data
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
//		printf ("bind position %i string length %lu\n", bind_pos, data->bind_string_lengths[bind_pos]);
	}
	else if (RRR_TYPE_IS_64(definition->definition->type)) {
		bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
		bind[bind_pos].buffer = definition->data;
		bind[bind_pos].is_unsigned = RRR_TYPE_FLAG_IS_UNSIGNED(definition->flags);
//		printf ("bind position %i integer %" PRIi64 "\n", bind_pos, *((int64_t*)definition->data));
	}
	else {
		RRR_MSG_ERR("Unknown type %ul when binding with mysql\n", definition->definition->type);
		return 1;
	}
	return 0;
}

int colplan_array_bind_execute(struct process_entries_data *p_data, struct rrr_ip_buffer_entry *entry) {
	int ret = 0;

	struct mysql_data *data = p_data->data;

	struct rrr_array collection;
	memset(&collection, '\0', sizeof(collection));
	pthread_cleanup_push(free_collection, &collection);

	if (rrr_array_message_to_collection(&collection, entry->message) != 0) {
		RRR_MSG_ERR("Could not convert array message to data collection in mysql\n");
		ret = 1;
		goto out_cleanup;
	}

	if (collection.version != 7) {
		RRR_BUG("Array version mismatch in MySQL colplan_array_bind_execute (%u vs %i), module must be updated\n",
				collection.version, 7);
	}

	int column_count =	RRR_MAP_COUNT(&data->columns) +
						RRR_MAP_COUNT(&data->column_tags) +
						RRR_MAP_COUNT(&data->special_columns) +
						(data->add_timestamp_col != 0 ? 1 : 0);

	if (allocate_and_clear_bind_as_needed(data, column_count) != 0) {
		ret = 1;
		goto out_cleanup;
	}

	MYSQL_BIND *bind = data->bind;

	int bind_pos = 0;

	if (RRR_MAP_COUNT(&data->column_tags) > 0) {
		RRR_MAP_ITERATE_BEGIN(&data->column_tags);
			struct rrr_type_value *array_value = rrr_array_value_get_by_tag(&collection, node_tag);

			if (array_value == NULL) {
				RRR_MSG_ERR("Array tag '%s' not found when binding with MySQL\n", node_tag);
				ret = 1;
				goto out_cleanup;
			}

			if (bind_value(bind, bind_pos, array_value, node_value, data) != 0) {
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
				RRR_MSG_ERR("Warning: Incoming array message contains more array elements than configuration. The rest is discarded.\n");
				RRR_LL_ITERATE_BREAK();
			}

			if (bind_value(
					bind,
					bind_pos,
					definition,
					(item->value != NULL && *(item->value) != '\0' ? item->value : item->tag),
					data
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

//		printf ("bind position %i timestamp %llu\n", bind_pos, timestamp);

		bind_pos++;
	}

	if (bind_pos != p_data->column_count) {
		RRR_BUG("Bind items did not match column count in colplan_array_bind_execute\n");
	}

	ret = mysql_bind_and_execute(p_data);

	out_cleanup:
	if (ret != 0) {
		RRR_MSG_ERR("Could not save array message to mysql database\n");
	}
	pthread_cleanup_pop(1);

	return ret;
}

/* Check index numbers with defines above */
struct column_configurator column_configurators[] = {
		{ .create_sql = NULL,							.bind_and_execute = NULL },
		{ .create_sql = NULL,							.bind_and_execute = NULL },
		//{ .create_sql = &colplan_voltage_create_sql,	.bind_and_execute = &colplan_voltage_bind_execute },
		{ .create_sql = &colplan_array_create_sql,		.bind_and_execute = &colplan_array_bind_execute }
};

int mysql_disconnect(struct mysql_data *data) {
	if (data->mysql_connected == 1) {
		mysql_close(&data->mysql);
		data->mysql_connected = 0;
	}
	return 0;
}

int connect_to_mysql(struct mysql_data *data) {
	if (data->mysql_connected != 1) {
		void *ptr = mysql_init(&data->mysql);
		if (ptr == NULL) {
			RRR_MSG_ERR ("Could not initialize MySQL\n");
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
			RRR_MSG_ERR ("mysql: Failed to connect to database: Error: %s\n",
					mysql_error(&data->mysql));
			return 1;
		}

		data->mysql_connected = 1;
	}

	return 0;
}

void stop_mysql(void *arg) {
	struct mysql_data *data = arg;
	if (data->mysql_initialized == 1) {
		// TODO : Maybe do stuff here
		mysql_thread_end();
	}
	mysql_disconnect(data);
}

int start_mysql(struct mysql_data *data) {
	mysql_thread_init();
	data->mysql_initialized = 1;
	data->mysql_connected = 0;
	return 0;
}

struct mysql_parse_columns_data {
	struct rrr_linked_list *target;
};

// Check that blob write columns are also defined in mysql_columns or mysql_column_tags
int mysql_verify_blob_write_colums (struct mysql_data *data) {
	int ret = 0;

	RRR_MAP_ITERATE_BEGIN(&data->blob_write_columns);
		if (rrr_map_get_value(&data->columns, node_tag) == NULL) {
			if (rrr_map_get_value(&data->column_tags, node_tag) == NULL) {
				RRR_MSG_ERR("Column %s specified in blob write columns but is not defined as a column used to save data\n",
						node_tag);
				ret = 1;
			}
		}
	RRR_MAP_ITERATE_END();

	return ret;
}

int mysql_parse_column_plan (struct mysql_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	int yesno = 0;
//	int strip_separators_was_defined = 0;

	char *mysql_colplan = strdup("array");
	/*

	rrr_instance_config_get_string_noconvert_silent (&mysql_colplan, config, "mysql_colplan");

	if (mysql_colplan == NULL) {
		mysql_colplan = malloc(strlen(COLUMN_PLAN_NAME_VOLTAGE) + 1);
		if (mysql_colplan == NULL) {
			RRR_MSG_ERR("Could not allocate memory in mysql_parse_column_plan\n");
			ret = 1;
			goto out;
		}
		strcpy (mysql_colplan, COLUMN_PLAN_NAME_VOLTAGE);
		RRR_MSG_ERR("Warning: No mysql_colplan set for instance %s, defaulting to voltage\n", config->name);
	}

*/
	// BLOB WRITE COLUMNS
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->blob_write_columns, config, "mysql_blob_write_columns");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mysql_blob_write_columns of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i blob write columns specified for mysql instance %s\n", RRR_MAP_COUNT(&data->blob_write_columns), config->name);

	// SPECIAL COLUMNS AND THEIR VALUES
	ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->special_columns, config, "mysql_special_columns", "=");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mysql_special_columns of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i special columns specified for mysql instance %s\n", RRR_MAP_COUNT(&data->special_columns), config->name);

	// STRIP OUT SEPARATORS
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "mysql_strip_array_separators")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Could not parse mysql_strip_array_separators of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->strip_array_separators = yesno;
		//strip_separators_was_defined = 1;
	}

	// TABLE COLUMNS
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->columns, config, "mysql_columns");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mysql_columns of instance %s\n", config->name);
		goto out;
	}

	ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->column_tags, config, "mysql_column_tags", "->");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mysql_column_tags of instance %s\n", config->name);
		goto out;
	}

	if (COLUMN_PLAN_MATCH(mysql_colplan,ARRAY)) {
		data->colplan = COLUMN_PLAN_INDEX(ARRAY);

		if (RRR_MAP_COUNT(&data->columns) != 0 && RRR_MAP_COUNT(&data->column_tags) != 0) {
			RRR_MSG_ERR("mysql_column_tags and mysql_columns cannot be specified simultaneously in instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		RRR_DBG_1("%i ordinary columns specified for mysql instance %s\n",
				RRR_MAP_COUNT(&data->columns) + RRR_MAP_COUNT(&data->column_tags), config->name);

		if (RRR_MAP_COUNT(&data->columns) + RRR_MAP_COUNT(&data->column_tags) == 0) {
			RRR_MSG_ERR("No columns specified in mysql_columns or mysql_column_tags; needed when using array column plan for instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		if (mysql_verify_blob_write_colums (data) != 0) {
			RRR_MSG_ERR("Error in blob write column list for mysql instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
/*	else if (COLUMN_PLAN_MATCH(mysql_colplan,VOLTAGE)) {
		data->colplan = COLUMN_PLAN_INDEX(VOLTAGE);

		if (strip_separators_was_defined != 0) {
			RRR_MSG_ERR("Cannot use mysql_strip_array_separators along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (data->add_timestamp_col != 0) {
			RRR_MSG_ERR("Cannot use mysql_add_timestamp_col=yes along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (RRR_MAP_COUNT(&data->columns) != 0 || RRR_MAP_COUNT(&data->column_tags) != 0) {
			RRR_MSG_ERR("Cannot use mysql_column_tags and mysql_columns along with voltage column plan in instance %s\n", config->name);
			ret = 1;
		}

		if (RRR_MAP_COUNT(&data->special_columns) != 0) {
			RRR_MSG_ERR("Cannot use mysql_special_columns along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (RRR_MAP_COUNT(&data->blob_write_columns) != 0) {
			RRR_MSG_ERR("Cannot use mysql_columns_blob_writes along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (ret != 0) {
			goto out;
		}

		RRR_DBG_2("Using voltage column plan for mysql for instance %s\n", config->name);
	}*/
	else {
		RRR_MSG_ERR("BUG: Reached end of colplan name tests in mysql for instance %s\n", config->name);
		exit(EXIT_FAILURE);
	}

	out:
	RRR_FREE_IF_NOT_NULL(mysql_colplan);
	return ret;
}

int mysql_parse_port (struct mysql_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	data->mysql_port = RRR_MYSQL_DEFAULT_PORT;
	rrr_setting_uint tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "mysql_port");

	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse mysql_port for instance %s\n", config->name);
			ret = 1;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
	}

	return ret;
}

int parse_config(struct mysql_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	// These values are parsed by sub functions

	// char *mysql_colplan = NULL;
	// char *mysql_add_ts_col = NULL;
	// char *mysql_special_cols = NULL;
	// char *mysql_cols_blob_wr = NULL;
	// char *mysql_port = NULL;

	// These are free()d on thread exit, not here
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_server,	config, "mysql_server");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_user,		config, "mysql_user");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_password,	config, "mysql_password");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_db,		config, "mysql_db");
	rrr_instance_config_get_string_noconvert_silent (&data->mysql_table,	config, "mysql_table");

	if (data->mysql_user == NULL || data->mysql_password == NULL) {
		RRR_MSG_ERR ("mysql_user or mysql_password not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_table == NULL) {
		RRR_MSG_ERR ("mysql_table not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_server == NULL) {
		RRR_MSG_ERR ("mysql_server not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_db == NULL) {
		RRR_MSG_ERR ("mysql_db not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	// GENERATE TAG MESSAGES (UNDOCUMENTED, FOR TESTING)
	int yesno = 0;
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_generate_tag_messages") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_ERR ("mysql: Could not understand argument mysql_generate_tag_messages of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->generate_tag_messages = (yesno == 0 || yesno == 1 ? yesno : 0);

	// DROP UNKNOWN MESSAGES
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_drop_unknown_messages") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_ERR ("mysql: Could not understand argument mysql_drop_unknown_messages of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->drop_unknown_messages = (yesno == 0 || yesno == 1 ? yesno : 0);

	// ADD TIMESTAMP COL
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_add_timestamp_col") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_ERR ("mysql: Could not understand argument mysql_add_timestamp_col of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->add_timestamp_col = (yesno == 0 || yesno == 1 ? yesno : 0);

	// MYSQL PORT
	if (mysql_parse_port(data, config) != 0) {
		RRR_MSG_ERR("Error while parsing mysql port for instance %s\n", config->name);
		ret = 1;
	}

	// COLUMN PLAN AND COLUMN LISTS
	if (mysql_parse_column_plan(data, config) != 0) {
		RRR_MSG_ERR("Error in mysql column plan for instance %s\n", config->name);
		ret = 1;
	}

	return ret;
}

int poll_callback_ip(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;

	RRR_DBG_3 ("mysql: Result from buffer (ip): size %lu\n", size);

	rrr_fifo_buffer_write(&mysql_data->input_buffer, data, size);

	return 0;
}

int poll_callback_local(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;
	struct rrr_message *reading = (struct rrr_message *) data;
	struct rrr_ip_buffer_entry *entry = NULL;
	int ret = 0;

	(void)(size);

	if (rrr_ip_buffer_entry_new (
			&entry,
			MSG_TOTAL_SIZE(reading),
			NULL,
			0,
			0,
			reading
	) != 0) {
		RRR_MSG_ERR("Could not allocate ip buffer entry in poll_callback_local\n");
		ret = 1;
		goto out;
	}

	rrr_fifo_buffer_write(&mysql_data->input_buffer, (char*) entry, sizeof(*entry));

	reading = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(reading);
	return ret;
}

// Poll request from other local modules
int mysql_poll_delete_local (RRR_MODULE_POLL_SIGNATURE) {
	struct mysql_data *mysql_data = data->private_data;

	return rrr_fifo_read_clear_forward(&mysql_data->output_buffer_local, NULL, callback, poll_data, wait_milliseconds);
}

// Poll request from other IP-capable modules
int mysql_poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct mysql_data *mysql_data = data->private_data;

	return rrr_fifo_read_clear_forward(&mysql_data->output_buffer_ip, NULL, callback, poll_data, wait_milliseconds);
}

int mysql_save(struct process_entries_data *data, struct rrr_ip_buffer_entry *entry) {
	if (data->data->mysql_connected != 1) {
		return 1;
	}

	struct mysql_data *mysql_data = data->data;
	struct rrr_message *message = entry->message;

	int is_unknown = 0;
	int colplan_index = COLUMN_PLAN_VOLTAGE;
	if (MSG_IS_MSG_ARRAY(message)) {
		if (!IS_COLPLAN_ARRAY(mysql_data)) {
			RRR_MSG_ERR("Received an array message in mysql but array column plan is not being used\n");
			is_unknown = 1;
			goto out;
		}
		colplan_index = COLUMN_PLAN_ARRAY;
	}
/*	else if (MSG_IS_MSG(message)) {
		if (!IS_COLPLAN_VOLTAGE(mysql_data)) {
			RRR_MSG_ERR("Received a non-array message in mysql, dropping. Class was %" PRIu32 ".\n", MSG_CLASS(message));
			is_unknown = 1;
			goto out;
		}
		colplan_index = COLUMN_PLAN_VOLTAGE;
	}*/
	else {
		RRR_MSG_ERR("Unknown message class/type %u/%u received in mysql_save\n", MSG_CLASS(message), MSG_TYPE(message));
		is_unknown = 1;
		goto out;
	}

	out:
	if (is_unknown) {
		return 1;
	}

	return column_configurators[colplan_index].bind_and_execute(data, entry);
}

int process_callback (struct rrr_fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct process_entries_data *process_data = callback_data->private_data;
	struct rrr_instance_thread_data *thread_data = callback_data->source;
	struct mysql_data *mysql_data = process_data->data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;
	struct rrr_message *message = entry->message;

	rrr_thread_update_watchdog_time(thread_data->thread);

	int err = RRR_FIFO_OK;

	RRR_DBG_3 ("mysql: processing message with timestamp %" PRIu64 "\n", message->timestamp);

	int mysql_save_res = mysql_save (process_data, entry);

	if (mysql_save_res != 0) {
		if (mysql_data->drop_unknown_messages) {
			RRR_MSG_ERR("mysql instance %s dropping message\n", INSTANCE_D_NAME(thread_data));
			rrr_ip_buffer_entry_destroy(entry);
			entry = NULL;
		}
		else {
			// Put back in buffer
			RRR_DBG_3 ("mysql: Putting message with timestamp %" PRIu64 " back into the buffer\n", message->timestamp);
			rrr_fifo_buffer_write(&mysql_data->input_buffer, (char *) entry, size);
			entry = NULL;
		}
	}
	else if (mysql_data->generate_tag_messages != 0) {
		// Tag message as saved to sender
		RRR_DBG_3 ("mysql: generate tag message for entry with timestamp %" PRIu64 "\n", message->timestamp);
		MSG_SET_TYPE(message, MSG_TYPE_TAG);
		MSG_SET_CLASS(message, MSG_CLASS_ARRAY);
		message->msg_size = MSG_TOTAL_SIZE(message) - MSG_DATA_LENGTH(message);
		entry->data_length = MSG_TOTAL_SIZE(message);
		if (entry->addr_len == 0) {
			// Message does not contain IP information which means it originated locally
			rrr_fifo_buffer_write(&mysql_data->output_buffer_local, entry->message, entry->data_length);
			entry->message = NULL;
		}
		else {
			rrr_fifo_buffer_write(&mysql_data->output_buffer_ip, (char *) entry, size);
			entry = NULL;
		}
	}

	if (entry != NULL) {
		rrr_ip_buffer_entry_destroy(entry);
	}

	return err;
}

void close_mysql_stmt(void *arg) {
	mysql_stmt_close(arg);
}

int process_entries (struct rrr_instance_thread_data *thread_data) {
	struct mysql_data *data = thread_data->private_data;
	struct rrr_fifo_callback_args poll_data;

	if (connect_to_mysql(data) != 0) {
		return 1;
	}

	int ret = 0;
	char *query = NULL;

	MYSQL_STMT *stmt = mysql_stmt_init(&data->mysql);

	pthread_cleanup_push(close_mysql_stmt, stmt);

	struct process_entries_data process_data;

	process_data.data = data;
	process_data.stmt = stmt;

	poll_data.private_data = &process_data;
	poll_data.source = thread_data;

	if (!COLPLAN_OK(data)) {
		RRR_MSG_ERR("BUG: Mysql colplan was out of range in process_entries\n");
		exit (EXIT_FAILURE);
	}

	if (column_configurators[data->colplan].create_sql(&query, &process_data.column_count, data) != 0) {
		ret = 1;
		goto out;
	}

	if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
		RRR_MSG_ERR ("mysql: Failed to prepare statement: Error: %s\n",
				mysql_error(&data->mysql));
		mysql_disconnect(data);
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		if (rrr_fifo_buffer_get_entry_count(&data->input_buffer) > 0) {
			RRR_MSG("mysql SQL: %s\n", query);
		}
	}

	ret = rrr_fifo_read_clear_forward(&data->input_buffer, NULL, process_callback, &poll_data, 50);
	if (ret != 0) {
		RRR_MSG_ERR ("mysql: Error when saving entries to database\n");
		mysql_disconnect(data);
	}

	out:
	RRR_FREE_IF_NOT_NULL(query);
	pthread_cleanup_pop(1);
	return ret;
}

static void *thread_entry_mysql (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data) != 0) {
		RRR_MSG_ERR("Could not initalize data in mysql instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("mysql thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	poll_collection_init(&poll);
	poll_collection_init(&poll_ip);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(stop_mysql, data);
	pthread_cleanup_push(data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (start_mysql(data) != 0) {
		goto out_message;
	}

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
			goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP);

	poll_remove_senders_also_in(&poll, &poll_ip);

	RRR_DBG_1 ("mysql started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		int err = 0;

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback_local, 50) != 0) {
			break;
		}

		process_entries(thread_data);

		if (poll_do_poll_delete_ip_simple (&poll_ip, thread_data, poll_callback_ip, 50) != 0) {
			break;
		}

		process_entries(thread_data);

		if (data->mysql_connected != 1) {
			// Sleep a little if we can't connect to the server
			usleep (1000000);
		}

		if (err != 0) {
			break;
		}
	}

	out_message:
	RRR_DBG_1 ("Thread mysql %p exiting\n", thread_data->thread);

//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct mysql_data data;
	int ret = 0;
	if ((ret = data_init(&data)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mysql,
		NULL,
		NULL,
		NULL,
		mysql_poll_delete_local,
		mysql_poll_delete_ip,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "mysql";

__attribute__((constructor)) void load(void) {
	rrr_mysql_library_init();
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->special_module_operations = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy mysql module\n");
	rrr_mysql_library_end();
}
