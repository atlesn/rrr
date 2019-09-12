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
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../global.h"

// Should not be smaller than module max
#define RRR_MYSQL_MAX_SENDERS VL_MODULE_MAX_SENDERS

#define RRR_MYSQL_DEFAULT_SERVER "localhost"
#define RRR_MYSQL_DEFAULT_PORT 5506

#define RRR_MYSQL_SQL_MAX 4096
#define RRR_MYSQL_MAX_COLUMN_NAME_LENGTH 32

#define RRR_PY_PASTE(x,y) x ## _ ## y

// TODO : Fix URI support

struct mysql_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer_local;
	struct fifo_buffer output_buffer_ip;
	MYSQL mysql;
	MYSQL_BIND bind[RRR_MYSQL_BIND_MAX];
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
	int no_tagging;
	int colplan;
	int add_timestamp_col;
	int strip_array_separators;
	unsigned int mysql_special_columns_count;

	/* Must be traversed and non-nulls freed at thread exit */
	char *mysql_columns[RRR_MYSQL_BIND_MAX];
	char *mysql_special_columns[RRR_MYSQL_BIND_MAX];
	char *mysql_special_values[RRR_MYSQL_BIND_MAX];
	char *mysql_columns_blob_writes[RRR_MYSQL_BIND_MAX]; // Force blob write method
};

struct process_entries_data {
	struct mysql_data *data;
	MYSQL_STMT *stmt;
};

struct column_configurator {
	int (*create_sql)(char *target, unsigned int target_size, struct mysql_data *data);
	int (*bind_and_execute)(struct process_entries_data *data, struct ip_buffer_entry *entry);
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
	for (int i = 0; i < RRR_MYSQL_BIND_MAX; i++) {
		const char *col_2 = data->mysql_columns_blob_writes[i];

		if (col_2 == NULL) {
			break;
		}
		if (strcmp(col_1, col_2) == 0) {
			return 1;
		}
	}

	return 0;
}

int mysql_bind_and_execute(struct process_entries_data *data) {
	MYSQL_BIND *bind = data->data->bind;

	if (mysql_stmt_bind_param(data->stmt, bind) != 0) {
		VL_MSG_ERR ("mysql: Failed to bind values to statement: Error: %s\n",
				mysql_error(&data->data->mysql));
		return 1;
	}

	if (mysql_stmt_execute(data->stmt) != 0) {
		VL_MSG_ERR ("mysql: Failed to execute statement: Error: %s\n",
				mysql_error(&data->data->mysql));
		return 1;
	}

	return 0;
}

int colplan_voltage_create_sql(char *target, unsigned int target_size, struct mysql_data *data) {
	const char *query_base = "REPLACE INTO `%s` " \
			"(`timestamp`, `source`, `class`, `time_from`, `time_to`, `value`, `message`, `message_length`) " \
			"VALUES (?,?,?,?,?,?,?,?)";

	unsigned int len = strlen(query_base) + strlen(data->mysql_table) + 1;
	if (len > target_size) {
		VL_MSG_ERR("Could not fit voltage column plan SQL in colplan_volate_create_sql");
		return 1;
	}

	sprintf(target, query_base, data->mysql_table);

	return 0;
}

int colplan_voltage_bind_execute(struct process_entries_data *data, struct ip_buffer_entry *entry) {
	MYSQL_BIND *bind = data->data->bind;

	memset(bind, '\0', sizeof(*bind));

	struct sockaddr_in *ipv4_in = (struct sockaddr_in*) &entry->addr;

	// TODO : not thread safe
	char *ipv4_string_tmp = inet_ntoa(ipv4_in->sin_addr);
	char ipv4_string[strlen(ipv4_string_tmp)+1];
	sprintf(ipv4_string, "%s", ipv4_string_tmp);

	struct vl_message *message = entry->message;

	VL_DEBUG_MSG_2 ("mysql: Saving message type %" PRIu32 " with timestamp %" PRIu64 "\n",
			message->type, message->timestamp_to);

	// TODO : Check that message length fits in unsigned long
	// TODO : We are not very careful with int sizes here

	// Timestamp
	bind[0].buffer = &message->timestamp_to;
	bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[0].is_unsigned = 1;

	// Source
	unsigned long source_length = strlen(ipv4_string);
	bind[1].buffer = ipv4_string;
	bind[1].length = &source_length;
	bind[1].buffer_type = MYSQL_TYPE_STRING;

	// Class
	bind[2].buffer = &message->class;
	bind[2].buffer_type = MYSQL_TYPE_LONG;
	bind[2].is_unsigned = 1;

	// Time from
	bind[3].buffer = &message->timestamp_from;
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
	unsigned long message_length = message->length;
	bind[6].buffer = message->data_;
	bind[6].length = &message_length;
	bind[6].buffer_type = MYSQL_TYPE_STRING;

	// Message length
	bind[7].buffer = &message->length;
	bind[7].buffer_type = MYSQL_TYPE_LONG;
	bind[7].is_unsigned = 1;

	return mysql_bind_and_execute(data);
}

int colplan_array_create_sql(char *target, unsigned int target_size, struct mysql_data *data) {
	static const unsigned int query_base_max = RRR_MYSQL_SQL_MAX + ((RRR_MYSQL_BIND_MAX + 1) * RRR_MYSQL_MAX_COLUMN_NAME_LENGTH * 2);
	char query_base[query_base_max];
	int pos = 0;
	*target = '\0';

	// Make sure constant strings to be put into query_base do no exceed
	// VL_MYSQL_SQL_MAX, as we do not use snprintf (YOLO)

	const char *timestamp_column = (data->add_timestamp_col ? ",`timestamp`" : "");
	const char *timestamp_column_questionmark = (data->add_timestamp_col ? ",?" : "");

	sprintf(query_base + pos, "REPLACE INTO `%s` (", data->mysql_table);
	pos = strlen(query_base);

	// Standard columns
	int columns_count = 0;
	for (int i = 0; i < RRR_MYSQL_BIND_MAX && data->mysql_columns[i] != NULL; i++) {
		unsigned int len = strlen(data->mysql_columns[i]);

		if (len + pos + 4 > query_base_max) {
			VL_MSG_ERR("BUG: Column names were too long in mysql array SQL creation");
			return 1;
		}

		const char *comma = (columns_count > 0 ? "," : "");

		sprintf (query_base + pos, "%s`%s`", comma, data->mysql_columns[i]);
		pos = strlen(query_base);
		columns_count++;
	}

	// Special columns
	for (unsigned int i = 0; i < data->mysql_special_columns_count; i++) {
		int unsigned len = strlen(data->mysql_special_columns[i]);

		if (len + pos + 4 > query_base_max) {
			VL_MSG_ERR("BUG: Column names were too long in mysql array SQL creation");
			return 1;
		}

		const char *comma = (columns_count > 0 ? "," : "");

		sprintf (query_base + pos, "%s`%s`", comma, data->mysql_special_columns[i]);
		pos = strlen(query_base);
		columns_count++;
	}

	sprintf(query_base + pos, "%s) VALUES (", timestamp_column);
	pos = strlen(query_base);

	for (int i = 0; i < columns_count; i++) {
		const char *comma = (i > 0 ? "," : "");
		sprintf(query_base + pos, "%s?", comma);
		pos = strlen(query_base);
	}

	sprintf(query_base + pos, "%s)", timestamp_column_questionmark);

	// Double check length
	if (strlen(query_base) > query_base_max) {
		VL_BUG("BUG: query_base was too long in colplan_array_create_sql");
	}

	if (target_size < strlen(query_base)) {
		VL_MSG_ERR("Mysql query was too long in colplan_array_create_sql\n");
		return 1;
	}

	sprintf(target, "%s", query_base);

	return 0;
}

void free_collection(void *arg) {
	struct vl_thread_double_pointer *data = arg;
	if (*data->ptr != NULL) {
		rrr_array_clear(*data->ptr);
	}
}

int colplan_array_bind_execute(struct process_entries_data *data, struct ip_buffer_entry *entry) {
	int res = 0;

	struct rrr_array collection;
	pthread_cleanup_push(free_collection, &collection);

	if (rrr_array_message_to_collection(&collection, entry->message) != 0) {
		VL_MSG_ERR("Could not convert array message to data collection in mysql\n");
		res = 1;
		goto out_cleanup;
	}

	MYSQL_BIND *bind = data->data->bind;

	if (collection.node_count + data->data->add_timestamp_col + data->data->mysql_special_columns_count > RRR_MYSQL_BIND_MAX) {
		VL_MSG_ERR("Number of types exceeded maximum (%i vs %i)\n",
				collection.node_count + data->data->add_timestamp_col + data->data->mysql_special_columns_count, RRR_MYSQL_BIND_MAX);
		res = 1;
		goto out_cleanup;
	}

	unsigned long string_lengths[RRR_MYSQL_BIND_MAX];
	memset(string_lengths, '\0', sizeof(string_lengths));

	rrr_def_count bind_pos = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(&collection,struct rrr_type_value);
		struct rrr_type_value *definition = node;

		if (data->data->strip_array_separators != 0 && node->definition->type == RRR_TYPE_SEP) {
			goto next;
		}

		if (	// Arrays must be inserted as blobs. They might be shorter than the
				// maximum length, the input definition decides.
				definition->element_count > 1 ||
				RRR_TYPE_IS_BLOB(definition->definition->type) ||
				mysql_columns_check_blob_write(data->data, data->data->mysql_columns[bind_pos])
		) {
			string_lengths[bind_pos] = definition->total_stored_length;
			bind[bind_pos].buffer = definition->data;
			bind[bind_pos].length = &string_lengths[bind_pos];
			bind[bind_pos].buffer_type = MYSQL_TYPE_STRING;
		}
		else if (RRR_TYPE_IS_64(definition->definition->type)) {
			// TODO : Support signed
			bind[bind_pos].buffer = definition->data;
			bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
			bind[bind_pos].is_unsigned = 1;
		}
		else {
			VL_MSG_ERR("Unknown type %ul when binding with mysql\n", definition->definition->type);
			res = 1;
			goto out_cleanup;
		}

		bind_pos++;
		next:
	RRR_LINKED_LIST_ITERATE_END(&collection);

	for (rrr_def_count i = 0; i < data->data->mysql_special_columns_count; i++) {
		string_lengths[bind_pos] = strlen(data->data->mysql_special_values[i]);
		bind[bind_pos].buffer = data->data->mysql_special_values[i];
		bind[bind_pos].length = &string_lengths[bind_pos];
		bind[bind_pos].buffer_type = MYSQL_TYPE_STRING;

		bind_pos++;
	}

	unsigned long long int timestamp = time_get_64();
	if (data->data->add_timestamp_col) {
		bind[bind_pos].buffer = &timestamp;
		bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
		bind[bind_pos].is_unsigned = 1;
	}

	res = mysql_bind_and_execute(data);

	// Produce warning if blob data was chopped of by mysql
	bind_pos = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(&collection,struct rrr_type_value);
		struct rrr_type_value *definition = node;
		if (RRR_TYPE_IS_BLOB(definition->definition->type)) {
			if (string_lengths[bind_pos] < definition->total_stored_length) {
				VL_MSG_ERR("Warning: Only %lu bytes of %u where saved to mysql for column with index %u\n",
						string_lengths[bind_pos], definition->total_stored_length, bind_pos);
			}
		}
		bind_pos++;
	RRR_LINKED_LIST_ITERATE_END(&collection);

	out_cleanup:
	if (res != 0) {
		VL_MSG_ERR("Could not save array message to mysql database\n");
	}
	pthread_cleanup_pop(1);

	return res;
}

/* Check index numbers with defines above */
struct column_configurator column_configurators[] = {
		{ .create_sql = NULL,							.bind_and_execute = NULL },
		{ .create_sql = &colplan_voltage_create_sql,	.bind_and_execute = &colplan_voltage_bind_execute },
		{ .create_sql = &colplan_array_create_sql,		.bind_and_execute = &colplan_array_bind_execute }
};

void data_cleanup(void *arg) {
	struct mysql_data *data = arg;

	for (rrr_def_count i = 0; i < RRR_MYSQL_BIND_MAX; i++) {
		RRR_FREE_IF_NOT_NULL(data->mysql_special_values[i]);
		RRR_FREE_IF_NOT_NULL(data->mysql_special_columns[i]);
		RRR_FREE_IF_NOT_NULL(data->mysql_columns[i]);
		RRR_FREE_IF_NOT_NULL(data->mysql_columns_blob_writes[i]);
	}

	fifo_buffer_invalidate (&data->input_buffer);
	fifo_buffer_invalidate (&data->output_buffer_local);
	fifo_buffer_invalidate (&data->output_buffer_ip);

	RRR_FREE_IF_NOT_NULL(data->mysql_server);
	RRR_FREE_IF_NOT_NULL(data->mysql_user);
	RRR_FREE_IF_NOT_NULL(data->mysql_password);
	RRR_FREE_IF_NOT_NULL(data->mysql_db);
	RRR_FREE_IF_NOT_NULL(data->mysql_table);
}

int data_init(struct mysql_data *data) {
	int ret = 0;
	memset (data, '\0', sizeof(*data));
	ret |= fifo_buffer_init (&data->input_buffer);
	ret |= fifo_buffer_init (&data->output_buffer_local);
	ret |= fifo_buffer_init (&data->output_buffer_ip);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

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
			VL_MSG_ERR ("Could not initialize MySQL\n");
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
			VL_MSG_ERR ("mysql: Failed to connect to database: Error: %s\n",
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
	char **target;
	int target_length;
	struct rrr_instance_config *config;
	int columns_count;
};

int mysql_parse_columns_callback(const char *value, void *_data) {
	struct mysql_parse_columns_data *data = _data;

	int ret = 0;

	if (value == NULL || *value == '\0') {
		goto out;
	}
	else if (data->columns_count >= data->target_length) {
		VL_MSG_ERR("BUG: Too many mysql column arguments (%i vs %i) for instance %s\n",
				data->columns_count, data->target_length, data->config->name);
		exit (EXIT_FAILURE);
	}

	int length = strlen(value);
	if (length > RRR_MYSQL_MAX_COLUMN_NAME_LENGTH) {
		VL_MSG_ERR("Length of column '%s' was longer than maximum (%i vs %i)\n", value, length, RRR_MYSQL_MAX_COLUMN_NAME_LENGTH);
		ret = 1;
		goto out;
	}

	char *tmp =  malloc(length + 1);
	if (tmp == NULL) {
		VL_MSG_ERR("Could not allocate memory in mysql_parse_columns_callback\n");
		return 1;
	}
	sprintf(tmp, "%s", value);

	data->target[data->columns_count] = tmp;
	data->columns_count++;

	out:
	return ret;
}

int mysql_traverse_column_list (char **target, int target_length, int *count, struct rrr_instance_config *config, const char *name) {
	struct mysql_parse_columns_data columns_data;

	int ret = 0;

	*count = 0;

	columns_data.target = target;
	columns_data.target_length = target_length;
	columns_data.config = config;
	columns_data.columns_count = 0;

	ret = rrr_instance_config_traverse_split_commas_silent_fail (
			config, name, &mysql_parse_columns_callback, &columns_data
	);

	*count = columns_data.columns_count;

	return ret;
}

// Check that blob write columns are also defined in mysql_columns
int mysql_verify_blob_write_colums (struct mysql_data *data) {
	int ret = 0;
	int all_was_ok = 1;

	for (int i = 0; i < RRR_MYSQL_BIND_MAX; i++) {
		const char *col_1 = data->mysql_columns_blob_writes[i];

		if (col_1 == NULL) {
			break;
		}

		int was_ok = 0;
		for (int j = 0; j < RRR_MYSQL_BIND_MAX; j++) {
			const char *col_2 = data->mysql_columns[j];
			if (strcmp(col_1, col_2) == 0) {
				was_ok = 1;
				break;
			}
		}

		if (was_ok == 0) {
			VL_MSG_ERR("Column %s specified in mysql_columns_blob_writes but not in mysql_columns\n", col_1);
			all_was_ok = 0;
		}
	}

	if (all_was_ok != 1) {
		ret = 1;
	}

	return ret;
}

int mysql_parse_column_plan (struct mysql_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	int yesno = 0;

	int column_count = 0;
	int special_column_count = 0;
	int special_value_count = 0;
	int strip_separators_was_defined = 0;

	char *mysql_colplan = NULL;
	rrr_instance_config_get_string_noconvert_silent (&mysql_colplan, config, "mysql_colplan");

	if (mysql_colplan == NULL) {
		mysql_colplan = malloc(strlen(COLUMN_PLAN_NAME_VOLTAGE) + 1);
		if (mysql_colplan == NULL) {
			VL_MSG_ERR("Could not allocate memory in mysql_parse_column_plan\n");
			ret = 1;
			goto out;
		}
		strcpy (mysql_colplan, COLUMN_PLAN_NAME_VOLTAGE);
		VL_MSG_ERR("Warning: No mysql_colplan set for instance %s, defaulting to voltage\n", config->name);
	}

	// BLOB WRITE COLUMNS
	ret = mysql_traverse_column_list (
			data->mysql_columns_blob_writes, RRR_MYSQL_BIND_MAX, &column_count, config, "mysql_blob_write_columns"
	);
	VL_DEBUG_MSG_1("%i blob write columns specified for mysql instance %s\n", column_count, config->name);
	if (mysql_verify_blob_write_colums (data) != 0) {
		VL_MSG_ERR("Error in blob write column list for mysql instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// SPECIAL COLUMNS AND THEIR VALUES
	ret = mysql_traverse_column_list (
			data->mysql_special_columns, RRR_MYSQL_BIND_MAX, &special_column_count, config, "mysql_special_columns"
	);
	ret = mysql_traverse_column_list (
			data->mysql_special_values, RRR_MYSQL_BIND_MAX, &special_value_count, config, "mysql_special_values"
	);
	if (special_column_count != special_value_count) {
		VL_MSG_ERR("Special column/value count mismatch %i vs %i for mysql instance %s\n",
				special_column_count, special_value_count, config->name);
		ret = 1;
		goto out;
	}
	data->mysql_special_columns_count = special_column_count;
	VL_DEBUG_MSG_1("%i special columns specified for mysql instance %s\n", special_column_count, config->name);

	// STRIP OUT SEPARATORS
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "mysql_strip_array_separators")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Could not parse mysql_strip_array_separators of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->strip_array_separators = yesno;
		strip_separators_was_defined = 1;
	}

	if (COLUMN_PLAN_MATCH(mysql_colplan,ARRAY)) {
		data->colplan = COLUMN_PLAN_INDEX(ARRAY);

		// TABLE COLUMNS
		ret = mysql_traverse_column_list (
				data->mysql_columns, RRR_MYSQL_BIND_MAX, &column_count, config, "mysql_columns"
		);
		VL_DEBUG_MSG_1("%i ordinary columns specified for mysql instance %s\n", column_count, config->name);
		if (column_count == 0) {
			VL_MSG_ERR("No columns specified in mysql_columns; needed when using array column plan for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (COLUMN_PLAN_MATCH(mysql_colplan,VOLTAGE)) {
		data->colplan = COLUMN_PLAN_INDEX(VOLTAGE);

		if (data->strip_array_separators != 0) {
			VL_MSG_ERR("Cannot use mysql_strip_array_separators with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (data->add_timestamp_col != 0) {
			VL_MSG_ERR("Cannot use mysql_add_timestamp_col=yes along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (data->mysql_special_columns_count > 0) {
			VL_MSG_ERR("Cannot use mysql_special_columns along with voltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (data->mysql_columns_blob_writes[0] != NULL) {
			VL_MSG_ERR("Cannot use mysql_columns_blob_writes along with coltage column plan for instance %s\n", config->name);
			ret = 1;
		}

		if (ret != 0) {
			goto out;
		}

		VL_DEBUG_MSG_2("Using voltage column plan for mysql for instance %s\n", config->name);
	}
	else {
		VL_MSG_ERR("BUG: Reached end of colplan name tests in mysql for instance %s\n", config->name);
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
			VL_MSG_ERR("Could not parse mysql_port for instance %s\n", config->name);
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
		VL_MSG_ERR ("mysql_user or mysql_password not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_table == NULL) {
		VL_MSG_ERR ("mysql_table not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_server == NULL) {
		VL_MSG_ERR ("mysql_server not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	if (data->mysql_db == NULL) {
		VL_MSG_ERR ("mysql_db not correctly set for instance %s.\n", config->name);
		ret = 1;
	}

	// DROP UNKNOWN MESSAGES
	int yesno = 0;
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_drop_unknown_messages") == RRR_SETTING_PARSE_ERROR) {
		VL_MSG_ERR ("mysql: Could not understand argument mysql_drop_unknown_messages of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->drop_unknown_messages = (yesno == 0 || yesno == 1 ? yesno : 0);

	// NO TAGGING
	yesno = 0;
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_no_tagging") == RRR_SETTING_PARSE_ERROR) {
		VL_MSG_ERR ("mysql: Could not understand argument mysql_no_tagging of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->no_tagging = (yesno == 0 || yesno == 1 ? yesno : 0);

	// ADD TIMESTAMP COL
	if (rrr_instance_config_check_yesno (&yesno, config, "mysql_add_timestamp_col") == RRR_SETTING_PARSE_ERROR) {
		VL_MSG_ERR ("mysql: Could not understand argument mysql_add_timestamp_col of instance '%s', please specify 'yes' or 'no'\n",
				config->name
		);
		ret = 1;
	}
	data->add_timestamp_col = (yesno == 0 || yesno == 1 ? yesno : 0);

	// MYSQL PORT
	if (mysql_parse_port(data, config) != 0) {
		VL_MSG_ERR("Error while parsing mysql port for instance %s\n", config->name);
		ret = 1;
	}

	// COLUMN PLAN AND COLUMN LISTS
	if (mysql_parse_column_plan(data, config) != 0) {
		VL_MSG_ERR("Error in mysql column plan for instance %s\n", config->name);
		ret = 1;
	}

	return ret;
}

int poll_callback_ip(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;

	VL_DEBUG_MSG_3 ("mysql: Result from buffer (ip): size %lu\n", size);

	fifo_buffer_write(&mysql_data->input_buffer, data, size);

	return 0;
}

int poll_callback_local(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	struct ip_buffer_entry *entry = NULL;
	int ret = 0;

	(void)(size);

	if (ip_buffer_entry_new(&entry, sizeof(*reading) - 1 + reading->length, NULL, 0, reading) != 0) {
		VL_MSG_ERR("Could not allocate ip buffer entry in poll_callback_local\n");
		ret = 1;
		goto out;
	}

	fifo_buffer_write(&mysql_data->input_buffer, (char*) entry, sizeof(*entry));

	reading = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(reading);
	return ret;
}

// Poll request from other local modules
int mysql_poll_delete_local (RRR_MODULE_POLL_SIGNATURE) {
	struct mysql_data *mysql_data = data->private_data;

	return fifo_read_clear_forward(&mysql_data->output_buffer_local, NULL, callback, poll_data, wait_milliseconds);
}

// Poll request from other IP-capable modules
int mysql_poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct mysql_data *mysql_data = data->private_data;

	return fifo_read_clear_forward(&mysql_data->output_buffer_ip, NULL, callback, poll_data, wait_milliseconds);
}

int mysql_save(struct process_entries_data *data, struct ip_buffer_entry *entry) {
	if (data->data->mysql_connected != 1) {
		return 1;
	}

	struct mysql_data *mysql_data = data->data;
	struct vl_message *message = entry->message;

	// TODO : Don't default to old voltage/info-message, should have it's own class

	int is_unknown = 0;
	int colplan_index = COLUMN_PLAN_VOLTAGE;
	if (MSG_IS_MSG_ARRAY(message)) {
		if (!IS_COLPLAN_ARRAY(mysql_data)) {
			VL_MSG_ERR("Received an array message in mysql but array column plan is not being used\n");
			is_unknown = 1;
			goto out;
		}
		colplan_index = COLUMN_PLAN_ARRAY;
	}

	else if (!IS_COLPLAN_VOLTAGE(mysql_data)) {
		VL_MSG_ERR("Received a voltage message in mysql but voltage column plan is not being used. Class was %" PRIu32 ".\n", message->class);
		is_unknown = 1;
		goto out;
	}
	else {
		VL_MSG_ERR("Unknown message class/type %u/%u received in mysql_save", message->class, message->type);
		is_unknown = 1;
		goto out;
	}

	out:
	if (is_unknown) {
		return 1;
	}

	return column_configurators[colplan_index].bind_and_execute(data, entry);
}

int process_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct process_entries_data *process_data = callback_data->private_data;
	struct instance_thread_data *thread_data = callback_data->source;
	struct mysql_data *mysql_data = process_data->data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;
	struct vl_message *message = entry->message;

	update_watchdog_time(thread_data->thread);

	int err = 0;

	VL_DEBUG_MSG_3 ("mysql: processing message with timestamp %" PRIu64 "\n", message->timestamp_from);

	int mysql_save_res = mysql_save (process_data, entry);

	if (mysql_save_res != 0) {
		if (mysql_data->drop_unknown_messages) {
			VL_MSG_ERR("mysql instance %s dropping message\n", INSTANCE_D_NAME(thread_data));
			free(entry);
		}
		else {
			// Put back in buffer
			VL_DEBUG_MSG_3 ("mysql: Putting message with timestamp %" PRIu64 " back into the buffer\n", message->timestamp_from);
			fifo_buffer_write(&mysql_data->input_buffer, data, size);
			err = 1;
		}
	}
	else {
		// Tag message as saved to sender
		VL_DEBUG_MSG_3 ("mysql: generate tag message for entry with timestamp %" PRIu64 "\n", message->timestamp_from);
		message->type = MSG_TYPE_TAG;
		message->length = 0;
		message->network_size = sizeof(*message) - 1;
		entry->data_length = sizeof(*message) - 1;
		if (entry->addr_len == 0) {
			// Message does not contain IP information which means it originated locally
			fifo_buffer_write(&mysql_data->output_buffer_local, data, size);
		}
		else {
			fifo_buffer_write(&mysql_data->output_buffer_ip, data, size);
		}
	}

	return err;
}

void close_mysql_stmt(void *arg) {
	mysql_stmt_close(arg);
}

int process_entries (struct instance_thread_data *thread_data) {
	struct mysql_data *data = thread_data->private_data;
	struct fifo_callback_args poll_data;

	if (connect_to_mysql(data) != 0) {
		return 1;
	}

	int ret = 0;

	MYSQL_STMT *stmt = mysql_stmt_init(&data->mysql);

	pthread_cleanup_push(close_mysql_stmt, stmt);

	struct process_entries_data process_data;

	process_data.data = data;
	process_data.stmt = stmt;

	poll_data.private_data = &process_data;
	poll_data.source = thread_data;

	if (!COLPLAN_OK(data)) {
		VL_MSG_ERR("BUG: Mysql colplan was out of range in process_entries\n");
		exit (EXIT_FAILURE);
	}

	char query[RRR_MYSQL_SQL_MAX];
	column_configurators[data->colplan].create_sql(query, RRR_MYSQL_SQL_MAX, data);

	if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
		VL_MSG_ERR ("mysql: Failed to prepare statement: Error: %s\n",
				mysql_error(&data->mysql));
		mysql_disconnect(data);
		goto out;
	}

	if (VL_DEBUGLEVEL_3) {
		if (fifo_buffer_get_entry_count(&data->input_buffer) > 0) {
			VL_MSG("mysql SQL: %s\n", query);
		}
	}

	ret = fifo_read_clear_forward(&data->input_buffer, NULL, process_callback, &poll_data, 50);
	if (ret != 0) {
		VL_MSG_ERR ("mysql: Error when saving entries to database\n");
		mysql_disconnect(data);
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static void *thread_entry_mysql (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data) != 0) {
		VL_MSG_ERR("Could not initalize data in mysql instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("mysql thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	poll_collection_init(&poll);
	poll_collection_init(&poll_ip);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(stop_mysql, data);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (start_mysql(data) != 0) {
		goto out_message;
	}

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
			goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP);

	int err = 0;
	RRR_SENDER_LOOP(sender,thread_data->init_data.senders) {
		int delete_has = poll_collection_has(&poll, sender->sender->thread_data);
		int delete_ip_has = poll_collection_has(&poll_ip, sender->sender->thread_data);

		if (delete_has + delete_ip_has == 2) {
			VL_DEBUG_MSG_1("Sender %s for mysql instance %s has both delete and delete_ip poll functions, preferring IP\n",
					INSTANCE_M_NAME(sender->sender), INSTANCE_D_NAME(thread_data));
			poll_collection_remove(&poll, sender->sender->thread_data);
		}
		else if (delete_has + delete_ip_has == 0) {
			VL_MSG_ERR("Sender %s for mysql instance %s did not have delete_ip or delete poll functions\n",
					INSTANCE_M_NAME(sender->sender), INSTANCE_D_NAME(thread_data));
			err = 1;
		}
	}
	if (err) {
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("mysql started thread %p\n", thread_data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

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
	VL_DEBUG_MSG_1 ("Thread mysql %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
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

static struct module_operations module_operations = {
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

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->special_module_operations = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy mysql module\n");
	rrr_mysql_library_end();
}
