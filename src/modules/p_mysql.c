/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include "../lib/types.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/ip.h"
#include "../modules.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_MYSQL_MAX_SENDERS VL_MODULE_MAX_SENDERS

#define VL_MYSQL_DEFAULT_SERVER "localhost"
#define VL_MYSQL_DEFAULT_PORT 5506

#define VL_MYSQL_BIND_MAX CMD_ARGUMENT_MAX
#define VL_MYSQL_SQL_MAX 1024

#define PASTE(x,y) x ## _ ## y

// TODO : Fix URI support

struct mysql_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	MYSQL mysql;
	MYSQL_BIND bind[VL_MYSQL_BIND_MAX];
	int mysql_initialized;
	int mysql_connected;
	const char *mysql_server;
	unsigned int mysql_port;
	const char *mysql_user;
	const char *mysql_password;
//	const char *mysql_uri;
	const char *mysql_db;
	const char *mysql_table;
	int no_tagging;
	int colplan;
	int add_timestamp_col;
	const char *mysql_columns[VL_MYSQL_BIND_MAX];
	cmd_arg_count mysql_special_columns_count;
	const char *mysql_special_columns[VL_MYSQL_BIND_MAX];
	char *mysql_special_values[VL_MYSQL_BIND_MAX]; // Can't do const because of MySQL bind
	const char *mysql_columns_blob_writes[VL_MYSQL_BIND_MAX]; // Force blob write method
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
	strcmp(str,PASTE(COLUMN_PLAN_NAME,name)) == 0
#define COLUMN_PLAN_INDEX(name) \
	PASTE(COLUMN_PLAN,name)

int mysql_columns_check_blob_write(const struct mysql_data *data, const char *col_1) {
	for (int i = 0; i < VL_MYSQL_BIND_MAX; i++) {
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

	struct vl_message *message = &entry->data.message;

	VL_DEBUG_MSG_2 ("mysql: Saving message type %" PRIu32 " with timestamp %" PRIu64 "\n",
			message->type, message->timestamp_to);

	/* Attempt to make an integer value if possible */
	unsigned long long int value = message->data_numeric;
	if (value == 0 && message->length > 0) {
		char *pos;
		value = strtoull(message->data, &pos, 10);
		if (errno == ERANGE || pos == message->data) {
			value = 0;
		}
	}

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
	bind[5].buffer = &value;
	bind[5].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[5].is_unsigned = 1;

	// Message
	unsigned long message_length = message->length;
	bind[6].buffer = message->data;
	bind[6].length = &message_length;
	bind[6].buffer_type = MYSQL_TYPE_STRING;

	// Message length
	bind[7].buffer = &message->length;
	bind[7].buffer_type = MYSQL_TYPE_LONG;
	bind[7].is_unsigned = 1;

	return mysql_bind_and_execute(data);
}

int colplan_array_create_sql(char *target, unsigned int target_size, struct mysql_data *data) {
	static const int query_base_max = VL_MYSQL_SQL_MAX + ((CMD_ARGUMENT_MAX + 1) * CMD_ARGUMENT_SIZE * 2);
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
	for (int i = 0; i < VL_MYSQL_BIND_MAX && data->mysql_columns[i] != NULL; i++) {
		int len = strlen(data->mysql_columns[i]);

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
	for (int i = 0; i < data->mysql_special_columns_count; i++) {
		int len = strlen(data->mysql_special_columns[i]);

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

//	VL_DEBUG_MSG_3("mysql array SQL: %s\n", query_base);

	// Double check length
	if (strlen(query_base) > query_base_max) {
		VL_MSG_ERR("BUG: query_base was too long in colplan_array_create_sql");
		exit(EXIT_FAILURE);
	}

	if (target_size < strlen(query_base)) {
		VL_MSG_ERR("Mysql query was too long in colplan_array_create_sql\n");
		return 1;
	}

	sprintf(target, "%s", query_base);

	return 0;
}

void free_collection(void *data) {
	if (data != NULL) {
		rrr_types_destroy_data(data);
	}
}

int colplan_array_bind_execute(struct process_entries_data *data, struct ip_buffer_entry *entry) {
	int res = 0;

	struct rrr_data_collection *collection = NULL;

	if (rrr_types_message_to_collection(&collection, &entry->data.message) != 0) {
		VL_MSG_ERR("Could not convert array message to data collection in mysql\n");
		return 1;
	}

	pthread_cleanup_push(free_collection, collection);

	struct rrr_type_definition_collection *definitions = &collection->definitions;
	MYSQL_BIND *bind = data->data->bind;

	if (definitions->count + data->data->add_timestamp_col + data->data->mysql_special_columns_count > VL_MYSQL_BIND_MAX) {
		VL_MSG_ERR("Number of types exceeded maximum (%lu vs %i)\n", definitions->count + data->data->add_timestamp_col + data->data->mysql_special_columns_count, VL_MYSQL_BIND_MAX);
		res = 1;
		goto out_cleanup;
	}

	unsigned long string_lengths[VL_MYSQL_BIND_MAX];
	memset(string_lengths, '\0', sizeof(string_lengths));

	rrr_def_count bind_pos;
	for (bind_pos = 0; bind_pos < definitions->count; bind_pos++) {
		struct rrr_type_definition *definition = &definitions->definitions[bind_pos];

		if (definition->array_size > 1) {
			// Arrays must be inserted as blobs. They might be shorter than the
			// maximum length, the input definition decides.
			string_lengths[bind_pos] = definition->length * definition->array_size;
			bind[bind_pos].buffer = collection->data[bind_pos];
			bind[bind_pos].length = &string_lengths[bind_pos];
			bind[bind_pos].buffer_type = MYSQL_TYPE_BLOB;
		}
		else if (RRR_TYPE_IS_BLOB(definition->type) || mysql_columns_check_blob_write(data->data, data->data->mysql_columns[bind_pos])) {
			if (definition->length > definition->max_length) {
				VL_MSG_ERR("Type length defined for column with index %ul exceeds maximum of %ul when binding with mysql\n",
						definition->length, definition->max_length);
				res = 1;
				goto out_cleanup;
			}

			string_lengths[bind_pos] = definition->length;
			bind[bind_pos].buffer = collection->data[bind_pos];
			bind[bind_pos].length = &string_lengths[bind_pos];
			bind[bind_pos].buffer_type = MYSQL_TYPE_STRING;
		}
		else if (RRR_TYPE_IS_64(definition->type)) {
			// TODO : Support signed
			bind[bind_pos].buffer = collection->data[bind_pos];
			bind[bind_pos].buffer_type = MYSQL_TYPE_LONGLONG;
			bind[bind_pos].is_unsigned = 1;
		}
		else {
			VL_MSG_ERR("Unkown type %ul when binding with mysql\n", definition->type);
			res = 1;
			goto out_cleanup;
		}
	}

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

	for (rrr_def_count i = 0; i < definitions->count; i++) {
		struct rrr_type_definition *definition = &definitions->definitions[i];

		if (RRR_TYPE_IS_BLOB(definition->type)) {
			if (string_lengths[i] != definition->length) {
				VL_MSG_ERR("Warning: Only %lu bytes of %u where saved to mysql for column with index %u\n",
						string_lengths[i], definition->length, i);
			}
		}
	}

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

void data_init(struct mysql_data *data) {
	memset (data, '\0', sizeof(*data));
	fifo_buffer_init (&data->input_buffer);
	fifo_buffer_init (&data->output_buffer);
}

void data_cleanup(void *arg) {
	struct mysql_data *data = arg;
	for (rrr_def_count i = 0; i < VL_MYSQL_BIND_MAX; i++) {
		if (data->mysql_special_values[i] != NULL) {
			free(data->mysql_special_values[i]);
		}
		data->mysql_special_values[i] = NULL;
	}
	fifo_buffer_invalidate (&data->input_buffer);
	fifo_buffer_invalidate (&data->output_buffer);
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

int mysql_parse_cmd(struct mysql_data *data, struct cmd_data *cmd) {
	const char *mysql_server = VL_MYSQL_DEFAULT_SERVER;
	unsigned int mysql_port = VL_MYSQL_DEFAULT_PORT;
	const char *mysql_user = NULL;
	const char *mysql_password = NULL;
	const char *mysql_db = NULL;
	const char *mysql_table = NULL;
	const char *mysql_no_tagging = NULL;
	const char *mysql_colplan = NULL;
	const char *mysql_add_timestamp_col = NULL;
	const char *mysql_special_columns = NULL;
	const char *mysql_columns_blob_writes = NULL;
//	const char *mysql_uri = NULL;

	const char *tmp;

	if ((tmp = cmd_get_value(cmd, "mysql_server", 0)) != NULL ) {
		mysql_server = tmp;
	}

	int port = -1;
	if ((tmp = cmd_get_value(cmd, "mysql_port", 0)) != NULL) {
		if (cmd_convert_integer_10(cmd, tmp, &port) != 0 || port < 0) {
			VL_MSG_ERR ("Syntax error in mysql_port argument\n");
			return 1;
		}
	}
	if ((tmp = cmd_get_value(cmd, "mysql_user", 0)) != NULL ) {
		mysql_user = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_password", 0)) != NULL ) {
		mysql_password = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_db", 0)) != NULL ) {
		mysql_db = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_table", 0)) != NULL ) {
		mysql_table = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_no_tagging", 0)) != NULL ) {
		mysql_no_tagging = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_colplan", 0)) != NULL ) {
		mysql_colplan = tmp;
	}
	if ((tmp = cmd_get_value(cmd, "mysql_add_timestamp_col", 0)) != NULL ) {
		mysql_add_timestamp_col = tmp;
	}

	// TODO: Connect with URI
/*	if ((tmp = cmd_get_value(cmd, "mysql_uri", 0)) != NULL) {
		VL_DEBUG_MSG_1 ("mysql: Using URI for connecting to server\n");
		mysql_uri = tmp;
	}
	else*/ if (mysql_user == NULL || mysql_password == NULL) {
		VL_MSG_ERR ("mysql_user or mysql_password not correctly set.\n");
		return 1;
	}

	if (mysql_table == NULL || mysql_db == NULL) {
		VL_MSG_ERR ("mysql_db or mysql_table not correctly set.\n");
		return 1;
	}

	data->no_tagging = 0;
	if (mysql_no_tagging != NULL) {
		int yesno;
		if (cmdline_check_yesno(cmd, mysql_no_tagging, &yesno) != 0) {
			VL_MSG_ERR ("mysql: Could not understand argument mysql_no_tagging ('%s'), please specify 'yes' or 'no'\n",
					mysql_no_tagging);
			return 1;
		}
		data->no_tagging = yesno;
	}

	data->add_timestamp_col = 0;
	if (mysql_add_timestamp_col != NULL) {
		int yesno;
		if (cmdline_check_yesno(cmd, mysql_add_timestamp_col, &yesno) != 0) {
			VL_MSG_ERR ("mysql: Could not understand argument mysql_add_timestamp_col ('%s'), please specify 'yes' or 'no'\n",
					mysql_add_timestamp_col);
			return 1;
		}
		data->add_timestamp_col = yesno;
	}

	if (mysql_colplan == NULL) {
		mysql_colplan = COLUMN_PLAN_NAME_VOLTAGE;
		VL_MSG_ERR("Warning: No mysql_colplan set, defaulting to voltage\n");
	}

	if ((tmp = cmd_get_value(cmd, "mysql_special_columns", 0)) != NULL ) {
		cmd_arg_count i = 0;
		while (1) {
			const char *col = cmd_get_subvalue(cmd, "mysql_special_columns", 0, i);
			const char *val = cmd_get_subvalue(cmd, "mysql_special_columns", 0, i + 1);

			if (col == NULL || *col == '\0') {
				break;
			}
			else if (val == NULL || *val == '\0') {
				VL_MSG_ERR ("mysql: Missing value for special column %s", col);
				return 1;
			}
			else if (data->mysql_special_columns_count >= VL_MYSQL_BIND_MAX) {
				VL_MSG_ERR("BUG: Too many mysql special column arguments (%lu vs %i)\n",
						data->mysql_special_columns_count, VL_MYSQL_BIND_MAX);
				exit (EXIT_FAILURE);
			}

			data->mysql_special_columns[data->mysql_special_columns_count] = col;

			data->mysql_special_values[data->mysql_special_columns_count] = malloc(strlen(val) + 1);
			if (data->mysql_special_values[data->mysql_special_columns_count] == NULL) {
				VL_MSG_ERR("Could not allocate memory for mysql special column value\n");
				return 1;
			}
			sprintf(data->mysql_special_values[data->mysql_special_columns_count], "%s", val);
			data->mysql_special_columns_count += 1;

			i += 2;
		}
	}

	if ((tmp = cmd_get_value(cmd, "mysql_columns_blob_writes", 0)) != NULL ) {
		cmd_arg_count i = 0;
		while (1) {
			const char *col = cmd_get_subvalue(cmd, "mysql_columns_blob_writes", 0, i);

			if (col == NULL || *col == '\0') {
				break;
			}

			data->mysql_columns_blob_writes[i] = col;

			i++;
		}
	}

	if (COLUMN_PLAN_MATCH(mysql_colplan,ARRAY)) {
		data->colplan = COLUMN_PLAN_INDEX(ARRAY);

		cmd_arg_count i = 0;
		while (1) {
			const char *res = cmd_get_subvalue(cmd, "mysql_columns", 0, i);
			if (res == NULL || *res == '\0') {
				break;
			}
			else if (i >= VL_MYSQL_BIND_MAX) {
				VL_MSG_ERR("BUG: Too many mysql column arguments (%lu vs %i)\n", i, VL_MYSQL_BIND_MAX);
				exit (EXIT_FAILURE);
			}
			data->mysql_columns[i] = res;
			i++;
		}

		VL_DEBUG_MSG_2("%lu mysql columns specified for array column plan", i);

		if (data->mysql_columns[0] == NULL) {
			VL_MSG_ERR("No columns specified in mysql_columns; needed when using array column plan\n");
			return 1;
		}

		int all_was_ok = 1;
		for (int i = 0; i < VL_MYSQL_BIND_MAX; i++) {
			const char *col_1 = data->mysql_columns_blob_writes[i];

			if (col_1 == NULL) {
				break;
			}

			int was_ok = 0;
			for (int j = 0; j < VL_MYSQL_BIND_MAX; j++) {
				const char *col_2 = data->mysql_columns[j];
				if (strcmp(col_1, col_2) == 0) {
					was_ok = 1;
					break;
				}
			}

			if (was_ok == 0) {
				VL_MSG_ERR("Column %s specified in mysql_columns_blob_writes but not in mysql_columns\n");
				all_was_ok = 0;
			}
		}

		if (all_was_ok != 1) {
			return 1;
		}
	}
	else if (COLUMN_PLAN_MATCH(mysql_colplan,VOLTAGE)) {
		data->colplan = COLUMN_PLAN_INDEX(VOLTAGE);

		if (data->add_timestamp_col != 0) {
			VL_MSG_ERR("Cannot use mysql_add_timestamp_col=yes along with voltage column plan\n");
			return 1;
		}

		if (data->mysql_special_columns > 0) {
			VL_MSG_ERR("Cannot use mysql_special_columns along with voltage column plan\n");
			return 1;
		}

		if (data->mysql_columns_blob_writes[0] != NULL) {
			VL_MSG_ERR("Cannot use mysql_columns_blob_writes along with coltage column plan\n");
			return 1;
		}

		VL_DEBUG_MSG_2("Using voltage column plan for mysql");
	}
	else {
		VL_MSG_ERR("BUG: Reached end of colplan name tests in mysql");
		exit(EXIT_FAILURE);
	}

	data->mysql_server = mysql_server;
	data->mysql_port = mysql_port;
	data->mysql_user = mysql_user;
	data->mysql_password = mysql_password;
	data->mysql_db = mysql_db;
	data->mysql_table = mysql_table;
//	data->mysql_uri = mysql_uri;

	return 0;
}

int poll_callback_ip(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	VL_DEBUG_MSG_3 ("mysql: Result from buffer (ip): size %lu\n", size);

	fifo_buffer_write(&mysql_data->input_buffer, data, size);

	return 0;
}

int poll_callback_local(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	// Convert message to IP buffer entry
	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	memset(entry, '\0', sizeof(*entry));
	memcpy(&entry->data.message, reading, sizeof(entry->data.message));
	free (reading);

	VL_DEBUG_MSG_3 ("mysql: Result from buffer (local): size %lu\n", size);

	fifo_buffer_write(&mysql_data->input_buffer, (char*) entry, sizeof(*entry));

	return 0;
}

// Poll request from other modules
int mysql_poll_delete_ip (
	struct module_thread_data *thread_data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *caller_data
) {
	struct mysql_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->output_buffer, NULL, callback, caller_data);
}

int mysql_save(struct process_entries_data *data, struct ip_buffer_entry *entry) {
	if (data->data->mysql_connected != 1) {
		return 1;
	}

	struct mysql_data *mysql_data = data->data;
	struct vl_message *message = &entry->data.message;

	// TODO : Don't default to old voltage/info-message, should have it's own class

	int colplan_index = COLUMN_PLAN_VOLTAGE;
	if (MSG_IS_MSG_ARRAY(message)) {
		if (!IS_COLPLAN_ARRAY(mysql_data)) {
			VL_MSG_ERR("Received an array message in mysql but array column plan is not being used\n");
			return 1;
		}
		colplan_index = COLUMN_PLAN_ARRAY;
	}
	else if (!IS_COLPLAN_VOLTAGE(mysql_data)) {
		VL_MSG_ERR("Received a voltage message in mysql but voltage column plan is not being used\n");
		return 1;
	}
	else {
		VL_MSG_ERR("Unknown message class/type %u/%u received in mysql_save", message->class, message->type);
		return 1;
	}

	return column_configurators[colplan_index].bind_and_execute(data, entry);
}

int process_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct process_entries_data *process_data = callback_data->private_data;
	struct module_thread_data *thread_data = callback_data->source;
	struct mysql_data *mysql_data = process_data->data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	update_watchdog_time(thread_data->thread);

	int err = 0;

	if (message_fix_endianess (&entry->data.message) != 0) {
		VL_MSG_ERR("mysql: Endianess could not be determined for message\n");
		fifo_buffer_write(&mysql_data->input_buffer, data, size);
		err = 1;
		goto out;
	}

	VL_DEBUG_MSG_3 ("mysql: processing message with timestamp %" PRIu64 "\n", entry->data.message.timestamp_from);

	if (mysql_save (process_data, entry) != 0) {
		// Put back in buffer
		VL_DEBUG_MSG_3 ("mysql: Putting message with timestamp %" PRIu64 " back into the buffer\n", entry->data.message.timestamp_from);
		fifo_buffer_write(&mysql_data->input_buffer, data, size);
		err = 1;
	}
	else {
		// Tag message as saved to sender
		struct vl_message *message = &entry->data.message;
		VL_DEBUG_MSG_3 ("mysql: generate tag message for entry with timestamp %" PRIu64 "\n", message->timestamp_from);
		message->type = MSG_TYPE_TAG;
		fifo_buffer_write(&mysql_data->output_buffer, data, size);
	}

	out:

	return err;
}

void close_mysql_stmt(void *arg) {
	mysql_stmt_close(arg);
}

int process_entries (struct module_thread_data *thread_data) {
	struct mysql_data *data = thread_data->private_data;
	struct fifo_callback_args poll_data;

	if (connect_to_mysql(data) != 0) {
		return 1;
	}

	int ret;

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

	char query[VL_MYSQL_SQL_MAX];
	column_configurators[data->colplan].create_sql(query, VL_MYSQL_SQL_MAX, data);

	if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
		VL_MSG_ERR ("mysql: Failed to prepare statement: Error: %s\n",
				mysql_error(&data->mysql));
		mysql_disconnect(data);
		goto out;
	}

	ret = fifo_read_clear_forward(&data->input_buffer, NULL, process_callback, &poll_data);
	if (ret != 0) {
		VL_MSG_ERR ("mysql: Error when saving entries to database\n");
		mysql_disconnect(data);
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

static void *thread_entry_mysql(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;

	VL_DEBUG_MSG_1 ("mysql thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

	data_init(data);

	pthread_cleanup_push(stop_mysql, data);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (start_mysql(data) != 0) {
		goto out_message;
	}

	if (mysql_parse_cmd(data, start_data->cmd) != 0) {
		goto out_message;
	}

	if (senders_count > VL_MYSQL_MAX_SENDERS) {
		VL_MSG_ERR ("Too many senders for mysql module, max is %i\n", VL_MYSQL_MAX_SENDERS);
		goto out_message;
	}


	int (*poll[VL_MYSQL_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *poll_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);

#define POLL_TYPE_IP 1
#define POLL_TYPE_LOCAL 2

	int poll_types[VL_MYSQL_MAX_SENDERS];

	for (int i = 0; i < senders_count; i++) {
		VL_DEBUG_MSG_1 ("mysql: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete_ip;
		poll_types[i] = POLL_TYPE_IP;

		if (poll[i] == NULL) {
			poll[i] = thread_data->senders[i]->module->operations.poll_delete;
			poll_types[i] = POLL_TYPE_LOCAL;
		}

		if (poll[i] == NULL) {
			VL_MSG_ERR ("mysql cannot use sender '%s', lacking poll_delete_ip and poll_delete function.\n",
					thread_data->senders[i]->module->name);
			goto out_message;
		}
	}

	VL_DEBUG_MSG_1 ("mysql started thread %p\n", thread_data);
	if (senders_count == 0) {
		VL_MSG_ERR ("Error: Sender was not set for mysql processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res;
			if (poll_types[i] == POLL_TYPE_IP) {
				res = poll[i](thread_data->senders[i], poll_callback_ip, &poll_data);
			}
			else if (poll_types[i] == POLL_TYPE_LOCAL) {
				res = poll[i](thread_data->senders[i], poll_callback_local, &poll_data);
			}
			else {
				VL_MSG_ERR("mysql: Bug: Unknown poll type %i\n", poll_types[i]);
				exit (EXIT_FAILURE);
			}
			if (!(res >= 0)) {
				VL_MSG_ERR ("mysql module received error from poll function\n");
				err = 1;
				break;
			}
		}

		process_entries(thread_data);

		if (data->mysql_connected != 1) {
			// Sleep a little longer if we can't connect to the server
			usleep (1000000);
		}

		if (err != 0) {
			break;
		}
		usleep (20000); // 20 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread mysql %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_mysql,
		NULL,
		NULL,
		NULL,
		mysql_poll_delete_ip
};

static const char *module_name = "mysql";

__attribute__((constructor)) void load() {
	// Has to be done here for thread-safety
	mysql_library_init(0, NULL, NULL);
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(struct module_dynamic_data *data) {
	VL_DEBUG_MSG_1 ("Destroy mysql module\n");
	mysql_library_end();
}
