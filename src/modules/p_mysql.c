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

#include "common/ip.h"
#include "../lib/buffer.h"
#include "../modules.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"

// Should not be smaller than module max
#define VL_MYSQL_MAX_SENDERS VL_MODULE_MAX_SENDERS

#define VL_MYSQL_DEFAULT_SERVER "localhost"
#define VL_MYSQL_DEFAULT_PORT 5506

// TODO : Fix URI support

struct mysql_data {
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	MYSQL mysql;
	int mysql_initialized;
	int mysql_connected;
	const char *mysql_server;
	unsigned int mysql_port;
	const char *mysql_user;
	const char *mysql_password;
//	const char *mysql_uri;
	const char *mysql_db;
	const char *mysql_table;
};

void data_init(struct mysql_data *data) {
	memset (data, '\0', sizeof(*data));
	fifo_buffer_init (&data->input_buffer);
	fifo_buffer_init (&data->output_buffer);
}

void data_cleanup(void *arg) {
	struct mysql_data *data = arg;
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
			fprintf (stderr, "Could not initialize MySQL\n");
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
			fprintf(stderr, "mysql: Failed to connect to database: Error: %s\n",
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
//	const char *mysql_uri = NULL;

	const char *tmp;

	if ((tmp = cmd_get_value(cmd, "mysql_server", 0)) != NULL ) {
		mysql_server = tmp;
	}

	int port = -1;
	if ((tmp = cmd_get_value(cmd, "mysql_port", 0)) != NULL) {
		if (cmd_convert_integer_10(cmd, tmp, &port) != 0 || port < 0) {
			fprintf (stderr, "Syntax error in mysql_port argument\n");
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

/*	if ((tmp = cmd_get_value(cmd, "mysql_uri", 0)) != NULL) {
		printf ("mysql: Using URI for connecting to server\n");
		mysql_uri = tmp;
	}
	else*/ if (mysql_user == NULL || mysql_password == NULL) {
		fprintf (stderr, "mysql_user or mysql_password not correctly set.\n");
		return 1;
	}

	if (mysql_table == NULL || mysql_db == NULL) {
		fprintf (stderr, "mysql_db or mysql_table not correctly set.\n");
		return 1;
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

int mysql_save(struct mysql_data *data, struct ip_buffer_entry *entry) {
	if (data->mysql_connected != 1) {
		return 1;
	}
	return 1;
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct mysql_data *mysql_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	printf ("mysql: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&mysql_data->input_buffer, data, size);

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

int process_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct mysql_data *mysql_data = callback_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	int err = 0;

	if (mysql_save (mysql_data, entry) != 0) {
		// Put back in buffer
		fifo_buffer_write(&mysql_data->input_buffer, data, size);
		err = 1;
	}
	else {
		// Free or something
		free(data);
	}

	return err;
}

int process_entries (struct mysql_data *data) {
	struct fifo_callback_args poll_data;
	poll_data.private_data = data;
	poll_data.source = NULL;

	if (connect_to_mysql(data) != 0) {
		return 1;
	}

	int ret = fifo_read_clear_forward(&data->input_buffer, NULL, process_callback, &poll_data);

	if (ret != 0) {
		fprintf (stderr, "mysql: Error when saving entries to database\n");
		mysql_disconnect(data);
	}

	return ret;
}

static void *thread_entry_mysql(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct mysql_data *data = thread_data->private_data = thread_data->private_memory;

	printf ("mysql thread data is %p, size of private data: %lu\n", thread_data, sizeof(*data));

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
		fprintf (stderr, "Too many senders for mysql module, max is %i\n", VL_MYSQL_MAX_SENDERS);
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

	for (int i = 0; i < senders_count; i++) {
		printf ("mysql: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete_ip;

		if (poll[i] == NULL) {
			fprintf (stderr, "mysql cannot use this sender, lacking poll_delete_ip function.\n");
			goto out_message;
		}
	}

	printf ("mysql started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for mysql processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				fprintf (stderr, "mysql module received error from poll function\n");
				err = 1;
				break;
			}
		}

		process_entries(data);

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
	printf ("Thread mysql %p exiting\n", thread_data->thread);

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
	printf ("Destroy mysql module\n");
	mysql_library_end();
}

