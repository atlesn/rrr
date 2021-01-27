/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../log.h"
#include "msgdb_common.h"
#include "msgdb_server.h"
#include "../read.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_client.h"
#include "../string_builder.h"
#include "../rrr_strerror.h"
#include "../helpers/nullsafe_str.h"

struct rrr_msgdb_server {
	char *directory;
	int fd;
	struct rrr_socket_client_collection clients;
};

int rrr_msgdb_server_new (
		struct rrr_msgdb_server **result,
		const char *directory,
		const char *socket
) {
	int ret = 0;

	struct rrr_msgdb_server *server = NULL;
	int fd = 0;

	if ((ret = rrr_socket_unix_create_bind_and_listen (
		&fd,
		"msgdb_server",
		socket,
		10, // Number of clients
		1,  // Do nonblock
		0,  // No mkstemp
		1   // Do unlink if exists
	)) != 0) {
		RRR_MSG_0("Failed to create listening socket '%s' in message database server\n", socket);
		goto out;
	}

	if ((server = malloc(sizeof(*server))) == NULL) {
		RRR_MSG_0("Could not allocate memory for server in rrr_msgdb_server_new\n");
		ret = 1;
		goto out_close;
	}

	memset(server, '\0', sizeof(*server));

	if ((server->directory = strdup(directory)) == NULL) {
		RRR_MSG_0("Could not allocate memory for directory in rrr_msgdb_server_new\n");
		ret = 1;
		goto out_free;
	}

	if ((ret = rrr_socket_client_collection_init(&server->clients, fd, "msgdb_server")) != 0) {
		goto out_free_directory;
	}

	server->fd = fd;

	*result = server;

	goto out;
	out_free_directory:
		free(server->directory);
	out_free:
		free(server);
	out_close:
		rrr_socket_close(fd);
	out:
		return ret;
}

void rrr_msgdb_server_destroy (
		struct rrr_msgdb_server *server
) {
	RRR_FREE_IF_NOT_NULL(server->directory);
	rrr_socket_close(server->fd);
	rrr_socket_client_collection_clear(&server->clients);
	free(server);
}

struct rrr_msgdb_server_client {
	int fd;
};

static int __rrr_msgdb_server_client_new (
		struct rrr_msgdb_server_client **target,
		int fd,
		void *arg
) {
	(void)(arg);

	*target = NULL;

	struct rrr_msgdb_server_client *client = malloc(sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_msgdb_server_client_new\n");
		return 1;
	}

	memset (client, '\0', sizeof(*client));

	client->fd = fd;

	*target = client;

	return 0;
}

static int __rrr_msgdb_server_client_new_void (
		void **target,
		int fd,
		void *arg
) {
	return __rrr_msgdb_server_client_new((struct rrr_msgdb_server_client **) target, fd, arg);
}

static void __rrr_msgdb_server_client_destroy (
		struct rrr_msgdb_server_client *client
) {
	free(client);
}

static void __rrr_msgdb_server_client_destroy_void (
		void *arg
) {
	return __rrr_msgdb_server_client_destroy(arg);
}

static int __rrr_msgdb_server_chdir (
		const char *directory
) {
	int ret = 0;

	if (mkdir(directory, 0777) != 0) {
		if (errno != EEXIST) {
			RRR_MSG_0("Could not create directory '%s' in message db server: %s\n",
				directory, rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}

	if (chdir(directory) != 0) {
		RRR_MSG_0("Could not change to directory '%s' in message db server: %s\n",
			directory, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	RRR_DBG_3("msgdb chdir '%s'\n", directory);

	out:
	return ret;
}

static int __rrr_msgdb_server_chdir_base (
		struct rrr_msgdb_server *server
) {
	return __rrr_msgdb_server_chdir(server->directory);
}

struct rrr_msgdb_server_path_iterate_callback_data {
	int (*callback)(const char *str, int is_last, void *arg);
	void *callback_arg;
	int is_last;
};

static int __rrr_msgdb_server_path_iterate_str_callback (
	const char *str,
	void *arg
) {
	struct rrr_msgdb_server_path_iterate_callback_data *callback_data = arg;
	return callback_data->callback(str, callback_data->is_last, callback_data->callback_arg);
}

static int __rrr_msgdb_server_path_iterate_split_callback (
		const struct rrr_nullsafe_str *str,
		int is_last,
		void *arg
) {
	struct rrr_msgdb_server_path_iterate_callback_data *callback_data = arg;

	callback_data->is_last = is_last;

	return rrr_nullsafe_str_with_raw_null_terminated_do (
		str,
		__rrr_msgdb_server_path_iterate_str_callback,
		arg
	);
}

static int __rrr_msgdb_server_path_iterate (
		const struct rrr_msg_msg *msg,
		int (*callback)(const char *str, int is_last, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_nullsafe_str *path_tmp = NULL;

	if ((ret = rrr_nullsafe_str_new_or_replace_raw(&path_tmp, MSG_TOPIC_PTR(msg), MSG_TOPIC_LENGTH(msg))) != 0) {
		goto out;
	}

	struct rrr_msgdb_server_path_iterate_callback_data callback_data = {
		callback,
		callback_arg,
		0
	};

	if ((ret = rrr_nullsafe_str_split(path_tmp, '/', __rrr_msgdb_server_path_iterate_split_callback, &callback_data)) != 0) {
		goto out;
	}

	out:
	rrr_nullsafe_str_destroy_if_not_null(&path_tmp);
	return ret;
}

struct rrr_msgdb_server_put_path_split_callback_data {
	const struct rrr_msg_msg *msg;
};

static int __rrr_msgdb_server_put_path_split_callback (
		const char *str,
		int is_last,
		void *arg
) {
	struct rrr_msgdb_server_put_path_split_callback_data *callback_data = arg;

	int ret = 0;
	int fd = 0;
	struct rrr_msg *msg_tmp = NULL;

	if (strlen(str) == 0) {
		if (is_last) {
			ret = 1;
			RRR_MSG_0("File component of a path in message db server had zero length (topic ends with a /), this is and error\n");
			goto out;
		}
		// Ignore empty path component
		goto out;
	}

	if (is_last) {
		if ((fd = rrr_socket_open(str, O_CREAT|O_TRUNC|O_RDWR, 0777, "msgdb_server_put", 0)) <= 0) {
			RRR_MSG_0("Could not open file '%s' for writing in message db server\n", str);
		}
		RRR_DBG_3("msgdb write to '%s' size %llu\n", str, (long long unsigned) MSG_TOTAL_SIZE(callback_data->msg));

		if ((msg_tmp = malloc(MSG_TOTAL_SIZE(callback_data->msg))) == NULL) {
			RRR_MSG_0("Could not allocate memory for temporary message in __rrr_msgdb_server_put_path_split_callback\n");
			ret = 1;
			goto out;
		}

		memcpy(msg_tmp, callback_data->msg, MSG_TOTAL_SIZE(callback_data->msg));

		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg_tmp);
		rrr_msg_checksum_and_to_network_endian(msg_tmp);

		// Note: Do not attempt to use size from the endian-converted message
		if (write(fd, msg_tmp, MSG_TOTAL_SIZE(callback_data->msg)) != MSG_TOTAL_SIZE(callback_data->msg)) {
			RRR_MSG_0("Could not write to file '%s' in message db server: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}
	else {
		if ((ret = __rrr_msgdb_server_chdir(str)) != 0) {
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	if (fd != 0) {
		rrr_socket_close(fd);
	}
	return ret;
}

static int __rrr_msgdb_server_put (
		struct rrr_msgdb_server *server,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	struct rrr_msgdb_server_put_path_split_callback_data callback_data = {
		msg
	};

	if ((ret = __rrr_msgdb_server_path_iterate (
			msg,
			__rrr_msgdb_server_put_path_split_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_send_msg_ack (
		int fd
) {
	RRR_DBG_3("msgdb fd %i send ACK\n", fd);

	return rrr_msgdb_common_ctrl_msg_send_blocking(fd, RRR_MSGDB_CTRL_F_ACK);
}

static int __rrr_msgdb_server_send_msg_nack (
		int fd
) {
	RRR_DBG_3("msgdb fd %i send NACK\n", fd);

	return rrr_msgdb_common_ctrl_msg_send_blocking(fd, RRR_MSGDB_CTRL_F_NACK);
}

static int __rrr_msgdb_server_read_msg_msg_callback (
		struct rrr_msg_msg **msg,
		void *private_data,
		void *arg
) {
	struct rrr_msgdb_server_client *client = private_data;
	struct rrr_msgdb_server *server = arg;

	int ret = 0;

	struct rrr_string_builder topic = {0};

	if ((ret = rrr_string_builder_append_raw(&topic, MSG_TOPIC_PTR(*msg), MSG_TOPIC_LENGTH(*msg))) != 0) {
		goto out;
	}

	RRR_DBG_3("msgdb fd %i recv MSG command %s topic '%s' size %" PRIrrrl "\n",
			client->fd, MSG_TYPE_NAME(*msg), rrr_string_builder_buf(&topic), MSG_TOPIC_LENGTH(*msg));

	if (MSG_TOPIC_LENGTH(*msg) == 0) {
		RRR_DBG_3("msgdb fd %i received message with zero-length topic\n", client->fd);
		goto out_negative_ack;
	}

	switch (MSG_TYPE(*msg)) {
		case MSG_TYPE_PUT:
			ret = __rrr_msgdb_server_put(server, *msg);
			break;
		default:
			RRR_MSG_0("msgdb fd %i unknown message type %i received in message db server\n", client->fd, MSG_TYPE(*msg));
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
	};

	if (ret != 0) {
		goto out_negative_ack;
	}

	goto out_positive_ack;
	out_negative_ack:
		ret = __rrr_msgdb_server_send_msg_nack(client->fd);
		goto out;

	out_positive_ack:
		ret = __rrr_msgdb_server_send_msg_ack(client->fd);
		goto out;

	out:
		rrr_string_builder_clear(&topic);
		return ret;
}

static int __rrr_msgdb_server_read_msg_ctrl_callback (
		const struct rrr_msg *msg,
		void *private_data,
		void *arg
) {
	struct rrr_msgdb_server_client *client = private_data;

	(void)(arg);
	(void)(client);

	RRR_MSG_0("Received unknown control message %u\n", RRR_MSG_CTRL_FLAGS(msg));
	return RRR_MSGDB_SOFT_ERROR;

//	client->prev_ctrl_msg_type = RRR_MSG_CTRL_FLAGS(msg);
//	return 0;
}

int rrr_msgdb_server_tick (
	struct rrr_msgdb_server *server
) {
	int ret = 0;

	if ((ret = rrr_socket_client_collection_accept (
		&server->clients,
		__rrr_msgdb_server_client_new_void,
		NULL,
		__rrr_msgdb_server_client_destroy_void
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_socket_client_collection_read_message (
			&server->clients,
			4096,
			RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
			__rrr_msgdb_server_read_msg_msg_callback,
			NULL,
			NULL,
			__rrr_msgdb_server_read_msg_ctrl_callback,
			server
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
