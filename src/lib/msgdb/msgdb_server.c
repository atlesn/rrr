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
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_client.h"
#include "../helpers/nullsafe_str.h"
#include "../util/rrr_time.h"
#include "../util/rrr_readdir.h"
#include "../string_builder.h"
#include "../rrr_strerror.h"
#include "../read.h"
#include "../array.h"
#include "../map.h"

struct rrr_msgdb_server {
	char *directory;
	int fd;
	struct rrr_socket_client_collection *clients;
	uint64_t recv_count;
};

void rrr_msgdb_server_destroy_void (
		void *server
) {
	rrr_msgdb_server_destroy(server);
}

struct rrr_msgdb_server_client {
	int fd;
	char *send_data;
	size_t send_data_size;
	size_t send_data_pos;
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
	RRR_FREE_IF_NOT_NULL(client->send_data);
	free(client);
}

static void __rrr_msgdb_server_client_destroy_void (
		void *arg
) {
	return __rrr_msgdb_server_client_destroy(arg);
}

static int __rrr_msgdb_server_chdir (
		const char *directory,
		int silent
) {
	int ret = 0;

	if (chdir(directory) != 0) {
		if (!silent) {
			if (errno == ENOENT) {
				RRR_DBG_3("Note: Could not change to directory '%s' in message db server: %s\n",
					directory, rrr_strerror(errno));
			}
			else {
				RRR_MSG_0("Could not change to directory '%s' in message db server: %s\n",
					directory, rrr_strerror(errno));
			}
		}
		ret = 1;
		goto out;
	}

	RRR_DBG_3("msgdb chdir '%s'\n", directory);

	out:
	return ret;
}

static int __rrr_msgdb_server_mkdir_chdir (
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

	out:
	return ret;
}

static int __rrr_msgdb_server_chdir_base (
		struct rrr_msgdb_server *server
) {
	return __rrr_msgdb_server_mkdir_chdir(server->directory);
}

struct rrr_msgdb_server_path_iterate_callback_data {
	int (*callback)(const char *str, int is_last, void *arg);
	void *callback_arg;
	const int allow_trailing_slash;
	int is_last;
};

static int __rrr_msgdb_server_path_iterate_str_callback (
		const char *str,
		void *arg
) {
	struct rrr_msgdb_server_path_iterate_callback_data *callback_data = arg;

	if (strlen(str) == 0) {
		if (!callback_data->allow_trailing_slash && callback_data->is_last) {
			RRR_MSG_0("File component of a path in message db server had zero length (topic ends with a /), this is an error\n");
			return RRR_MSGDB_SOFT_ERROR;
		}
		// Ignore empty path component
		return 0;
	}

	if ((strlen(str) >= 2 && strncmp(str, "..", 2) == 0) || strncmp(str, ".", 1) == 0) {
		RRR_MSG_0("Illegal path component name '%s' in message db server\n", str);
		return RRR_MSGDB_SOFT_ERROR;
	}

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
		const int allow_trailing_slash,
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
		allow_trailing_slash,
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

	if (is_last) {
		if ((fd = rrr_socket_open(str, O_CREAT|O_TRUNC|O_RDWR, 0777, "msgdb_server_put", 0)) <= 0) {
			RRR_MSG_0("Could not open file '%s' for writing in message db server: %s\n",
				str, rrr_strerror(errno));
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}
		RRR_DBG_3("msgdb write to '%s' size %llu\n", str, (long long unsigned) MSG_TOTAL_SIZE(callback_data->msg));

		if ((msg_tmp = malloc(MSG_TOTAL_SIZE(callback_data->msg))) == NULL) {
			RRR_MSG_0("Could not allocate memory for temporary message in __rrr_msgdb_server_put_path_split_callback\n");
			ret = 1;
			goto out;
		}

		memcpy(msg_tmp, callback_data->msg, MSG_TOTAL_SIZE(callback_data->msg));

		// Don't save the message with PUT type, would be silly, innit?
		MSG_SET_TYPE((struct rrr_msg_msg *) msg_tmp, MSG_TYPE_MSG);

		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg_tmp);
		rrr_msg_checksum_and_to_network_endian(msg_tmp);

		// Note: Do not attempt to use size from the endian-converted message
		if (write(fd, msg_tmp, MSG_TOTAL_SIZE(callback_data->msg)) != MSG_TOTAL_SIZE(callback_data->msg)) {
			RRR_MSG_0("Could not write to file '%s' in message db server: %s\n", str, rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}
	else {
		if ((ret = __rrr_msgdb_server_mkdir_chdir(str)) != 0) {
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	if (fd > 0) {
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
			0, // Disallow trailing slash
			__rrr_msgdb_server_put_path_split_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct rrr_msgdb_server_del_path_split_callback_data {
	struct rrr_map path_elements_reverse;
};

static int __rrr_msgdb_server_del_path_split_callback (
		const char *str,
		int is_last,
		void *arg
) {
	int ret = 0;

	struct rrr_msgdb_server_del_path_split_callback_data *callback_data = arg;

	if (is_last) {
		if (unlink(str) != 0) {
			if (errno == EISDIR) {
				if (rmdir(str) != 0) {
					RRR_MSG_0("Could not remove directory '%s' in message db server: %s\n",
						str, rrr_strerror(errno));
					ret = RRR_MSGDB_SOFT_ERROR;
				}
			}
			else {
				if (errno == ENOENT) {
					RRR_DBG_3("Note: Tried to delete file '%s' in message db server, but it had already been deleted.\n",
						str);
				}
				else {
					RRR_MSG_0("Could not unlink file '%s' in message db server: %s\n",
						str, rrr_strerror(errno));
					ret = RRR_MSGDB_SOFT_ERROR;
				}
			}
			goto out;
		}
	}
	else {
		if ((ret = rrr_map_item_prepend_new(&callback_data->path_elements_reverse, str, NULL)) != 0) {
			goto out;
		}
		if (__rrr_msgdb_server_chdir(str, 0)) {
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_del (
		struct rrr_msgdb_server *server,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	struct rrr_msgdb_server_del_path_split_callback_data callback_data = {0};

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	if ((ret = __rrr_msgdb_server_path_iterate (
			msg,
			0, // Disallow trailing slash
			__rrr_msgdb_server_del_path_split_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	RRR_MAP_ITERATE_BEGIN(&callback_data.path_elements_reverse);
		if (__rrr_msgdb_server_chdir("..", 0) != 0) {
			RRR_MSG_0("Could not chdir while ascending in message db server: %s\n",
				rrr_strerror(errno));
			// Do not return NACK, file has been deleted. Return success.
			goto out;
		}
		if (rmdir(node_tag) != 0) {
			if (errno == ENOTEMPTY || errno == EEXIST) {
				// OK, not deleting directory as files are still present in it
			}
			else {
				RRR_MSG_0("Warning: Could not remove directory '%s' in message db server: %s\n",
					node_tag, rrr_strerror(errno));
				// Do not return NACK, file has been deleted. Return success.
				goto out;
			}
			RRR_MAP_ITERATE_BREAK();
		}
		else {
			RRR_DBG_3("msgdb rmdir '%s'\n", node_tag);
		}
	RRR_MAP_ITERATE_END();

	out:
	RRR_MAP_CLEAR(&callback_data.path_elements_reverse);
	return ret;
}

static int __rrr_msgdb_server_send_callback (
	int fd,
	void **data,
	ssize_t data_size,
	void *arg
) {
	struct rrr_msgdb_server *server = arg;
	return rrr_socket_client_collection_send_push (
			server->clients,
			fd,
			data,
			data_size
	);
}

static int __rrr_msgdb_server_send_msg_ack (
		struct rrr_msgdb_server *server,
		int fd
) {
	RRR_DBG_3("msgdb fd %i send ACK\n", fd);
	return rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_ACK, __rrr_msgdb_server_send_callback, server);
}

static int __rrr_msgdb_server_send_msg_nack (
		struct rrr_msgdb_server *server,
		int fd
) {
	RRR_DBG_3("msgdb fd %i send NACK\n", fd);
	return rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_NACK, __rrr_msgdb_server_send_callback, server);
}

struct rrr_msgdb_server_get_path_split_callback_data {
	int response_fd;
	struct rrr_msgdb_server *server;
};

static int __rrr_msgdb_server_get_path_split_callback (
		const char *str,
		int is_last,
		void *arg
) {
	struct rrr_msgdb_server_get_path_split_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg *msg_tmp = NULL;

	if (is_last) {
		ssize_t file_size = 0;

		// Note that successful return is an error
		if (__rrr_msgdb_server_chdir(str, 1) == 0) {
			RRR_MSG_0("Could not read file '%s' in message db server, it was a directory\n",
				str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if (rrr_socket_open_and_read_file((char **) &msg_tmp, &file_size, str, O_RDONLY, 0) != 0) {
			RRR_MSG_0("Could not read file '%s' in message db server\n",
				str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if (file_size < (ssize_t) sizeof(*msg_tmp)) {
			RRR_MSG_0("Empty or too small file '%s' found in message db server directory\n", str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if (rrr_msg_head_to_host_and_verify(msg_tmp, file_size) != 0) {
			RRR_MSG_0("Head 1/2 verification of '%s' failed in message db server\n", str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if (!RRR_MSG_IS_RRR_MESSAGE(msg_tmp)) {
			RRR_MSG_0("Message type of '%u' was not RRR message in message db server\n", msg_tmp->msg_type);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if (rrr_msg_msg_to_host_and_verify((struct rrr_msg_msg *) msg_tmp, (rrr_biglength) file_size) != 0) {
			RRR_MSG_0("Head 2/2 verification of '%s' failed in message db server\n", str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		RRR_DBG_3("msgdb fd %i read from '%s' size %llu\n", callback_data->response_fd, str, (long long unsigned) MSG_TOTAL_SIZE(msg_tmp));

		if (rrr_msgdb_common_msg_send (
				callback_data->response_fd,
				(struct rrr_msg_msg *) msg_tmp,
				__rrr_msgdb_server_send_callback,
				callback_data->server
		) != 0) {
			ret = RRR_MSGDB_EOF;
			goto out;
		}
	}
	else {
		if (__rrr_msgdb_server_chdir(str, 0) != 0) {
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

struct rrr_msgdb_server_idx_path_split_callback_data {
	struct rrr_map *paths;
};

static int __rrr_msgdb_server_idx_path_split_callback (
		const char *str,
		int is_last,
		void *arg
) {
	(void)(is_last);

	int ret = 0;

	struct rrr_msgdb_server_idx_path_split_callback_data *callback_data = arg;

	if ((ret = rrr_map_item_add_new(callback_data->paths, str, NULL)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct rrr_msgdb_server_idx_make_index_readdir_callback_data {
	struct rrr_array *response_target;
};

static int __rrr_msgdb_server_idx_make_index_readdir_callback (
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	(void)(resolved_path);

	struct rrr_msgdb_server_idx_make_index_readdir_callback_data *callback_data = private_data;

	int ret = 0;

	if (strlen(orig_path) >= 2 && strncmp(orig_path, "./", 2) == 0) {
		orig_path += 2;
	}

	if (type == DT_DIR) {
		if ((ret = rrr_array_push_value_str_with_tag(callback_data->response_target, "dir", orig_path)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = rrr_array_push_value_str_with_tag(callback_data->response_target, "file", orig_path)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_idx_make_index (
		struct rrr_array *response_target,
		struct rrr_msgdb_server *server,
		const struct rrr_map *path_base
) {
	int ret = 0;

	struct rrr_string_builder path_base_str = {0};

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	int last_was_file = 0;

	if (RRR_LL_COUNT(path_base) == 0) {
		if ((ret = rrr_string_builder_append(&path_base_str, "")) != 0) {
			goto out;
		}
	}
	else {
		RRR_MAP_ITERATE_BEGIN_CONST(path_base);
			if (RRR_MAP_ITERATE_IS_LAST()) {
				if (__rrr_msgdb_server_chdir(node_tag, 1) != 0) {
					last_was_file = 1;
				}
			}
			else {
				if ((ret = __rrr_msgdb_server_chdir(node_tag, 0)) != 0) {
					goto out;
				}
			}
			if ((ret = rrr_string_builder_append_format(&path_base_str, "%s%s", node_tag, last_was_file ? "" : "/")) != 0) {
				goto out;
			}
		RRR_MAP_ITERATE_END();
	}

	if (last_was_file) {
		if ((ret = rrr_array_push_value_str_with_tag(response_target, "file", rrr_string_builder_buf(&path_base_str))) != 0) {
			goto out;
		}
	}
	else {
		struct rrr_msgdb_server_idx_make_index_readdir_callback_data callback_data = {
			response_target
		};

		if ((ret = rrr_readdir_foreach_recursive (".", __rrr_msgdb_server_idx_make_index_readdir_callback, &callback_data)) != 0) {
			goto out;
		}
	}

	out:
	rrr_string_builder_clear(&path_base_str);
	return ret;
}

static int __rrr_msgdb_server_idx (
		struct rrr_msgdb_server *server,
		const struct rrr_msg_msg *msg,
		int response_fd
) {
	int ret = 0;

	struct rrr_array results_tmp = {0};
	struct rrr_map paths_tmp = {0};
	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	struct rrr_msgdb_server_idx_path_split_callback_data callback_data = {
		&paths_tmp
	};

	if ((ret = __rrr_msgdb_server_path_iterate (
			msg,
			1, // Allow trailing slash
			__rrr_msgdb_server_idx_path_split_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_msgdb_server_idx_make_index (&results_tmp, server, &paths_tmp)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_new_message_from_collection (
			&msg_tmp,
			&results_tmp,
			rrr_time_get_64(),
			NULL,
			0
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_msgdb_common_msg_send (
			response_fd,
			(struct rrr_msg_msg *) msg_tmp,
			__rrr_msgdb_server_send_callback,
			server
	)) != 0) {
		ret = RRR_MSGDB_EOF;
		goto out;
	}

	out:
	rrr_map_clear(&paths_tmp);
	rrr_array_clear(&results_tmp);
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_msgdb_server_get (
		struct rrr_msgdb_server *server,
		const struct rrr_msg_msg *msg,
		int response_fd
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	struct rrr_msgdb_server_get_path_split_callback_data callback_data = {
		response_fd,
		server
	};

	if ((ret = __rrr_msgdb_server_path_iterate (
			msg,
			0, // Disallow trailing slash
			__rrr_msgdb_server_get_path_split_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_read_msg_msg_callback (
		struct rrr_msg_msg **msg,
		void *private_data,
		void *arg
) {
	struct rrr_msgdb_server_client *client = private_data;
	struct rrr_msgdb_server *server = arg;

	int ret = 0;
	int no_ack = 0;

	struct rrr_string_builder topic = {0};

	if ((ret = rrr_string_builder_append_raw(&topic, MSG_TOPIC_PTR(*msg), MSG_TOPIC_LENGTH(*msg))) != 0) {
		goto out;
	}

	RRR_DBG_3("msgdb fd %i %s size %" PRIrrrl " topic '%s'\n",
			client->fd, MSG_TYPE_NAME(*msg), MSG_TOTAL_SIZE(*msg), rrr_string_builder_buf(&topic));

	server->recv_count++;

	if (MSG_TOPIC_LENGTH(*msg) == 0) {
		RRR_MSG_0("Zero-length topic in message db server, this is an error\n");
		goto out_negative_ack;
	}

	switch (MSG_TYPE(*msg)) {
		case MSG_TYPE_PUT:
			ret = __rrr_msgdb_server_put(server, *msg);
			break;
		case MSG_TYPE_DEL:
			ret = __rrr_msgdb_server_del(server, *msg);
			break;
		case MSG_TYPE_GET:
			if ((ret = __rrr_msgdb_server_get(server, *msg, client->fd)) == 0) {
				// GET responds with a message upon success, not need for ACK
				// unless we failed
				no_ack = 1;
			}
			break;
		case MSG_TYPE_IDX:
			if ((ret = __rrr_msgdb_server_idx(server, *msg, client->fd)) == 0) {
				// IDX responds with a message upon success, not need for ACK
				// unless we failed
				no_ack = 1;
			}
			break;
		default:
			RRR_MSG_0("msgdb fd %i unknown message type %i received in message db server\n", client->fd, MSG_TYPE(*msg));
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
	};

	// Note that any errors produced while processing the
	// client request should be masked by setting ret value while
	// sending ACK. Only fail soft/hard if the sending of the ACK
	// message fails or if the client sends corrupt messages.

	if (ret == 0) {
		goto out_positive_ack;
	}
	else if (ret == RRR_MSGDB_SOFT_ERROR) {
		goto out_negative_ack;
	}

	// Any other errors => close connection
	RRR_DBG_3("msgdb fd %i close following error\n", client->fd);
	ret = RRR_MSGDB_EOF;
	goto out;

	out_negative_ack:
		if (!no_ack) {
			ret = __rrr_msgdb_server_send_msg_nack(server, client->fd) ? RRR_MSGDB_EOF : 0;
		}
		goto out;

	out_positive_ack:
		if (!no_ack) {
			ret = __rrr_msgdb_server_send_msg_ack(server, client->fd) ? RRR_MSGDB_EOF : 0;
		}
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

uint64_t rrr_msgdb_server_recv_count_get (
		struct rrr_msgdb_server *server
) {
	return server->recv_count;
}

int rrr_msgdb_server_new (
		struct rrr_msgdb_server **result,
		struct rrr_event_queue *queue,
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

	if ((ret = rrr_socket_client_collection_new(&server->clients, "msgdb_server")) != 0) {
		goto out_free_directory;
	}

	rrr_socket_client_collection_event_setup (
			server->clients,
			queue,
			__rrr_msgdb_server_client_new_void,
			__rrr_msgdb_server_client_destroy_void,
			NULL,
			4096,
			RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
			__rrr_msgdb_server_read_msg_msg_callback,
			NULL,
			NULL,
			__rrr_msgdb_server_read_msg_ctrl_callback,
			NULL,
			server
	);

	if ((ret = rrr_socket_client_collection_listen_fd_push (server->clients, fd)) != 0) {
		RRR_MSG_0("Could not push listen handle to client collection in rrr_msgdb_server_new\n");
		goto out_destroy_client_collection;
	}

	server->fd = fd;

	*result = server;

	goto out;
	out_destroy_client_collection:
		rrr_socket_client_collection_destroy(server->clients);
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
	rrr_socket_client_collection_destroy(server->clients);
	free(server);
}
