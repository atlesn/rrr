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
#include "../allocator.h"
#include "msgdb_common.h"
#include "msgdb_server.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_client.h"
#include "../helpers/nullsafe_str.h"
#include "../util/rrr_time.h"
#include "../util/rrr_readdir.h"
#include "../util/sha256.h"
#include "../helpers/string_builder.h"
#include "../rrr_strerror.h"
#include "../read.h"
#include "../array.h"
#include "../map.h"
#include "../event/event.h"
#include "../event/event_collection.h"

#define RRR_MSGDB_SERVER_SEND_CHUNK_COUNT_LIMIT 10000
#define RRR_MSGDB_SERVER_DIRECTORY_LEVELS 2

struct rrr_msgdb_server_client;

#define RRR_MSGDB_SERVER_ITERATION_FILE_CALLBACK_ARGS \
	int *do_delete, struct rrr_msgdb_server_client *client, const char *path, void *arg

#define RRR_MSGDB_SERVER_ITERATION_COMPLETE_CALLBACK_ARGS \
	struct rrr_msgdb_server_client *client, void *arg

struct rrr_msgdb_server_iteration_session {
	struct rrr_array dirs;
	uint32_t min_age_s;

	int (*file_callback)(RRR_MSGDB_SERVER_ITERATION_FILE_CALLBACK_ARGS);
	int (*complete_callback)(RRR_MSGDB_SERVER_ITERATION_COMPLETE_CALLBACK_ARGS);
	void *callback_arg;
};

static void __rrr_msgdb_server_iteration_session_destroy (
		struct rrr_msgdb_server_iteration_session *session
) {
	rrr_array_clear(&session->dirs);
	rrr_free(session);
}

struct rrr_msgdb_server {
	char *directory;
	struct rrr_socket_client_collection *clients;
	uint64_t recv_count;
	struct rrr_event_queue *queue;
};

void rrr_msgdb_server_destroy_void (
		void *server
) {
	rrr_msgdb_server_destroy(server);
}

struct rrr_msgdb_server_client {
	struct rrr_msgdb_server *server;
	int fd;
	char *send_data;
	rrr_length send_data_size;
	rrr_length send_data_pos;
	struct rrr_event_collection events;
	struct rrr_msgdb_server_iteration_session *iteration_session;
	rrr_event_handle iteration_event;
};

static void __rrr_msgdb_server_client_destroy (
		struct rrr_msgdb_server_client *client
) {
	if (client->iteration_session != NULL) {
		__rrr_msgdb_server_iteration_session_destroy(client->iteration_session);
	}
	rrr_event_collection_clear(&client->events);
	RRR_FREE_IF_NOT_NULL(client->send_data);
	rrr_free(client);
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

static int __rrr_msgdb_server_mkdir_chdir_levels (
		const char *str
) {
	int ret = 0;

	const char *pos = str;
	for (size_t i = 0; i < RRR_MSGDB_SERVER_DIRECTORY_LEVELS && *pos != '\0'; i++) {
		const char tmp[2] = { *pos, '\0' };
		if ((ret = __rrr_msgdb_server_mkdir_chdir (tmp)) != 0) {
			goto out;
		}
		pos++;
	}

	if (*pos == '\0') {
		RRR_MSG_0("Filename '%s' too short in %s\n", str, __func__);
		ret = RRR_MSGDB_SOFT_ERROR;
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

static int __rrr_msgdb_server_put (
		struct rrr_msgdb_server *server,
		const struct rrr_msg_msg *msg,
		const char *sha256_str,
		const char *topic
) {
	int ret = 0;
	int fd = 0;
	struct rrr_msg *msg_tmp = NULL;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	if ((ret = __rrr_msgdb_server_mkdir_chdir_levels (sha256_str)) != 0) {
		goto out;
	}

	if ((fd = rrr_socket_open(sha256_str, O_CREAT|O_TRUNC|O_RDWR, 0777, "msgdb_server_put", 0)) <= 0) {
		RRR_MSG_0("Could not open file '%s' for writing in message db server: %s\n",
			sha256_str, rrr_strerror(errno));
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	RRR_DBG_3("msgdb write to '%s' topic '%s' size %llu\n", sha256_str, topic, (long long unsigned) MSG_TOTAL_SIZE(msg));

	if ((msg_tmp = rrr_allocate(MSG_TOTAL_SIZE(msg))) == NULL) {
		RRR_MSG_0("Could not allocate memory for temporary message in __rrr_msgdb_server_put\n");
		ret = 1;
		goto out;
	}

	memcpy(msg_tmp, msg, MSG_TOTAL_SIZE(msg));

	// Don't save the message with PUT type, would be silly, innit?
	MSG_SET_TYPE((struct rrr_msg_msg *) msg_tmp, MSG_TYPE_MSG);

	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg_tmp);
	rrr_msg_checksum_and_to_network_endian(msg_tmp);

	// Note: Do not attempt to use size from the endian-converted message
	if (write(fd, msg_tmp, MSG_TOTAL_SIZE(msg)) != (rrr_slength) MSG_TOTAL_SIZE(msg)) {
		RRR_MSG_0("Could not write to file '%s' in message db server: %s\n", sha256_str, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	if (fd > 0) {
		rrr_socket_close(fd);
	}
	return ret;
}

static int __rrr_msgdb_server_del_raw (
		const char *str
) {
	int ret = 0;

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

	out:
	return ret;
}

static int __rrr_msgdb_server_del (
		struct rrr_msgdb_server *server,
		const char *str
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	if ((ret = __rrr_msgdb_server_mkdir_chdir_levels (str)) != 0) {
		goto out;
	}

	if ((ret = __rrr_msgdb_server_del_raw(str)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_send_callback (
		int fd,
		void **data,
		rrr_length data_size,
		void *arg
) {
	struct rrr_msgdb_server *server = arg;

	int ret = 0;

	rrr_length send_chunk_count = 0;
	if ((ret = rrr_socket_client_collection_send_push (
			&send_chunk_count,
			server->clients,
			fd,
			data,
			data_size
	)) != 0) {
		goto out;
	}

	if (send_chunk_count > RRR_MSGDB_SERVER_SEND_CHUNK_COUNT_LIMIT) {
		RRR_MSG_0("msgdb fd %i send chunk limit of %i reached, soft error.\n",
				fd, RRR_MSGDB_SERVER_SEND_CHUNK_COUNT_LIMIT);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_send_msg_ack (
		struct rrr_msgdb_server_client *client
) {
	RRR_DBG_3("msgdb fd %i send ACK\n", client->fd);
	return rrr_msgdb_common_ctrl_msg_send_ack(client->fd, __rrr_msgdb_server_send_callback, client->server);
}

static int __rrr_msgdb_server_send_msg_nack (
		struct rrr_msgdb_server_client *client
) {
	RRR_DBG_3("msgdb fd %i send NACK\n", client->fd);
	return rrr_msgdb_common_ctrl_msg_send_nack(client->fd, __rrr_msgdb_server_send_callback, client->server);
}

static int __rrr_msgdb_server_send_msg_pong (
		struct rrr_msgdb_server_client *client
) {
	RRR_DBG_3("msgdb fd %i send PONG\n", client->fd);
	return rrr_msgdb_common_ctrl_msg_send_pong(client->fd, __rrr_msgdb_server_send_callback, client->server);
}

static int __rrr_msgdb_server_idx_make_directory_index_recurse (
		struct rrr_array *response_target,
		const char *path_tmp,
		char *path_tmp_wpos,
		int level
) {
	int ret = 0;

	char c = '0';

	while (c <= 'f') {
		sprintf(path_tmp_wpos, "%c/", c);

		if (level == 1) {
			if ((ret = rrr_array_push_value_str_with_tag(response_target, "dir", path_tmp)) != 0) {
				goto out;
			}
		}
		else {
			if ((ret = __rrr_msgdb_server_idx_make_directory_index_recurse (
					response_target,
					path_tmp,
					path_tmp_wpos + 2,
					level - 1
			)) != 0) {
				goto out;
			}
		}

		if (c == '9') {
			c = 'a';
		}
		else {
			c++;
		}
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_idx_make_directory_index (
		struct rrr_array *response_target
) {
	char path_tmp[1 + RRR_MSGDB_SERVER_DIRECTORY_LEVELS * 2];

	return __rrr_msgdb_server_idx_make_directory_index_recurse (
		response_target,
		path_tmp,
		path_tmp,
		RRR_MSGDB_SERVER_DIRECTORY_LEVELS
	);
}

static int __rrr_msgdb_server_open_and_read_file (
		struct rrr_msg_msg **target,
		const char *str,
		int do_head_only,
		const char *topic_to_verify
) {
	int ret = 0;

	struct rrr_msg *msg_tmp = NULL;

	rrr_biglength total_read;
	rrr_biglength file_size;
	if (rrr_socket_open_and_read_file_head (
			(char **) &msg_tmp,
			&total_read,
			&file_size,
			str,
			0,
			O_RDONLY,
			// Max read size for header only is max size of topic + header
			(rrr_biglength) (do_head_only ? RRR_MSG_TOPIC_MAX + sizeof(struct rrr_msg_msg) - 1 : 0)
	) != 0) {
		if (errno != EEXIST && errno != ENOENT) {
			RRR_MSG_0("Could not read file '%s' in message db server\n",
				str);
		}
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (file_size < sizeof(*msg_tmp)) {
		RRR_MSG_0("Empty or too small file '%s' found in message db server directory\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (file_size > UINT32_MAX) {
		RRR_MSG_0("File '%s' was too big in message db server directory (%llu>%llu)\n",
			str, (unsigned long long) file_size, (unsigned long long) UINT32_MAX);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (!do_head_only) {
		rrr_length target_size_control = 0;
		if (rrr_msg_get_target_size_and_check_checksum (
				&target_size_control,
				msg_tmp,
				sizeof(*msg_tmp)
		) != 0) {
			RRR_MSG_0("Head verification step 1/4 of '%s' failed in message db server (checksum error)\n", str);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}

		if ((rrr_length) file_size != target_size_control) {
			RRR_MSG_0("Head verification step 2/4 of '%s' failed in message db server (actual size was %llu while %llu was excpected)\n",
					str,
					(unsigned long long) file_size,
					(unsigned long long) target_size_control
			);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;
		}
	}

	if (rrr_msg_head_to_host_and_verify(msg_tmp, (rrr_length) file_size) != 0) {
		RRR_MSG_0("Head verification step 3/4 of '%s' failed in message db server (possible invalid field values)\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (!RRR_MSG_IS_RRR_MESSAGE(msg_tmp)) {
		RRR_MSG_0("Message type of '%u' was not RRR message in message db server\n", msg_tmp->msg_type);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify((struct rrr_msg_msg *) msg_tmp, (rrr_biglength) file_size) != 0) {
		RRR_MSG_0("Head verification step 4/4 of '%s' failed in message db server\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if ( (void *) MSG_TOPIC_PTR((struct rrr_msg_msg *) msg_tmp) + MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp) >
	     (void *) msg_tmp + file_size
	) {
		RRR_MSG_0("Specified topic length of '%s' exceeds size of file in message db server\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (topic_to_verify != NULL) {
		if ( MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp) != strlen(topic_to_verify) ||
		     memcmp(MSG_TOPIC_PTR((struct rrr_msg_msg *) msg_tmp), topic_to_verify, MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp)) != 0
		) {
			RRR_MSG_0("Warning: Hash error, collition or topic error for '%s' in message db server, requsted topic was '%s'",
				       str, topic_to_verify);
			ret = RRR_MSGDB_SOFT_ERROR;
			goto out;

		}
	}

	*target = (struct rrr_msg_msg *) msg_tmp;
	msg_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_msgdb_server_get_raw (
		struct rrr_msgdb_server *server,
		const char *str,
		const char *topic_to_verify,
		int response_fd
) {
	int ret = 0;

	struct rrr_msg_msg *msg_tmp  = NULL;

	if ((ret = __rrr_msgdb_server_open_and_read_file (
			&msg_tmp,
			str,
			0 /* Whole file */,
			topic_to_verify
	)) != 0) {
		goto out;
	}

	if (rrr_msgdb_common_msg_send (
			response_fd,
			(struct rrr_msg_msg *) msg_tmp,
			__rrr_msgdb_server_send_callback,
			server
	) != 0) {
		ret = RRR_MSGDB_EOF;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_msgdb_server_get (
		struct rrr_msgdb_server *server,
		const char *str,
		const char *topic,
		int response_fd
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	// Note that successful return is an error
	if (__rrr_msgdb_server_chdir(str, 1) == 0) {
		RRR_MSG_0("Could not read file '%s' in message db server, it was a directory\n",
			str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if ((ret = __rrr_msgdb_server_mkdir_chdir_levels (str)) != 0) {
		goto out;
	}

	RRR_DBG_3("msgdb fd %i read from '%s' topic '%s'\n", response_fd, str, topic);

	if ((ret = __rrr_msgdb_server_get_raw (
			server,
			str,
			topic,
			response_fd
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

/*
static int __rrr_msgdb_server_verify_path (
		const char *filename
) {
	const size_t filename_length = strlen(filename);

	// Name must begin with for instance "a/b/"

	if (filename_length <= RRR_MSGDB_SERVER_DIRECTORY_LEVELS * 2) {
		return RRR_MSGDB_SOFT_ERROR;
	}

	for (size_t i = 1; i < RRR_MSGDB_SERVER_DIRECTORY_LEVELS * 2; i += 2) {
		if (filename[i] != '/') {
			return RRR_MSGDB_SOFT_ERROR;
		}
	}

	return RRR_MSGDB_OK;
}
*/

struct rrr_msgdb_server_client_iteration_session_process_file_callback_data {
	struct rrr_msgdb_server_client *client;
	uint64_t time_end;
};

static int __rrr_msgdb_server_client_iteration_session_process_file_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct rrr_msgdb_server_client_iteration_session_process_file_callback_data *callback_data = private_data;
	struct rrr_msgdb_server_client *client = callback_data->client;;
	struct rrr_msgdb_server_iteration_session *session = client->iteration_session;

	(void)(entry);
	(void)(resolved_path);

	int ret = 0;

	const uint64_t min_age_us = (uint64_t) session->min_age_s * 1000 * 1000;

	char *msg_tmp = NULL;

	if (type == DT_DIR) {
		goto out;
	}

	if (strncmp (orig_path, "./", 2) == 0) {
		orig_path += 2;
	}

	if (__rrr_msgdb_server_open_and_read_file (
				(struct rrr_msg_msg **) &msg_tmp,
				orig_path,
				1, /* Head only */
				NULL /* No topic to verify */
	) != 0) {
		RRR_MSG_0("Warning: msgdb failed to read header of '%s'. Deleting file.\n",
				orig_path
		);
		goto delete;
	}

	if (!rrr_msg_msg_ttl_ok((struct rrr_msg_msg *) msg_tmp, min_age_us)) {
		int do_delete = 0;
		if ((ret = session->file_callback (
				&do_delete,
				client,
				orig_path,
				session->callback_arg
		)) != 0) {
			goto out;
		}
		if (do_delete) {
			goto delete;
		}
	}

	goto out;
	delete:
		RRR_DBG_3("msgdb del '%s'\n",
				orig_path
		);
		if (__rrr_msgdb_server_del_raw(orig_path) != 0) {
			RRR_MSG_0("Warning: msgdb deletion failed for '%s'\n", orig_path);
		}
	out:
		if (ret == 0 && rrr_time_get_64() > callback_data->time_end) {
			ret = RRR_MSGDB_INCOMPLETE;
		}
		RRR_FREE_IF_NOT_NULL(msg_tmp);
		return ret;
}

static int __rrr_msgdb_server_client_iteration_session_process (
		struct rrr_msgdb_server_client *client
) {
	struct rrr_msgdb_server *server = client->server;
	struct rrr_msgdb_server_iteration_session *session = client->iteration_session;

	int ret = 0;

	char *path_tmp = NULL;

	uint64_t time_end = rrr_time_get_64() + 1 * 1000 * 1000; // 1 s

	struct rrr_msgdb_server_client_iteration_session_process_file_callback_data file_callback_data = {
		client,
		time_end
	};

	RRR_LL_ITERATE_BEGIN(&session->dirs, struct rrr_type_value);
		if (rrr_time_get_64() > time_end) {
			ret = RRR_MSGDB_INCOMPLETE;
			goto out;
		}

		RRR_LL_ITERATE_SET_DESTROY();

		if (!RRR_TYPE_IS_BLOB(node->definition->type)) {
			RRR_BUG("BUG: File path element was not of blob type in %s\n", __func__);
		}
		if (node->total_stored_length > PATH_MAX) {
			RRR_BUG("BUG: File path length too long in %s\n", __func__);
		}

		RRR_FREE_IF_NOT_NULL(path_tmp);

		if ((ret = node->definition->to_str(&path_tmp, node)) != 0) {
			RRR_MSG_0("Failed to extract string in %s\n", __func__);
			goto out;
		}

		if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
			goto out;
		}

		if (rrr_type_value_is_tag(node, "dir")) {
			if (__rrr_msgdb_server_chdir (path_tmp, 1) != 0) {
				// Ignore
				RRR_LL_ITERATE_NEXT();
			}
			if ((ret = rrr_readdir_foreach(".", __rrr_msgdb_server_client_iteration_session_process_file_callback, &file_callback_data)) != 0) {
				goto out;
			}
		}
		else {
			RRR_BUG("BUG: directory tag not found in node in %s, make sure directory index only is provided\n", __func__);
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&session->dirs, 0; rrr_type_value_destroy(node));

	ret = session->complete_callback (client, session->callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(path_tmp);
	return ret;
}

static int __rrr_msgdb_server_iteration_begin (
		struct rrr_msgdb_server_client *client,
		uint32_t min_age_s,
		int (*file_callback)(RRR_MSGDB_SERVER_ITERATION_FILE_CALLBACK_ARGS),
		int (*complete_callback)(RRR_MSGDB_SERVER_ITERATION_COMPLETE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	if (client->iteration_session != NULL) {
		RRR_MSG_0("Attempted to start iteration session while one was already in progress\n");
		ret = RRR_MSGDB_HARD_ERROR;
		goto out;
	}

	if ((client->iteration_session = rrr_allocate_zero(sizeof(*client->iteration_session))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	client->iteration_session->min_age_s = min_age_s;
	client->iteration_session->file_callback = file_callback;
	client->iteration_session->complete_callback = complete_callback;
	client->iteration_session->callback_arg = callback_arg;

	if ((ret = __rrr_msgdb_server_idx_make_directory_index (&client->iteration_session->dirs)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_tidy_file_callback (RRR_MSGDB_SERVER_ITERATION_FILE_CALLBACK_ARGS) {
	(void)(client);
	(void)(path);
	(void)(arg);

	*do_delete = 1;

	return 0;
}

static int __rrr_msgdb_server_tidy_complete_callback (RRR_MSGDB_SERVER_ITERATION_COMPLETE_CALLBACK_ARGS) {
	(void)(arg);

	return __rrr_msgdb_server_send_msg_ack(client);
}

static int __rrr_msgdb_server_tidy (
		struct rrr_msgdb_server_client *client,
		uint32_t max_age_s
) {
	int ret = 0;

	// max age: maximum age of messages, older messages are deleted
	// min age: minimum age of messagesto delete, younger are preserved
	if ((ret = __rrr_msgdb_server_iteration_begin (
			client,
			max_age_s,
			__rrr_msgdb_server_tidy_file_callback,
			__rrr_msgdb_server_tidy_complete_callback,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_idx_callback (RRR_MSGDB_SERVER_ITERATION_FILE_CALLBACK_ARGS) {
	(void)(arg);

	int ret = 0;

	*do_delete = 0;
	if ((ret = __rrr_msgdb_server_get_raw (
			client->server,
			path,
			NULL,
			client->fd
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_idx_complete_callback (RRR_MSGDB_SERVER_ITERATION_COMPLETE_CALLBACK_ARGS) {
	(void)(arg);

	return __rrr_msgdb_server_send_msg_ack(client);
}

static int __rrr_msgdb_server_idx (
		struct rrr_msgdb_server_client *client,
		uint32_t min_age_s
) {
	return __rrr_msgdb_server_iteration_begin (
			client,
			min_age_s,
			__rrr_msgdb_server_idx_callback,
			__rrr_msgdb_server_idx_complete_callback,
			NULL
	);
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

	uint8_t sha256[RRR_SHA256_SIZE];
	rrr_sha256_calculate(sha256, MSG_TOPIC_PTR(*msg), MSG_TOPIC_LENGTH(*msg));

	char sha256_hex[sizeof(sha256) * 2 + 1];
	for (size_t i = 0; i < sizeof(sha256); i++) {
		sprintf(sha256_hex + i * 2, "%02x", sha256[i]);
	}
	sha256_hex[sizeof(sha256_hex) - 1] = '\0';

	switch (MSG_TYPE(*msg)) {
		case MSG_TYPE_PUT:
			ret = __rrr_msgdb_server_put(server, *msg, sha256_hex, rrr_string_builder_buf(&topic));
			break;
		case MSG_TYPE_DEL:
			ret = __rrr_msgdb_server_del(server, sha256_hex);
			break;
		case MSG_TYPE_GET:
			if ((ret = __rrr_msgdb_server_get(server, sha256_hex, rrr_string_builder_buf(&topic), client->fd)) == 0) {
				// GET responds with a message upon success, no need for ACK
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
			ret = __rrr_msgdb_server_send_msg_nack(client) ? RRR_MSGDB_EOF : 0;
		}
		goto out;

	out_positive_ack:
		if (!no_ack) {
			ret = __rrr_msgdb_server_send_msg_ack(client) ? RRR_MSGDB_EOF : 0;
		}
		goto out;

	out:
		rrr_string_builder_clear(&topic);
		return ret;
}

static void __rrr_msgdb_server_client_iteration_session_stop (
		struct rrr_msgdb_server_client *client
) {
	if (client->iteration_session == NULL)
		return;

	__rrr_msgdb_server_iteration_session_destroy(client->iteration_session);
	client->iteration_session = NULL;
}

static int __rrr_msgdb_server_read_msg_ctrl_callback (
		const struct rrr_msg *msg,
		void *private_data,
		void *arg
) {
	struct rrr_msgdb_server_client *client = private_data;
	struct rrr_msgdb_server *server = arg;

	(void)(server);

	if (RRR_MSG_CTRL_FLAGS(msg) & RRR_MSGDB_CTRL_F_PING) {
		RRR_DBG_3("msgdb fd %i recv PING\n", client->fd);
		return __rrr_msgdb_server_send_msg_pong(client) ? RRR_MSGDB_EOF : 0;
	}

	if (RRR_MSG_CTRL_FLAGS(msg) & RRR_MSGDB_CTRL_F_TIDY) {
		RRR_DBG_3("msgdb fd %i recv TIDY max age %" PRIu32 " seconds\n", client->fd, msg->msg_value);
		return __rrr_msgdb_server_tidy(client, msg->msg_value);
	}

	if (RRR_MSG_CTRL_FLAGS(msg) & RRR_MSGDB_CTRL_F_IDX) {
		RRR_DBG_3("msgdb fd %i recv IDX min age %" PRIu32 " seconds\n", client->fd, msg->msg_value);
		return __rrr_msgdb_server_idx(client, msg->msg_value);
	}

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

static void __rrr_msgdb_client_event_iteration (
		int fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct rrr_msgdb_server_client *client = arg;

	if (client->iteration_session == NULL) {
		return;
	}

	int ret_tmp = 0;

	if ((ret_tmp = __rrr_msgdb_server_client_iteration_session_process (client)) == 0) {
		// Iteration complete
		__rrr_msgdb_server_client_iteration_session_stop(client);
	}
	else if (ret_tmp == RRR_MSGDB_INCOMPLETE) {
		// Not done yet
	}
	else {
		// Some error, close connection
		rrr_socket_client_collection_close_when_send_complete_by_fd (
				client->server->clients,
				client->fd
		);
		EVENT_REMOVE(client->iteration_event);
	}
}

static int __rrr_msgdb_server_client_new (
		struct rrr_msgdb_server_client **target,
		struct rrr_msgdb_server *server,
		int fd
) {
	int ret = 0;

	*target = NULL;

	struct rrr_msgdb_server_client *client = rrr_allocate_zero(sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	rrr_event_collection_init (&client->events, server->queue);

	if ((ret = rrr_event_collection_push_periodic (
			&client->iteration_event,
			&client->events,
			__rrr_msgdb_client_event_iteration,
			client,
			50 * 1000 // 50 ms
	)) != 0) {
		RRR_MSG_0("Failed to create iteration event in %s\n", __func__);
		goto out_clear_events;
	}

	EVENT_ADD(client->iteration_event);

	client->server = server;
	client->fd = fd;

	*target = client;

	goto out;
	out_clear_events:
		rrr_event_collection_clear(&client->events);
//	out_free:
		rrr_free(client);
	out:
	return ret;
}

static int __rrr_msgdb_server_client_new_void (
		void **target,
		int fd,
		void *arg
) {
	struct rrr_msgdb_server *server = arg;
	return __rrr_msgdb_server_client_new((struct rrr_msgdb_server_client **) target, server, fd);
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

	if ((server = rrr_allocate(sizeof(*server))) == NULL) {
		RRR_MSG_0("Could not allocate memory for server in rrr_msgdb_server_new\n");
		ret = 1;
		goto out_close;
	}

	memset(server, '\0', sizeof(*server));

	if ((server->directory = rrr_strdup(directory)) == NULL) {
		RRR_MSG_0("Could not allocate memory for directory in rrr_msgdb_server_new\n");
		ret = 1;
		goto out_free;
	}

	if ((ret = rrr_socket_client_collection_new(&server->clients, queue, "msgdb_server")) != 0) {
		goto out_free_directory;
	}

	rrr_socket_client_collection_event_setup (
			server->clients,
			__rrr_msgdb_server_client_new_void,
			__rrr_msgdb_server_client_destroy_void,
			server,
			1 * 1024 * 1024, // 1 MB
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

	server->queue = queue;

	*result = server;

	goto out;
//	out_clear_events:
//		rrr_event_collection_clear(&server->events);
	out_destroy_client_collection:
		rrr_socket_client_collection_destroy(server->clients);
	out_free_directory:
		rrr_free(server->directory);
	out_free:
		rrr_free(server);
	out_close:
		rrr_socket_close(fd);
	out:
		return ret;
}

void rrr_msgdb_server_destroy (
		struct rrr_msgdb_server *server
) {
	RRR_FREE_IF_NOT_NULL(server->directory);
	rrr_socket_client_collection_destroy(server->clients);
	rrr_free(server);
}
