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
#include "../string_builder.h"
#include "../rrr_strerror.h"
#include "../read.h"
#include "../array.h"
#include "../map.h"

#define RRR_MSGDB_SERVER_SEND_CHUNK_COUNT_LIMIT 10000

struct rrr_msgdb_server {
	char *directory;
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

	struct rrr_msgdb_server_client *client = rrr_allocate(sizeof(*client));
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
		struct rrr_msgdb_server *server,
		const char *str
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

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
	return __rrr_msgdb_server_del_raw(server, str);
}

static int __rrr_msgdb_server_send_callback (
		int fd,
		void **data,
		ssize_t data_size,
		void *arg
) {
	struct rrr_msgdb_server *server = arg;

	int ret = 0;

	int send_chunk_count = 0;
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
		struct rrr_msgdb_server *server,
		int fd
) {
	RRR_DBG_3("msgdb fd %i send ACK\n", fd);
	return rrr_msgdb_common_ctrl_msg_send_ack(fd, __rrr_msgdb_server_send_callback, server);
}

static int __rrr_msgdb_server_send_msg_nack (
		struct rrr_msgdb_server *server,
		int fd
) {
	RRR_DBG_3("msgdb fd %i send NACK\n", fd);
	return rrr_msgdb_common_ctrl_msg_send_nack(fd, __rrr_msgdb_server_send_callback, server);
}

static int __rrr_msgdb_server_send_msg_pong (
		struct rrr_msgdb_server *server,
		int fd
) {
	RRR_DBG_3("msgdb fd %i send PONG\n", fd);
	return rrr_msgdb_common_ctrl_msg_send_pong(fd, __rrr_msgdb_server_send_callback, server);
}

struct rrr_msgdb_server_idx_make_index_readdir_callback_data {
	struct rrr_array *response_target;
	int do_single_level;
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
		if (!callback_data->do_single_level && (ret = rrr_array_push_value_str_with_tag(callback_data->response_target, "dir", orig_path)) != 0) {
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
		int do_single_level
) {
	int ret = 0;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	struct rrr_msgdb_server_idx_make_index_readdir_callback_data callback_data = {
		response_target,
		do_single_level
	};

	if ((ret = rrr_readdir_foreach_recursive (".", __rrr_msgdb_server_idx_make_index_readdir_callback, &callback_data)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msgdb_server_quick_topic_get (
		struct rrr_string_builder *topic,
		const char *str
) {
	int ret = 0;
	struct rrr_msg *msg_tmp  = NULL;

	ssize_t file_size = 0;

	// Max read size is max size of topic + header
	if (rrr_socket_open_and_read_file((char **) &msg_tmp, &file_size, str, O_RDONLY, RRR_MSG_TOPIC_MAX + sizeof(struct rrr_msg_msg) - 1) != 0) {
		if (errno != EEXIST && errno != ENOENT) {
			RRR_MSG_0("Could not read file '%s' in message db server\n",
				str);
		}
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (file_size < (ssize_t) sizeof(*msg_tmp)) {
		RRR_MSG_0("Empty or too small file '%s' found in message db server directory\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify(msg_tmp, (rrr_length) file_size) != 0) {
		RRR_MSG_0("Head verification step 1/2 of '%s' failed in message db server (possible invalid field values)\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (!RRR_MSG_IS_RRR_MESSAGE(msg_tmp)) {
		RRR_MSG_0("Message type of '%u' was not RRR message in message db server\n", msg_tmp->msg_type);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify((struct rrr_msg_msg *) msg_tmp, (rrr_biglength) file_size) != 0) {
		RRR_MSG_0("Head verification step 2/2 of '%s' failed in message db server\n", str);
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

	if ((ret = rrr_string_builder_append_raw (
			topic,
			MSG_TOPIC_PTR((struct rrr_msg_msg *) msg_tmp),
			MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp
	))) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_msgdb_server_idx (
		struct rrr_msgdb_server *server,
		int response_fd
) {
	int ret = 0;

	char *filename_tmp = NULL;
	struct rrr_string_builder topic_tmp = {0};
	struct rrr_array results_tmp = {0};
	struct rrr_array results_tmp_topics = {0};
	struct rrr_map paths_tmp = {0};
	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = __rrr_msgdb_server_idx_make_index (&results_tmp, server, 1 /* Single level only */)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&results_tmp, struct rrr_type_value);
		RRR_FREE_IF_NOT_NULL(filename_tmp);
		if ((ret = node->definition->to_str(&filename_tmp, node)) != 0) {
			goto out;
		}
		if (__rrr_msgdb_server_quick_topic_get (&topic_tmp, filename_tmp) != 0) {
			RRR_MSG_0("Warning: Failed to read message during idx in message db server\n");
			goto out;
		}
		if ((ret = rrr_array_push_value_str_with_tag(&results_tmp_topics, "file", rrr_string_builder_buf(&topic_tmp))) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	if ((ret = rrr_array_new_message_from_collection (
			&msg_tmp,
			&results_tmp_topics,
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
	rrr_string_builder_clear(&topic_tmp);
	rrr_map_clear(&paths_tmp);
	rrr_array_clear(&results_tmp);
	rrr_array_clear(&results_tmp_topics);
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	RRR_FREE_IF_NOT_NULL(filename_tmp);
	return ret;
}

static int __rrr_msgdb_server_get (
		struct rrr_msgdb_server *server,
		const char *str,
		const char *topic,
		int response_fd
) {
	int ret = 0;
	struct rrr_msg *msg_tmp  = NULL;

	if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
		goto out;
	}

	ssize_t file_size = 0;

	// Note that successful return is an error
	if (__rrr_msgdb_server_chdir(str, 1) == 0) {
		RRR_MSG_0("Could not read file '%s' in message db server, it was a directory\n",
			str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (rrr_socket_open_and_read_file((char **) &msg_tmp, &file_size, str, O_RDONLY, 0) != 0) {
		if (errno != EEXIST && errno != ENOENT) {
			RRR_MSG_0("Could not read file '%s' in message db server\n",
				str);
		}
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if (file_size < (ssize_t) sizeof(*msg_tmp)) {
		RRR_MSG_0("Empty or too small file '%s' found in message db server directory\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

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

	if (rrr_msg_head_to_host_and_verify(msg_tmp, (rrr_length) file_size) != 0) {
		RRR_MSG_0("Head verification step 2/4 of '%s' failed in message db server (possible invalid field values)\n", str);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;
	}

	if ((rrr_length) file_size != target_size_control) {
		RRR_MSG_0("Head verification step 3/4 of '%s' failed in message db server (actual size was %llu while %llu was excpected)\n",
				str,
				(unsigned long long) file_size,
				(unsigned long long) target_size_control
		);
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

	if ( MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp) != strlen(topic) ||
	     memcmp(MSG_TOPIC_PTR((struct rrr_msg_msg *) msg_tmp), topic, MSG_TOPIC_LENGTH((struct rrr_msg_msg *) msg_tmp)) != 0
	) {
		RRR_MSG_0("Warning: Hash error, collition or topic error for '%s' in message db server, requsted topic was '%s'",
			       str, topic);
		ret = RRR_MSGDB_SOFT_ERROR;
		goto out;

	}

	RRR_DBG_3("msgdb fd %i read from '%s' topic '%s' size %llu\n", response_fd, str, topic, (long long unsigned) MSG_TOTAL_SIZE(msg_tmp));

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

static int __rrr_msgdb_server_tidy (
		struct rrr_msgdb_server *server,
		uint32_t max_age,
		int response_fd
) {
	int ret = 0;

	struct rrr_array dirs_and_files = {0};
	uint64_t max_age_us = (uint64_t) max_age * 1000 * 1000;

	char *path_tmp = NULL;
	char *msg_tmp = NULL;

	if ((ret = __rrr_msgdb_server_idx_make_index (&dirs_and_files, server, 0 /* Multi-level */)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&dirs_and_files, struct rrr_type_value);
		if (!rrr_type_value_is_tag(node, "file")) {
			RRR_LL_ITERATE_NEXT();
		}

		if (!RRR_TYPE_IS_BLOB(node->definition->type)) {
			RRR_BUG("BUG: File path element was not of blob type in __rrr_msgdb_server_tidy\n");
		}
		if (node->total_stored_length > PATH_MAX) {
			RRR_BUG("BUG: File path length too long in __rrr_msgdb_server_tidy\n");
		}

		RRR_FREE_IF_NOT_NULL(path_tmp);
		RRR_FREE_IF_NOT_NULL(msg_tmp);

		if ((ret = node->definition->to_str(&path_tmp, node)) != 0) {
			RRR_MSG_0("Failed to extract string in __rrr_msgdb_server_tidy\n");
			goto out;
		}

		// The delete function might have chdir-ed the last round,
		// ensure we are still in base directory.
		if ((ret = __rrr_msgdb_server_chdir_base(server)) != 0) {
			goto out;
		}

		ssize_t msg_bytes_read = 0;
		ssize_t msg_size = 0;
		if (rrr_socket_open_and_read_file_head (
				&msg_tmp,
				&msg_bytes_read,
				&msg_size,
				path_tmp,
				O_RDONLY,
				0,
				sizeof(struct rrr_msg_msg)
		) != 0 || msg_bytes_read < (ssize_t) sizeof(struct rrr_msg_msg)) {
			RRR_MSG_0("Warning: msgdb failed to read header of '%s' during tidy (size %lli < %lli): %s. Deleting file.\n",
					path_tmp,
					msg_bytes_read,
					(ssize_t) sizeof(struct rrr_msg_msg),
					rrr_strerror(errno)
			);
			goto delete;
		}

		struct rrr_msg_msg *msg = (struct rrr_msg_msg *) msg_tmp;

		rrr_length target_size_control = 0;
		if (rrr_msg_get_target_size_and_check_checksum (
				&target_size_control,
				(const struct rrr_msg *) msg,
				sizeof(struct rrr_msg)
		) != 0) {
			RRR_MSG_0("Warning: msgdb header checksum failed for '%s' during tidy, deleting file.\n",
					path_tmp);
			goto delete;
		}

		if ( rrr_msg_head_to_host_and_verify((struct rrr_msg *) msg, (rrr_length) msg_size) != 0 ||
		     rrr_msg_msg_to_host_and_verify(msg, (rrr_biglength) msg_size) != 0
		) {
			RRR_MSG_0("Warning: msgdb head verification failed for '%s' during tidy, deleting file.\n",
				path_tmp);
			goto delete;
		}

		// Do not perform checksum test, only the message head has been read in

		if (!rrr_msg_msg_ttl_ok(msg, max_age_us)) {
			RRR_DBG_3("msgdb del '%s' (tidy)\n",
					path_tmp
			);
			goto delete;
		}

		// OK
		RRR_LL_ITERATE_NEXT();

		// Error / delete file
		delete:
		if (__rrr_msgdb_server_del_raw(server, path_tmp) != 0) {
			RRR_MSG_0("Warning: msgdb deletion failed for '%s' during tidy\n", path_tmp);
		}
	RRR_LL_ITERATE_END();

	ret = __rrr_msgdb_server_send_msg_ack(server, response_fd);

	out:
	rrr_array_clear(&dirs_and_files);
	RRR_FREE_IF_NOT_NULL(path_tmp);
	RRR_FREE_IF_NOT_NULL(msg_tmp);
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

	if (MSG_TOPIC_LENGTH(*msg) == 0 && MSG_TYPE(*msg) != MSG_TYPE_IDX) {
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
		case MSG_TYPE_IDX:
			if ((ret = __rrr_msgdb_server_idx(server, client->fd)) == 0) {
				// IDX responds with a message upon success, no need for ACK
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
	struct rrr_msgdb_server *server = arg;

	(void)(client);

	if (RRR_MSG_CTRL_FLAGS(msg) & RRR_MSGDB_CTRL_F_PING) {
		RRR_DBG_3("msgdb fd %i recv PING\n", client->fd);
		return __rrr_msgdb_server_send_msg_pong(server, client->fd) ? RRR_MSGDB_EOF : 0;
	}

	if (RRR_MSG_CTRL_FLAGS(msg) & RRR_MSGDB_CTRL_F_TIDY) {
		RRR_DBG_3("msgdb fd %i recv TIDY max age %" PRIu32 " seconds\n", client->fd, msg->msg_value);
		return __rrr_msgdb_server_tidy(server, msg->msg_value, client->fd);
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

	*result = server;

	goto out;
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
