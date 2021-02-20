/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <event2/event.h>

#include "../log.h"

#include "rrr_socket.h"
#include "rrr_socket_client.h"
#include "rrr_socket_read.h"
#include "rrr_socket_constants.h"
#include "rrr_socket_send_chunk.h"

#include "../read.h"
#include "../rrr_strerror.h"
#include "../messages/msg.h"
#include "../util/posix.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

struct rrr_socket_client_collection_event_callback_data {
	struct rrr_socket_client_collection *collection;
	struct event_base *event_base;

	int  (*callback_private_data_new)(void **target, int fd, void *private_arg);
	void (*callback_private_data_destroy)(void *private_data);
	void *callback_private_data_arg;

	int  (*callback_periodic)(void *arg);
	void *callback_periodic_arg;
	int callback_periodic_ret;

	ssize_t read_step_max_size;
	int read_flags_socket;
	RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_SEMICOLON;
	void *callback_arg;
};

struct rrr_socket_client {
	RRR_LL_NODE(struct rrr_socket_client);

	int connected_fd;

	struct rrr_read_session_collection read_sessions;
	struct rrr_socket_send_chunk_collection send_chunks;

	struct event *event_read;
	struct event *event_write;
	struct rrr_socket_client_collection_event_callback_data *event_callback_data;

	struct sockaddr_storage addr;
	socklen_t addr_len;

	uint64_t last_seen;

	void *private_data;
	void (*private_data_destroy)(void *private_data);
};

static int __rrr_socket_client_destroy (
		struct rrr_socket_client *client
) {
	if (client->connected_fd > 0) {
		rrr_socket_close(client->connected_fd);
	}
	rrr_read_session_collection_clear(&client->read_sessions);
	if (client->private_data != NULL) {
		client->private_data_destroy(client->private_data);
	}
	if (client->event_read != NULL) {
		event_del(client->event_read);
		event_free(client->event_read);
	}
	if (client->event_write != NULL) {
		event_del(client->event_write);
		event_free(client->event_write);
	}
	rrr_socket_send_chunk_collection_clear(&client->send_chunks);
	free(client);
	return 0;
}

static int __rrr_socket_client_new (
		struct rrr_socket_client **result,
		int fd,
		struct sockaddr *addr,
		socklen_t addr_len,
		int (*private_data_new)(void **target, int fd, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
) {
	int ret = 0;

	*result = NULL;

	struct rrr_socket_client *client = malloc (sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_client_new\n");
		ret = 1;
		goto out;
	}

	memset(client, '\0', sizeof(*client));

	if (addr_len > sizeof(client->addr)) {
		RRR_BUG("Address length too long in __rrr_socket_client_new\n");
	}

	client->connected_fd = fd;
	memcpy (&client->addr, addr, addr_len);
	client->addr_len = addr_len;
	client->last_seen = rrr_time_get_64();

	if (private_data_new != NULL) {
		if (private_data_destroy == NULL) {
			RRR_BUG("BUG: A new function was defined but no destroy function in __rrr_socket_client_new\n");
		}

		if ((ret = private_data_new(&client->private_data, fd, private_arg)) != 0) {
			RRR_MSG_0("Error while initializing private data in __rrr_socket_client_new\n");
			ret = 1;
			goto out_free;
		}

		client->private_data_destroy = private_data_destroy;
	}
	else if (private_data_destroy != NULL) {
		RRR_BUG("BUG: A destroy function was defined but no new function in __rrr_socket_client_new\n");
	}

	*result = client;
	goto out;

	out_free:
		free (client);
	out:
		return ret;
}

void rrr_socket_client_collection_clear (
		struct rrr_socket_client_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_socket_client,__rrr_socket_client_destroy(node));
	RRR_FREE_IF_NOT_NULL(collection->creator);
	collection->listen_fd = 0;
}

void __rrr_socket_client_collection_clear_void (
		void *collection
) {
	rrr_socket_client_collection_clear (collection);
}

int rrr_socket_client_collection_init (
		struct rrr_socket_client_collection *collection,
		int listen_fd,
		const char *creator
) {
	memset(collection, '\0', sizeof(*collection));
	collection->creator = strdup(creator);
	if (collection->creator == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_socket_client_collection_init\n");
		return 1;
	}
	collection->listen_fd = listen_fd;
	return 0;
}

int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

int rrr_socket_client_collection_iterate (
		struct rrr_socket_client_collection *collection,
		int (*callback)(int fd, void *private_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if ((ret = callback(node->connected_fd, node->private_data, callback_arg)) != 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			if (ret == RRR_READ_SOFT_ERROR || ret == RRR_READ_EOF) {
				ret = 0;
			}
			else {
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy(node));

	out:
	return ret;
}

static void __rrr_socket_client_collection_find_and_destroy (
		struct rrr_socket_client_collection *collection,
		const struct rrr_socket_client *client
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node == client) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy(node));
}

struct rrr_socket_client_collection_read_raw_complete_callback_data {
		struct rrr_socket_client *client;
		int (*complete_callback)(struct rrr_read_session *read_session, void *private_data, void *arg);
		void *complete_callback_arg;
};

static int __rrr_socket_client_collection_read_raw_complete_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_socket_client_collection_read_raw_complete_callback_data *callback_data = arg;

	return callback_data->complete_callback (
		read_session,
		callback_data->client->private_data,
		callback_data->complete_callback_arg
	);
}

static int __rrr_socket_client_read_raw (
		struct rrr_socket_client *client,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *private_data, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;

	struct rrr_socket_client_collection_read_raw_complete_callback_data complete_callback_data = {
		client,
		complete_callback,
		complete_callback_arg
	};

	uint64_t timeout = rrr_time_get_64() - (RRR_SOCKET_CLIENT_TIMEOUT_S * 1000 * 1000);

	uint64_t bytes_read = 0;
	if ((ret = rrr_socket_read_message_default (
			&bytes_read,
			&client->read_sessions,
			client->connected_fd,
			read_step_initial,
			read_step_max_size,
			0, // No max size
			read_flags_socket,
			get_target_size,
			get_target_size_arg,
			__rrr_socket_client_collection_read_raw_complete_callback,
			&complete_callback_data
	)) == 0) {
		client->last_seen = rrr_time_get_64();
	}
	else if (ret == RRR_READ_INCOMPLETE) {
		// OK, mask
		ret = 0;
	}
	else if (ret == RRR_READ_EOF) {
		// OK, propagate
	}
	else if (ret == RRR_READ_SOFT_ERROR) {
		RRR_DBG_7("Disconnecting fd %i in client collection following soft error\n", client->connected_fd);
		// Mask with EOF
		ret = RRR_READ_EOF;
	}
	else if (client->last_seen < timeout) {
		RRR_DBG_7("Disconnecting fd %i in client collection following inactivity timeout\n", client->connected_fd);
		ret = RRR_READ_EOF;
	}
	else {
		// Hard errror propagates
	}

	return ret;
}

int rrr_socket_client_collection_read_raw (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags_socket,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *private_data, void *arg),
		void *complete_callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if ((ret = __rrr_socket_client_read_raw (
				node,
				read_step_initial,
				read_step_max_size,
				read_flags_socket,
				get_target_size,
				get_target_size_arg,
				complete_callback,
				complete_callback_arg
		)) != 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			if (ret == RRR_READ_EOF) {
				ret = 0;
			}
			else {
				RRR_LL_ITERATE_LAST();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection,__rrr_socket_client_destroy(node));

	return ret;
}

struct rrr_socket_client_collection_read_message_complete_callback_data {
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_SEMICOLON;
		void *callback_arg;
};

static int __rrr_socket_client_collection_read_message_complete_callback (
		struct rrr_read_session *read_session,
		void *private_data,
		void *arg
) {
	int ret = 0;

	struct rrr_socket_client_collection_read_message_complete_callback_data *callback_data = arg;

	if (read_session->rx_buf_wpos > RRR_LENGTH_MAX) {
		RRR_MSG_0("Message was too long in __rrr_socket_client_collection_read_message_complete_callback\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	// Callbacks are allowed to set the pointer to NULL if they wish to take control of memory,
	// make sure no pointers to local variables are used but only the pointer to rx_buf_ptr

	ret = rrr_msg_to_host_and_verify_with_callback (
			(struct rrr_msg **) &read_session->rx_buf_ptr,
			(rrr_length) read_session->rx_buf_wpos,
			callback_data->callback_msg,
			callback_data->callback_addr_msg,
			callback_data->callback_log_msg,
			callback_data->callback_ctrl_msg,
			private_data,
			callback_data->callback_arg
	);

	out:
	return ret;
}

// TODO : Add disconnect notification callback for debug purposes

int rrr_socket_client_collection_read_message (
		struct rrr_socket_client_collection *collection,
		ssize_t read_step_max_size,
		int read_flags_socket,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
) {
	struct rrr_socket_client_collection_read_message_complete_callback_data complete_callback_data = {
			callback_msg,
			callback_addr_msg,
			callback_log_msg,
			callback_ctrl_msg,
			callback_arg
	};

	return rrr_socket_client_collection_read_raw (
			collection,
			sizeof(struct rrr_msg),
			read_step_max_size,
			read_flags_socket,
			rrr_read_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__rrr_socket_client_collection_read_message_complete_callback,
			&complete_callback_data
	);
}

static int __rrr_socket_client_send_tick (
		struct rrr_socket_client *client
) {
	int ret;

	if ((ret = rrr_socket_send_chunk_collection_sendto (
			&client->send_chunks,
			client->connected_fd,
			NULL,
			0
	)) != RRR_SOCKET_OK && ret != RRR_SOCKET_WRITE_INCOMPLETE) {
		RRR_DBG_7("Disconnecting fd %i in client collection following send error, return was %i\n",
				client->connected_fd, ret);
	}

	return ret;
}

void __rrr_socket_client_collection_event_write (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp = __rrr_socket_client_send_tick (client);

	if (ret_tmp != 0 && ret_tmp != RRR_SOCKET_WRITE_INCOMPLETE) {
		__rrr_socket_client_collection_find_and_destroy (client->event_callback_data->collection, client);
		// Do nothing more, also not on hard errors
		return;
	}

	if (RRR_LL_COUNT(&client->send_chunks) == 0) {
		event_del(client->event_write);
	}
}

void __rrr_socket_client_collection_event_read (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client *client = arg;

	(void)(fd);
	(void)(flags);

	struct rrr_socket_client_collection_read_message_complete_callback_data complete_callback_data = {
		client->event_callback_data->callback_msg,
		client->event_callback_data->callback_addr_msg,
		client->event_callback_data->callback_log_msg,
		client->event_callback_data->callback_ctrl_msg,
		client->event_callback_data->callback_arg
	};

	int ret_tmp = __rrr_socket_client_read_raw (
			client,
			sizeof(struct rrr_msg),
			client->event_callback_data->read_step_max_size,
			client->event_callback_data->read_flags_socket,
			rrr_read_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__rrr_socket_client_collection_read_message_complete_callback,
			&complete_callback_data
	);

	if (ret_tmp != 0) {
		__rrr_socket_client_collection_find_and_destroy (client->event_callback_data->collection, client);
		if (ret_tmp != RRR_READ_EOF) {
			event_base_loopbreak(client->event_callback_data->event_base);
		}
	}
}

static int __rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, int fd, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data),
		struct rrr_socket_client_collection_event_callback_data *event_callback_data
) {
	int ret = 0;

	struct rrr_socket_client *client_new = NULL;

	struct rrr_socket_client temp = {0};
	temp.addr_len = sizeof(temp.addr);

	ret = rrr_socket_accept(collection->listen_fd, (struct sockaddr *) &temp.addr, &temp.addr_len, collection->creator);
	if (ret == -1) {
		if (errno != EWOULDBLOCK) {
			RRR_MSG_0("Error while accepting connection in rrr_socket_client_collection_accept: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		ret = 0;
		goto out;
	}

	temp.connected_fd = ret;

	if ((ret = __rrr_socket_client_new (
			&client_new,
			temp.connected_fd,
			(struct sockaddr *) &temp.addr,
			temp.addr_len,
			private_data_new,
			private_arg,
			private_data_destroy
	)) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_socket_client_collection_accept\n");
		goto out;
	}

	RRR_DBG_7("Client connection accepted into collection with fd %i\n", temp.connected_fd);

	if (event_callback_data != NULL) {
		client_new->event_callback_data = event_callback_data;

		if ((client_new->event_read = event_new (
				event_callback_data->event_base,
				temp.connected_fd,
				EV_READ|EV_PERSIST,
				__rrr_socket_client_collection_event_read,
				client_new
		)) == NULL) {
			RRR_MSG_0("Failed to create read event in __rrr_socket_client_collection_accept\n");
			ret = 1;
			goto out;
		}

		if (event_add(client_new->event_read, NULL) != 0) {
			RRR_MSG_0("Failed to add read event in __rrr_socket_client_collection_accept\n");
			ret = 1;
			goto out;
		}

		if ((client_new->event_write = event_new (
				event_callback_data->event_base,
				temp.connected_fd,
				EV_WRITE|EV_PERSIST,
				__rrr_socket_client_collection_event_write,
				client_new
		)) == NULL) {
			RRR_MSG_0("Failed to create write event in __rrr_socket_client_collection_accept\n");
			ret = 1;
			goto out;
		}

		// Don't add write event yet, wait until data is pushed
	}

	RRR_LL_UNSHIFT(collection, client_new);
	client_new = NULL;

	out:
	if (client_new != NULL) {
		__rrr_socket_client_destroy(client_new);
	}
	return ret;
}

int rrr_socket_client_collection_accept (
		struct rrr_socket_client_collection *collection,
		int (*private_data_new)(void **target, int fd, void *private_arg),
		void *private_arg,
		void (*private_data_destroy)(void *private_data)
) {
	return __rrr_socket_client_collection_accept (
			collection,
			private_data_new,
			private_arg,
			private_data_destroy,
			NULL
	);
}

struct rrr_socket_client_collection_multicast_send_ignore_full_pipe_callback_data {
	void *data;
	size_t size;
};

static int __rrr_socket_client_collection_multicast_send_ignore_full_pipe_callback (
		int fd,
		void *private_data,
		void *arg
) {
	struct rrr_socket_client_collection_multicast_send_ignore_full_pipe_callback_data *callback_data = arg;

	(void)(private_data);

	int ret = 0;

	RRR_DBG_7("TX to fd %i in client collection\n", fd);

	ssize_t written_bytes_dummy = 0;
	if ((ret = rrr_socket_send_nonblock_check_retry(&written_bytes_dummy, fd, callback_data->data, callback_data->size)) != 0) {
		if (ret != RRR_SOCKET_WRITE_INCOMPLETE) {
			// TODO : This error message is useless because we don't know which client has disconnected
			RRR_DBG_7("Disconnecting fd %i in client collection following send error, return was %i\n", fd, ret);
			ret = RRR_READ_EOF;
		}
	}

	return ret;
}

int rrr_socket_client_collection_multicast_send_ignore_full_pipe (
		struct rrr_socket_client_collection *collection,
		void *data,
		size_t size
) {
	struct rrr_socket_client_collection_multicast_send_ignore_full_pipe_callback_data callback_data = {
		data,
		size
	};

	return rrr_socket_client_collection_iterate (
			collection,
			__rrr_socket_client_collection_multicast_send_ignore_full_pipe_callback,
			&callback_data
	);
}

static struct rrr_socket_client *__rrr_socket_client_collection_find_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		if (node->connected_fd == fd) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

int rrr_socket_client_collection_send_push (
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		ssize_t data_size
) {
	int ret = 0;

	struct rrr_socket_client *client = __rrr_socket_client_collection_find_by_fd(collection, fd);

	if (client == NULL) {
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_socket_send_chunk_collection_push (&client->send_chunks, data, data_size)) != 0) {
		goto out;
	}

	if (client->event_write != NULL) {
		if (event_add(client->event_write, NULL) != 0) {
			RRR_MSG_0("Failed to add event in rrr_socket_client_collection_send_push\n");
			ret = RRR_READ_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

void rrr_socket_client_collection_send_tick (
		struct rrr_socket_client_collection *collection
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_socket_client);
		int ret_tmp;
		if ((ret_tmp = __rrr_socket_client_send_tick (
			node
		)) != RRR_SOCKET_OK && ret_tmp != RRR_SOCKET_WRITE_INCOMPLETE) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_socket_client_destroy(node));
}

void __rrr_socket_client_collection_event_base_destroy_void (
		void *event_base
) {
	event_base_free(event_base);
}

void __rrr_socket_client_collection_event_destroy_void_dbl_ptr (
		void *arg
) {
	struct event **event = arg;
	if (*event != NULL) {
		event_free(*event);
	}
}

void __rrr_socket_client_collection_event_accept (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client_collection_event_callback_data *callback_data = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp;

	if ((ret_tmp = __rrr_socket_client_collection_accept (
			callback_data->collection,
			callback_data->callback_private_data_new,
			callback_data->callback_arg,
			callback_data->callback_private_data_destroy,
			callback_data
	)) != 0) {
		event_base_loopbreak(callback_data->event_base);
	}
}

void __rrr_socket_client_collection_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_socket_client_collection_event_callback_data *callback_data = arg;

	(void)(fd);
	(void)(flags);

	if ( callback_data->callback_periodic != NULL &&
	    (callback_data->callback_periodic_ret = callback_data->callback_periodic(callback_data->callback_arg)) != 0
	) {
		event_base_loopbreak(callback_data->event_base);
	}
}

int rrr_socket_client_collection_dispatch (
		struct rrr_socket_client_collection *collection,
		uint64_t periodic_interval_us,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int (*callback_periodic)(void *arg),
		void *callback_periodic_arg,
		ssize_t read_step_max_size,
		int read_flags_socket,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
) {
	int ret = 0;

	struct event_base *event_base = NULL;

	if ((event_base = event_base_new()) == NULL) {
		RRR_MSG_0("Could not create event base in rrr_socket_client_collection_dispatch\n");
		ret = 1;
		goto out_final;
	}

	pthread_cleanup_push(__rrr_socket_client_collection_event_base_destroy_void, event_base);

	// The clients including event struct must be destroyed prior to the base
	pthread_cleanup_push(__rrr_socket_client_collection_clear_void, collection);

	struct event *listen_event = NULL;
	struct event *periodic_event = NULL;

	pthread_cleanup_push(__rrr_socket_client_collection_event_destroy_void_dbl_ptr, &listen_event);
	pthread_cleanup_push(__rrr_socket_client_collection_event_destroy_void_dbl_ptr, &periodic_event);

	struct rrr_socket_client_collection_event_callback_data callback_data = {
		collection,
		event_base,
		callback_private_data_new,
		callback_private_data_destroy,
		callback_private_data_arg,
		callback_periodic,
		callback_periodic_arg,
		0,
		read_step_max_size,
		read_flags_socket,
		callback_msg,
		callback_addr_msg,
		callback_log_msg,
		callback_ctrl_msg,
		callback_arg
	};

	if ((listen_event = event_new (
			event_base,
			collection->listen_fd,
			EV_READ|EV_TIMEOUT|EV_PERSIST,
			__rrr_socket_client_collection_event_accept,
			&callback_data
	)) == NULL) {
		RRR_MSG_0("Failed to create listening event in rrr_socket_client_collection_dispatch\n");
		ret = 1;
		goto out;
	}

	struct timeval tv_interval = {0};

	tv_interval.tv_usec = periodic_interval_us % 1000000;
	tv_interval.tv_sec = (periodic_interval_us - tv_interval.tv_usec) / 1000000;

	if ((periodic_event = event_new (
			event_base,
			0,
			EV_PERSIST,
			__rrr_socket_client_collection_event_periodic,
			&callback_data
	)) == NULL) {
		RRR_MSG_0("Failed to create listening event in rrr_socket_client_collection_dispatch\n");
		ret = 1;
		goto out;
	}

	if (event_add(periodic_event, &tv_interval) || event_add(listen_event, NULL)) {
		RRR_MSG_0("Failed to add events in rrr_socket_client_collection_dispatch\n");
		event_del(periodic_event);
		event_del(listen_event);
		ret = 1;
		goto out;
	}

	if ((ret = event_base_dispatch(event_base)) != 0) {
		RRR_MSG_0("Error from event_base_dispatch in rrr_socket_client_collection_dispatch: %i\n", ret);
		ret = 1;
		goto out;
	}

	if (callback_data.callback_periodic_ret != 0) {
		ret = callback_data.callback_periodic_ret & ~(RRR_READ_EOF);
	}
	else if (event_base_got_break(event_base)) {
		ret = 1;
		goto out;
	}

	out:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
	out_final:
		return ret;
}
