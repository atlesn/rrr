/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <unistd.h>

#include "log_socket.h"
#include "log.h"
#include "allocator.h"
#include "rrr_strerror.h"
#include "event/event.h"
#include "util/gnu.h"
#include "socket/rrr_socket.h"
#include "socket/rrr_socket_client.h"
#include "messages/msg_log.h"
#include "messages/msg_msg_struct.h"

#define RRR_LOG_SOCKET_SEND_CHUNK_WARN_LIMIT 10000
#define RRR_LOG_SOCKET_SEND_CHUNK_CRITICAL_LIMIT 100000

struct rrr_log_socket_sayer {
	int connected_fd;
	struct rrr_socket_options connected_options;
	struct rrr_socket_client_collection *client_collection;
	struct rrr_event_queue *queue;
};

struct rrr_log_socket_listener {
	char *listen_filename;
	int listen_fd;
	struct rrr_socket_client_collection *client_collection;
};

static struct rrr_log_socket_listener rrr_log_socket_listener = {0};
static _Thread_local struct rrr_log_socket_sayer rrr_log_socket_sayer = {0};

static int __rrr_log_socket_connect (
		int *fd,
		struct rrr_socket_options *options
) {
	const struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;

	int ret = 0;

	int fd_tmp;

	if ((ret = rrr_socket_unix_connect (
			&fd_tmp,
			"rrr_log_socket_child",
			listener->listen_filename,
			1 /* Nonblock */
	)) != RRR_SOCKET_OK) {
		RRR_MSG_0("Failed to connect to log socket '%s' in pid %li\n",
			listener->listen_filename, (long int) getpid());
		ret = 1;
		goto out;
	}

	/* When debug messages are active, the socket subsystem might
	   deadlock. We must extract the socket options first and pass
	   it ourselves for each write. */
	if ((ret = rrr_socket_get_options_from_fd (
			options,
			fd_tmp
	)) != 0) {
		RRR_MSG_0("Failed to get socket options in %s\n", __func__);
		goto out_close;
	}

	*fd = fd_tmp;

	goto out;
	out_close:
		rrr_socket_close(fd_tmp);
	out:
		return ret;
}

static void __rrr_log_socket_intercept_callback (
		RRR_LOG_PRINTF_INTERCEPT_ARGS
) {

	struct rrr_log_socket_listener *listener = private_arg; 
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	(void)(listener);

	assert(sayer->connected_fd > 0 && "No call to __rrr_log_socket_connect\n");

	struct rrr_msg_log *msg_log = NULL;
	rrr_length msg_size;
	rrr_length send_chunk_count;

	if (rrr_msg_msg_log_new (
			&msg_log,
			file,
			line,
			loglevel_translated,
			loglevel_orig,
			prefix,
			message
	) != 0) {
		fprintf(stderr, "Warning: Failed to create log message in %s\n", __func__);
		goto out;
	}

	msg_size = MSG_TOTAL_SIZE(msg_log);

	rrr_msg_msg_log_prepare_for_network(msg_log);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_log);

	// printf("MSG: %s\n", message);

	if (rrr_socket_client_collection_send_push (
			&send_chunk_count,
			sayer->client_collection,
			sayer->connected_fd,
			(void **) &msg_log,
			msg_size
	) != 0) {
		RRR_BUG("Failed to queue log message to main in pid %li. Bytes to send was %" PRIrrrl ". Cannot continue, aborting now.\n",
			(long int) getpid(),
			msg_size
		);
	}

	if (send_chunk_count > RRR_LOG_SOCKET_SEND_CHUNK_CRITICAL_LIMIT) {
		RRR_BUG("Send chunk limit exceeded with %" PRIrrrl " send chunks, pid is %li. Aborting now.\n",
			send_chunk_count, (long int) getpid());
	}
	else if (send_chunk_count > RRR_LOG_SOCKET_SEND_CHUNK_WARN_LIMIT) {
		fprintf(stderr, "Warning: %" PRIrrrl " send chunks with log messages in pid %li\n",
			send_chunk_count, (long int) getpid());
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_log);
}

static int __rrr_log_socket_read_callback (
		const struct rrr_msg_log *msg,
		void *arg1,
		void *arg2
) {
	(void)(arg1);
	(void)(arg2);

	int ret = 0;

	char *prefix;
	char *message;

	if ((ret = rrr_msg_msg_log_to_str (
			&prefix,
			&message,
			msg
	)) != 0) {
		RRR_MSG_0("Failed to allocate prefix and message in %s\n", __func__);
		goto out;
	}

	rrr_log_print_no_hooks (
		msg->file,
		msg->line,
		msg->loglevel_translated,
		msg->loglevel_orig,
		prefix,
		message
	);

	rrr_free(prefix);
	rrr_free(message);

	out:
	return ret;
}

int rrr_log_socket_bind (void) {
	struct rrr_log_socket_listener *target = &rrr_log_socket_listener;

	int ret = 0;

	assert(target->listen_fd == 0 && "Double call to rrr_log_socket_bind()");

	pid_t pid = getpid();
	if (rrr_asprintf(&target->listen_filename, "%s/rrr_log_socket.%i", rrr_config_global.run_directory, pid) <= 0) {
		RRR_MSG_0("Could not generate filename for log socket in %s\n", __func__);
		ret = 1;
		goto out_final;
	}

	unlink(target->listen_filename); // OK to ignore errors

	if (rrr_socket_unix_create_bind_and_listen(&target->listen_fd, "rrr_log_socket_main", target->listen_filename, 2, 1, 0, 0) != 0) {
		RRR_MSG_0("Could not create socket for log socket with filename '%s' in %s\n", target->listen_filename, __func__);
		ret = 1;
		goto out_free;
	}

	RRR_DBG_1("Bound to log socket %s\n", target->listen_filename);

	goto out_final;
//	out_close_socket:
//		rrr_socket_close(target->listen_fd);
	out_free:
		rrr_free(target->listen_filename);
		memset(target, '\0', sizeof(*target));
	out_final:
		return ret;
}

int rrr_log_socket_start_listen (
		struct rrr_event_queue *queue
) {
	struct rrr_log_socket_listener *target = &rrr_log_socket_listener;

	int ret = 0;

	assert(target->client_collection == NULL && "Double call to rrr_log_socket_start_listen");

	if (rrr_socket_client_collection_new(&target->client_collection, queue, "rrr_log_socket_main") != 0) {
		RRR_MSG_0("Could not create client collection for log socket in %s\n", __func__);
		ret = 1;
		goto out;
	}

	rrr_socket_client_collection_set_silent(target->client_collection, 1);
	rrr_socket_client_collection_event_setup (
			target->client_collection,
			NULL,
			NULL,
			target,
			1024 * 1024 * 1, // 1MB
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP,
			NULL,
			NULL,
			NULL, // msg
			NULL, // addr
			__rrr_log_socket_read_callback,
			NULL, // ctrl
			NULL, // stats
			NULL
	);

	if ((ret = rrr_socket_client_collection_listen_fd_push (
			target->client_collection,
			target->listen_fd
	)) != 0) {
		RRR_MSG_0("Failed to push listen fd in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

int rrr_log_socket_thread_start_say (
		struct rrr_event_queue *queue
) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	int ret = 0;

	assert(sayer->queue == NULL && "Queue must be null when say is stared");
	assert(sayer->client_collection == NULL && "Client collection must be null when say is stared");
	assert(sayer->connected_fd == 0 && "Connected fd must be zero when say is stared");

	// Must preserve event queue as it would otherwise be
	// destroyed prior to the sayer as thread shuts down
	sayer->queue = queue;
	rrr_event_queue_incref(queue);

	if ((ret = rrr_socket_client_collection_new (
			&sayer->client_collection,
			queue,
			"rrr_log_socket_fork"
	)) != 0) {
		RRR_MSG_0("Failed to create client collection in %s\n", __func__);
		goto out_decref;
	}
	
	rrr_socket_client_collection_set_silent(sayer->client_collection, 1);
	rrr_socket_client_collection_event_setup_write_only(sayer->client_collection, NULL, NULL, NULL);

	if ((ret = __rrr_log_socket_connect (
			&sayer->connected_fd,
			&sayer->connected_options
	)) != 0) {
		goto out_destroy_collection;
	}

	if ((ret = rrr_socket_client_collection_connected_fd_push (
			sayer->client_collection,
			sayer->connected_fd,
			RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
	)) != 0) {
		RRR_MSG_0("Failed to push fd in %s\n", __func__);
		goto out_close;
	}

	RRR_DBG_1("Log socket now connected in pid %li, setting intercept callback.\n", (long int) getpid());

	rrr_log_printf_thread_local_intercept_set (__rrr_log_socket_intercept_callback, NULL);
	
	goto out;
	out_decref:
		rrr_event_queue_destroy(queue);
		sayer->queue = NULL;
	out_close:
		rrr_socket_close(sayer->connected_fd);
		sayer->connected_fd = 0;
	out_destroy_collection:
		rrr_socket_client_collection_destroy(sayer->client_collection);
		sayer->client_collection = NULL;
	out:
		return ret;
}

int rrr_log_socket_after_fork (void) {
	struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;

	int ret = 0;

	if (listener->listen_fd > 0) {
		rrr_socket_close_no_unlink(listener->listen_fd);
		listener->listen_fd = 0;
	}

	if (listener->client_collection != NULL) {
		rrr_socket_client_collection_destroy(listener->client_collection);
		listener->client_collection = NULL;
	}

	goto out;
	out:
		return ret;
}

void rrr_log_socket_cleanup_sayer (void) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	rrr_log_printf_thread_local_intercept_set (NULL, NULL);

	if (sayer->connected_fd > 0) {
		// Should be closed when destroying client collection
	}
	if (sayer->client_collection != NULL)
		rrr_socket_client_collection_destroy(sayer->client_collection);
	if (sayer->queue != NULL)
		rrr_event_queue_destroy(sayer->queue);
}

void rrr_log_socket_cleanup_listener (void) {
	struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;

	if (listener->listen_fd > 0) {
		// Should be closed when destroying client collection
	}
	if (listener->client_collection != NULL)
		rrr_socket_client_collection_destroy(listener->client_collection);
	rrr_free(listener->listen_filename);
}

int rrr_log_socket_fds_get (
		int **log_fds,
		size_t *log_fds_count
) {
	const struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;
	const struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	int ret = 0;

	int *client_fds = NULL;
	size_t client_fds_count = 0;
	int *all_fds = NULL;
	size_t all_fds_count = 0;
	struct rrr_socket_client_collection *client_collection_use;

	assert((listener->client_collection || sayer->client_collection) && "Either client collection must be set");

	client_collection_use = sayer->client_collection != NULL
		? sayer->client_collection
		: listener->client_collection;

	if ((ret = rrr_socket_client_collection_get_fds(&client_fds, &client_fds_count, client_collection_use)) != 0) {
		goto out;
	}

	if ((all_fds = rrr_reallocate(client_fds, sizeof(*all_fds) * (client_fds_count + 2))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	client_fds = NULL;
	all_fds_count = client_fds_count;

	all_fds[all_fds_count++] = listener->listen_fd;
	all_fds[all_fds_count++] = sayer->connected_fd;

	*log_fds = all_fds;
	*log_fds_count = all_fds_count;

	out:
	RRR_FREE_IF_NOT_NULL(client_fds);
	return ret;
}
