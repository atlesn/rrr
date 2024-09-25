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
#include "event/event_collection.h"
#include "event/event_collection_struct.h"
#include "util/gnu.h"
#include "util/posix.h"
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
	struct rrr_event_collection events;
	struct rrr_event_handle event_periodic;
	struct rrr_event_handle event_connect;
};

struct rrr_log_socket_listener {
	char *listen_filename;
	int listen_fd;
	struct rrr_socket_client_collection *client_collection;
};

static struct rrr_log_socket_listener rrr_log_socket_listener = {0};
static _Thread_local struct rrr_log_socket_sayer rrr_log_socket_sayer = {0};
static _Thread_local pthread_mutex_t rrr_log_socket_reentry_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void __rrr_log_socket_connect_as_needed_sayer(void) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;
	
	int ret_tmp;
	int tmp_fd;
	int again_max = 10;

	if (sayer->connected_fd > 0 && rrr_socket_check_alive(sayer->connected_fd) == RRR_SOCKET_OK) {
		return;
	}

	while (--again_max) {
		if (sayer->connected_fd != 0) {
			RRR_MSG_ERR("Reconnecting log socket in pid %li...\n", (long int) getpid());
		}

		if (__rrr_log_socket_connect (
				&tmp_fd,
				&sayer->connected_options
		) != 0) {
			RRR_MSG_ERR("Reconnecting log socket in pid %li failed A.\n", (long int) getpid());
			continue;
		}

		rrr_posix_usleep(10 * 1000 /* 10 ms */);

		if ((ret_tmp = rrr_socket_client_collection_connected_fd_push (
				sayer->client_collection,
				tmp_fd,
				RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
		)) != 0) {
			RRR_MSG_ERR("Failed to push fd in %s: %i\n", __func__, ret_tmp);
			rrr_socket_close(tmp_fd);
			continue;
		}

		sayer->connected_fd = tmp_fd;

		return;
	}

	RRR_BUG("Max reconnect attempts, cannot continue.\n");
}

static void __rrr_log_socket_msg_send_sayer (
		struct rrr_msg *msg
) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	int ret_tmp = 0;
	rrr_length msg_size;
	rrr_length send_chunk_count;

	msg_size = MSG_TOTAL_SIZE(msg);
	rrr_msg_checksum_and_to_network_endian(msg);

	if (sayer->connected_fd == 0 || (ret_tmp = rrr_socket_client_collection_send_push_const (
			&send_chunk_count,
			sayer->client_collection,
			sayer->connected_fd,
			(void *) msg,
			msg_size
	)) != 0) {
		RRR_MSG_ERR("Warning: Failed to queue log socket message to main in pid %li. Return was %i. Bytes to send was %" PRIrrrl ".\n",
			(long int) getpid(),
			ret_tmp,
			msg_size
		);

		EVENT_ACTIVATE(sayer->event_connect);

		return;
	}

	if (send_chunk_count > RRR_LOG_SOCKET_SEND_CHUNK_CRITICAL_LIMIT) {
		RRR_BUG("Send chunk limit exceeded with %" PRIrrrl " send chunks queued for the log socket, pid is %li. Aborting now.\n",
			send_chunk_count, (long int) getpid());
	}
	else if (send_chunk_count > RRR_LOG_SOCKET_SEND_CHUNK_WARN_LIMIT) {
		RRR_MSG_ERR("Warning: %" PRIrrrl " send chunks with log socket messages in pid %li\n",
			send_chunk_count, (long int) getpid());
	}
}

static void __rrr_log_socket_intercept_callback (
		RRR_LOG_PRINTF_INTERCEPT_ARGS
) {

	struct rrr_log_socket_listener *listener = private_arg; 

	(void)(listener);

	struct rrr_msg_log *msg_log = NULL;

	// printf("Intercept %s", message);

	if (!(pthread_mutex_trylock(&rrr_log_socket_reentry_lock)) == 0) {
		RRR_MSG_ERR("Warning: Re-entry in log socket, possibly during re-connection. Logs are lost.\n");
		return;
	}

	if (rrr_msg_msg_log_new (
			&msg_log,
			file,
			line,
			loglevel_translated,
			loglevel_orig,
			prefix,
			message
	) != 0) {
		RRR_MSG_ERR("Warning: Failed to create log message in %s\n", __func__);
		goto out;
	}

	rrr_msg_msg_log_prepare_for_network(msg_log);

	__rrr_log_socket_msg_send_sayer((struct rrr_msg *) msg_log);

	out:
	pthread_mutex_unlock(&rrr_log_socket_reentry_lock);
	RRR_FREE_IF_NOT_NULL(msg_log);
}

static int __rrr_log_socket_read_log_callback (
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

static int __rrr_log_socket_read_ctrl_callback (
		const struct rrr_msg *msg,
		void *arg1,
		void *arg2
) {
	(void)(arg1);
	(void)(arg2);

	// Note that we do not respond with pong, the
	// client does not read anything.
	assert(RRR_MSG_CTRL_F_HAS(msg, RRR_MSG_CTRL_F_PING) && "Control message was not a ping");

	return 0;
}

int rrr_log_socket_bind (void) {
	struct rrr_log_socket_listener *target = &rrr_log_socket_listener;

	int ret = 0;

	//printf("Bind pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

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

	//printf("Starget listen pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

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
			__rrr_log_socket_read_log_callback,
			__rrr_log_socket_read_ctrl_callback,
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

static void __rrr_log_socket_send_ping_sayer (void) {
	struct rrr_msg msg_ctrl = {0};

	//printf("Send ping pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

	rrr_msg_populate_control_msg(&msg_ctrl, RRR_MSG_CTRL_F_PING, 0);

//	__rrr_log_socket_msg_send_sayer((struct rrr_msg *) &msg_ctrl);
}

static void __rrr_log_socket_event_periodic_sayer (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);
	(void)(arg);

	__rrr_log_socket_send_ping_sayer();
}

static void __rrr_log_socket_event_connect_sayer (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);
	(void)(arg);

	__rrr_log_socket_connect_as_needed_sayer();
}

int rrr_log_socket_thread_start_say (
		struct rrr_event_queue *queue
) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	int ret = 0;

	//printf("Thread start say pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

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
	rrr_socket_client_collection_set_no_unlink(sayer->client_collection, 1);
	rrr_socket_client_collection_event_setup_write_only(sayer->client_collection, NULL, NULL, NULL);

	rrr_event_collection_init(&sayer->events, queue);

	if ((ret = rrr_event_collection_push_periodic (
			&sayer->event_periodic,
			&sayer->events,
			__rrr_log_socket_event_periodic_sayer,
			NULL,
			1000 * 1000
			//RRR_SOCKET_CLIENT_HARD_TIMEOUT_S / 2
	)) != 0) {
		RRR_MSG_0("Failed to push periodic function in %s\n", __func__);
		// Note: Socket will be destroyed by client collection, skip out_close
		goto out_destroy_collection;
	}

	EVENT_ADD(sayer->event_periodic);

	if ((ret = rrr_event_collection_push_periodic (
			&sayer->event_connect,
			&sayer->events,
			__rrr_log_socket_event_connect_sayer,
			NULL,
			1000 * 1000
			//RRR_SOCKET_CLIENT_HARD_TIMEOUT_S / 2
	)) != 0) {
		RRR_MSG_0("Failed to push connect function in %s\n", __func__);
		// Note: Socket will be destroyed by client collection, skip out_close
		goto out_destroy_collection;
	}

	EVENT_ADD(sayer->event_connect);
	EVENT_ACTIVATE(sayer->event_connect);

	__rrr_log_socket_connect_as_needed_sayer();

	RRR_DBG_1("Log socket sayer pid %li setting intercept callback.\n", (long int) getpid());

	rrr_log_printf_thread_local_intercept_set (__rrr_log_socket_intercept_callback, NULL);
	
	goto out;
	out_destroy_collection:
		rrr_socket_client_collection_destroy(sayer->client_collection);
		sayer->client_collection = NULL;
	out_decref:
		rrr_event_queue_destroy(queue);
		sayer->queue = NULL;
	out:
		return ret;
}

int rrr_log_socket_after_fork (void) {
	struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;

	int ret = 0;

	//printf("After fork pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

	// Preserve filename only
	listener->listen_fd = 0;
	listener->client_collection = NULL;
//	memset(&rrr_log_socket_listener, '\0', sizeof(rrr_log_socket_listener));
/*	if (listener->client_collection != NULL) {
		rrr_socket_client_collection_set_no_unlink(listener->client_collection, 1);
		rrr_socket_client_collection_destroy(listener->client_collection);
	}
	else if (listener->listen_fd > 0) {
		rrr_socket_close_no_unlink(listener->listen_fd);
	}*/

//	listener->client_collection = NULL;
//	listener->listen_fd = 0;

	memset(&rrr_log_socket_sayer, '\0', sizeof(rrr_log_socket_sayer));
	rrr_log_printf_thread_local_intercept_set (NULL, NULL);

	goto out;
	out:
		return ret;
}

void rrr_log_socket_cleanup_sayer (void) {
	struct rrr_log_socket_sayer *sayer = &rrr_log_socket_sayer;

	//printf("Cleanup sayer pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

	rrr_log_printf_thread_local_intercept_set (NULL, NULL);

	rrr_event_collection_clear(&sayer->events);
	memset(&sayer->event_periodic, '\0', sizeof(sayer->event_periodic));
	memset(&sayer->event_connect, '\0', sizeof(sayer->event_connect));

	if (sayer->client_collection != NULL) {
		rrr_socket_client_collection_destroy(sayer->client_collection);
	}
	else if (sayer->connected_fd > 0) {
		rrr_socket_close_no_unlink(sayer->connected_fd);
	}

	sayer->client_collection = NULL;
	sayer->connected_fd = 0;

	if (sayer->queue != NULL)
		rrr_event_queue_destroy(sayer->queue);

	sayer->queue = NULL;
}

void rrr_log_socket_cleanup_listener (void) {
	struct rrr_log_socket_listener *listener = &rrr_log_socket_listener;

	//printf("Cleanup listener pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

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

	//printf("Get fds pid %i connected fd %i listen fd %i\n",
	//	getpid(), rrr_log_socket_sayer.connected_fd, rrr_log_socket_listener.listen_fd);

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
