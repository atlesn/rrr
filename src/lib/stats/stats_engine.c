/*

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stddef.h>
#include <netdb.h>

#include "../log.h"
#include "../allocator.h"

#include "stats_engine.h"
#include "stats_message.h"
#include "../rrr_config.h"
#include "../read.h"
#include "../random.h"
#include "../event/event.h"
#include "../event/event_functions.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_client.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../util/rrr_time.h"
#include "../util/linked_list.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"

#define RRR_STATS_ENGINE_SEND_INTERVAL_MS 50
#define RRR_STATS_ENGINE_LOG_JOURNAL_MAX_ENTRIES 25
#define RRR_STATS_ENGINE_SEND_CHUNK_LIMIT 10000

struct rrr_stats_client {
	struct rrr_stats_engine *engine;
	int first_log_stream_messages_sent;
};

static void __rrr_stats_engine_log_stream_lock (struct rrr_stats_engine *engine) {
	pthread_mutex_lock(&engine->log_stream_lock); 
}

static void __rrr_stats_engine_journal_unlock (struct rrr_stats_engine *engine) {
	pthread_mutex_unlock(&engine->log_stream_lock);
}

static void __rrr_stats_engine_journal_unlock_void (void *arg) {
	struct rrr_stats_engine *engine = arg;
	__rrr_stats_engine_journal_unlock(engine);
}

#define STREAM_LOCK(engine)                                   \
    __rrr_stats_engine_log_stream_lock(engine);                 \
    pthread_cleanup_push(__rrr_stats_engine_journal_unlock_void, engine)

#define STREAM_UNLOCK()                                       \
    pthread_cleanup_pop(1)

static int __rrr_stats_engine_message_pack (
		const struct rrr_msg_stats *message,
		int (*callback)(
				struct rrr_msg *data,
				rrr_length size,
				void *callback_arg
		),
		void *callback_arg
) {
	struct rrr_msg_stats_packed message_packed;
	rrr_length total_size;

	rrr_msg_stats_pack_and_flip (
			&message_packed,
			&total_size,
			message
	);

	rrr_msg_populate_head (
			(struct rrr_msg *) &message_packed,
			RRR_MSG_TYPE_TREE_DATA,
			total_size,
			(rrr_u32) (message->timestamp / 1000 / 1000)
	);

	rrr_msg_checksum_and_to_network_endian (
			(struct rrr_msg *) &message_packed
	);

	// This is very noisy, disable. Causes self-genration of messages
	// with log_stream
/*	RRR_DBG_3("STATS TX size %lu sticky %i path %s\n",
			total_size,
			RRR_STATS_MESSAGE_FLAGS_IS_STICKY(message),
			message->path
	);*/

	return callback((struct rrr_msg *) &message_packed, total_size, callback_arg);
}

static int __rrr_stats_engine_rrr_message_to_network (
		struct rrr_msg_msg **message,
		int (*callback)(
				struct rrr_msg *data,
				rrr_length size,
				void *callback_arg
		),
		void *callback_arg
) {
	int ret = 0;

	rrr_length msg_total_size;

	assert(RRR_MSG_IS_RRR_MESSAGE(*message) && "Message must be RRR message");

	msg_total_size = MSG_TOTAL_SIZE(*message);

	rrr_msg_msg_prepare_for_network(*message);
	rrr_msg_checksum_and_to_network_endian ((struct rrr_msg *) *message);

	ret = callback((struct rrr_msg *) *message, msg_total_size, callback_arg);

	rrr_free(*message);
	*message = NULL;

	return ret;
}

int __rrr_stats_engine_multicast_send_intermediate (
		struct rrr_msg *data,
		rrr_length size,
		void *callback_arg
) {
	struct rrr_stats_engine *stats = callback_arg;

	rrr_length send_chunk_count_dummy = 0;
	rrr_socket_client_collection_send_push_const_multicast (
			&send_chunk_count_dummy,
			stats->client_collection,
			data,
			size,
			RRR_STATS_ENGINE_SEND_CHUNK_LIMIT
	);
	return 0;
}

static int __rrr_stats_client_new (
		struct rrr_stats_client **target,
		int fd,
		struct rrr_stats_engine *engine
) {
	(void)(fd);

	struct rrr_stats_client *client = rrr_allocate(sizeof(*client));
	if (client == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	memset(client, '\0', sizeof(*client));

	client->engine = engine;

	*target = client;

	return 0;
}

static void __rrr_stats_client_destroy (
		struct rrr_stats_client *client
) {
	rrr_free(client);
}

static int __rrr_stats_client_new_void (void **target, int fd, void *private_data) {
	return __rrr_stats_client_new ((struct rrr_stats_client **) target, fd, private_data);
}

static void __rrr_stats_client_destroy_void (void *client) {
	__rrr_stats_client_destroy (client);
}

static int __rrr_stats_message_pair_destroy (
		struct rrr_stats_message_pair *pair
) {
	if (pair->preface)
		rrr_msg_stats_destroy(pair->preface);
	if (pair->message)
		rrr_free(pair->message);
	rrr_free(pair);
	return 0;
}

static void __rrr_stats_message_pair_list_clear (
		struct rrr_stats_message_pair_list *list
) {
	RRR_LL_DESTROY(list, struct rrr_stats_message_pair, __rrr_stats_message_pair_destroy(node));
}

static int __rrr_stats_message_pair_list_push (
		struct rrr_stats_message_pair_list *list,
		struct rrr_msg_stats **preface,
		struct rrr_msg_msg **message
) {
	int ret = 0;

	struct rrr_stats_message_pair *pair;
       
	if ((pair = rrr_allocate(sizeof(*pair))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	pair->preface = *preface;
	pair->message = *message;

	RRR_LL_APPEND(list, pair);

	*preface = NULL;
	*message = NULL;

	out:
	return ret;
}

static int __rrr_stats_named_message_list_destroy (
		struct rrr_stats_named_message_list *list
) {
	RRR_LL_DESTROY(list, struct rrr_msg_stats, rrr_msg_stats_destroy(node));
	rrr_free(list);
	return 0;
}

static void __rrr_stats_named_message_list_collection_clear (
		struct rrr_stats_named_message_list_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_stats_named_message_list, __rrr_stats_named_message_list_destroy(node));
}

static void __rrr_stats_log_stream_clear (
		struct rrr_stats_log_stream *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_msg_stats, rrr_msg_stats_destroy(node));
}

static struct rrr_stats_named_message_list *__rrr_stats_named_message_list_get (
		struct rrr_stats_named_message_list_collection *collection,
		unsigned int handle
) {
	struct rrr_stats_named_message_list *result = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_stats_named_message_list);
		if (node->owner_handle == handle) {
			result = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return result;
}

static int __rrr_stats_engine_has_clients (
		struct rrr_stats_engine *stats
) {
	// > 1 because we have the listen socket
	return rrr_socket_client_collection_count(stats->client_collection) > 1;
}

static int __rrr_stats_engine_send_messages_from_list_unlocked (
		struct rrr_stats_engine *stats,
		struct rrr_stats_named_message_list *list
) {
	int ret = 0;

	int has_clients = __rrr_stats_engine_has_clients(stats);

	uint64_t time_now = rrr_time_get_64();
	uint64_t sticky_send_limit = time_now - RRR_STATS_ENGINE_STICKY_SEND_INTERVAL_MS * 1000;

	// TODO : Consider having separate queue for sticky messages

	RRR_LL_ITERATE_BEGIN(list, struct rrr_msg_stats);
		if (RRR_STATS_MESSAGE_FLAGS_IS_STICKY(node)) {
			if (node->timestamp == 0 || node->timestamp <= sticky_send_limit) {
				node->timestamp = time_now;
			}
			else {
				// Don't send this sticky message now, skip to next message
				RRR_LL_ITERATE_NEXT();
			}
		}
		else {
			// Non-sticky messages are only sent once (if there's anybody out there)
			node->timestamp = time_now;
			RRR_LL_ITERATE_SET_DESTROY();
		}

		if (has_clients) {
			if (__rrr_stats_engine_message_pack (
					node,
					__rrr_stats_engine_multicast_send_intermediate,
					stats
			) != 0) {
				RRR_MSG_0("Error while sending message in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, rrr_msg_stats_destroy(node));

	out:
	return ret;
}

static int __rrr_stats_engine_send_messages (
		struct rrr_stats_engine *stats
) {
	int ret = 0;

	pthread_mutex_lock(&stats->main_lock);
	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (__rrr_stats_engine_send_messages_from_list_unlocked(stats, node) != 0) {
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	pthread_mutex_unlock(&stats->main_lock);
	return ret;
}

static void __rrr_stats_engine_chunk_send_start_callback(RRR_SOCKET_CLIENT_SEND_START_END_CALLBACK_ARGS) {
	struct rrr_stats_engine *stats = arg;
	STREAM_LOCK(stats);
	assert(stats->in_send_ctx_tid == 0);
	stats->in_send_ctx_tid = rrr_gettid();
	STREAM_UNLOCK();
}

static void __rrr_stats_engine_chunk_send_end_callback(RRR_SOCKET_CLIENT_SEND_START_END_CALLBACK_ARGS) {
	struct rrr_stats_engine *stats = arg;
	STREAM_LOCK(stats);
	stats->in_send_ctx_tid = 0;
	STREAM_UNLOCK();
}

static int __rrr_stats_engine_event_str_hook_data_available (
		RRR_EVENT_FUNCTION_ARGS
) {
	struct rrr_stats_engine *stats = arg;

	int amount_int = *amount;

	STREAM_LOCK(stats);
	while (--amount_int >= 0) {
		struct rrr_msg_stats *node = RRR_LL_SHIFT(&stats->log_stream);
		if (node == NULL) {
			// Can happen after forking
			break;
		}
		__rrr_stats_engine_message_pack(node, __rrr_stats_engine_multicast_send_intermediate, stats);
		rrr_msg_stats_destroy(node);
	}
	STREAM_UNLOCK();

	*amount = 0;

	return 0;
}

static int __rrr_stats_engine_send_rrr_message (
		struct rrr_stats_engine *stats,
		const struct rrr_msg_stats *message_preface,
		struct rrr_msg_msg **message
);

static int __rrr_stats_engine_event_msg_hook_data_available (
		RRR_EVENT_FUNCTION_ARGS
) {
	struct rrr_stats_engine *stats = arg;

	int ret = 0;

	int amount_int = *amount;

	STREAM_LOCK(stats);

	while (--amount_int >= 0) {
		struct rrr_stats_message_pair *node = RRR_LL_SHIFT(&stats->message_pairs);
		if ((ret = __rrr_stats_engine_send_rrr_message(stats, node->preface, &node->message)) != 0) {
			RRR_MSG_0("Error while sending message in %s\n", __func__);
		}
		__rrr_stats_message_pair_destroy(node);
		if (ret != 0) {
			goto out;
		}
	}

	*amount = 0;

	out:
	STREAM_UNLOCK();
	return ret;
}

static void __rrr_stats_engine_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_stats_engine *stats = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if ( __rrr_stats_engine_send_messages(stats)) {
		RRR_MSG_0("Error while sending messages in %s\n", __func__);
		rrr_event_dispatch_break(stats->queue);
	}
}
	
static int __rrr_stats_engine_read_callback (
		const struct rrr_msg_stats *message,
		void *arg1,
		void *arg2
) {
	(void)(message);
	(void)(arg1);
	(void)(arg2);

	// Only keepalive messages are received, no useful content

	return 0;
}

static int __rrr_stats_engine_event_pass_msg_hook_retry_callback (
		void *arg
) {
	struct rrr_stats_engine *stats = arg;

	(void)(stats);

	fprintf(stderr, "Error: Too many hooked messages, a build-up has occured. Consider reducing message rates while debugging.\n");

	return RRR_EVENT_ERR;
}

static int __rrr_stats_engine_event_pass_str_hook_retry_callback (
		void *arg
) {
	struct rrr_stats_engine *stats = arg;

 	(void)(stats);

	fprintf(stderr, "Error: Too many hooked log messages or events, a build-up has occured. Consider reducing rates while debugging.\n");

	return RRR_EVENT_ERR;
}

// To provide memory fence, this must be called prior to any thread starting or forking
int rrr_stats_engine_init (
		struct rrr_stats_engine *stats,
		struct rrr_event_queue *queue
) {
	int ret = 0;
	char *filename = NULL;

	memset (stats, '\0', sizeof(*stats));

	pid_t pid = getpid();
	if (rrr_asprintf(&filename, "%s/" RRR_STATS_SOCKET_PREFIX ".%i", rrr_config_global.run_directory, pid) <= 0) {
		RRR_MSG_0("Could not generate filename for statistics socket\n");
		ret = 1;
		goto out_final;
	}

	unlink(filename); // OK to ignore errors

	if (rrr_posix_mutex_init(&stats->main_lock, 0) != 0) {
		RRR_MSG_0("Could not initialize main mutex in %s\n", __func__);
		ret = 1;
		goto out_final;
	}

	if (rrr_socket_unix_create_bind_and_listen(&stats->socket, "rrr_stats_engine", filename, 2, 1, 0, 0) != 0) {
		RRR_MSG_0("Could not create socket for statistics engine with filename '%s'\n", filename);
		ret = 1;
		goto out_destroy_main_lock;
	}

	if (rrr_socket_client_collection_new(&stats->client_collection, queue, "rrr_stats_engine") != 0) {
		RRR_MSG_0("Could not create client collection in statistics engine\n");
		ret = 1;
		goto out_close_socket;
	}

	rrr_socket_client_collection_mask_write_event_hooks_setup (
			stats->client_collection,
			1 /* Set */
	);

	rrr_socket_client_collection_send_notify_setup_with_gates (
			stats->client_collection,
			NULL,
			__rrr_stats_engine_chunk_send_start_callback,
			__rrr_stats_engine_chunk_send_end_callback,
			stats
	);

	rrr_socket_client_collection_event_setup (
			stats->client_collection,
			__rrr_stats_client_new_void,
			__rrr_stats_client_destroy_void,
			stats,
			1024,
			RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			__rrr_stats_engine_read_callback,
			NULL
	);

	if (rrr_socket_client_collection_listen_fd_push (stats->client_collection, stats->socket) != 0) {
		RRR_MSG_0("Could not push listen handle to client collection in statistics engine\n");
		ret = 1;
		goto out_destroy_client_collection;
	}

	if (rrr_posix_mutex_init(&stats->log_stream_lock, RRR_POSIX_MUTEX_IS_RECURSIVE) != 0) {
		RRR_MSG_0("Could not initialize journal mutex in %s\n", __func__);
		ret = 1;
		goto out_destroy_client_collection;
	}

	rrr_event_collection_init(&stats->events, queue);

	if ((ret = rrr_event_collection_push_periodic (
			&stats->event_periodic,
			&stats->events,
			__rrr_stats_engine_event_periodic,
			stats,
			1 * 1000 * 1000 // 1 s
	)) != 0) {
		RRR_MSG_0("Could not create periodic event in %s\n", __func__);
		goto out_destroy_log_stream_lock;
	}

	EVENT_ADD(stats->event_periodic);

	rrr_event_function_set_with_arg (
			queue,
			RRR_EVENT_FUNCTION_STR_HOOK_DATA_AVAILABLE,
			__rrr_stats_engine_event_str_hook_data_available,
			stats,
			"stats engine journal data available"
	);

	rrr_event_function_set_with_arg (
			queue,
			RRR_EVENT_FUNCTION_MSG_HOOK_DATA_AVAILABLE,
			__rrr_stats_engine_event_msg_hook_data_available,
			stats,
			"stats engine msg hook data available"
	);

	RRR_DBG_1("Statistics engine started, listening at %s, log hook handle is %i\n",
			filename, stats->log_hook_handle);

	stats->queue = queue;
	stats->initialized = 1;

	goto out_final;
	out_destroy_log_stream_lock:
		pthread_mutex_destroy(&stats->log_stream_lock);
	out_destroy_client_collection:
		rrr_socket_client_collection_destroy(stats->client_collection);
	out_close_socket:
		rrr_socket_close(stats->socket);
	out_destroy_main_lock:
		pthread_mutex_destroy(&stats->main_lock);
	out_final:
		RRR_FREE_IF_NOT_NULL(filename);
		return ret;
}

void rrr_stats_engine_cleanup (
		struct rrr_stats_engine *stats
) {
	if (stats->initialized == 0) {
		return;
	}

	// Not waterproof, cleanup should not be called before threads have exited. This
	// is not possible, of course, if some thread is hanged up in which we take a
	// certain risk by destroying the mutex at program exit.
	pthread_mutex_lock(&stats->main_lock);

	rrr_socket_client_collection_destroy(stats->client_collection);
	__rrr_stats_named_message_list_collection_clear(&stats->named_message_list);
	__rrr_stats_message_pair_list_clear (&stats->message_pairs);
	__rrr_stats_log_stream_clear(&stats->log_stream);

	stats->initialized = 0;

	pthread_mutex_unlock(&stats->main_lock);

	rrr_event_collection_clear(&stats->events);
	rrr_socket_close_ignore_unregistered(stats->socket);
	stats->socket = 0;
	pthread_mutex_destroy(&stats->main_lock);
	pthread_mutex_destroy(&stats->log_stream_lock);
}


static void __rrr_stats_engine_message_sticky_remove_nolock (
		struct rrr_stats_named_message_list *list,
		const char *path
) {
	RRR_LL_ITERATE_BEGIN(list, struct rrr_msg_stats);
		if (RRR_STATS_MESSAGE_FLAGS_IS_STICKY(node) && strcmp(path, node->path) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, rrr_msg_stats_destroy(node));
}

static int __rrr_stats_engine_message_set_path (
		struct rrr_msg_stats *message,
		unsigned int stats_handle,
		const char *path_prefix
) {
	int ret = 0;

	char prefix_tmp[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1];

	ret = snprintf(prefix_tmp, RRR_STATS_MESSAGE_PATH_MAX_LENGTH, "%s/%u/%s", path_prefix, stats_handle, message->path);
	if (ret >= RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_0("Path was too long in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_msg_stats_set_path(message, prefix_tmp)) != 0) {
		RRR_MSG_0("Could not set path in new message in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_stats_engine_message_register_nolock (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle,
		const char *path_prefix,
		const struct rrr_msg_stats *message
) {
	int ret = 0;

	struct rrr_stats_named_message_list *list = __rrr_stats_named_message_list_get(&stats->named_message_list, stats_handle);

	if (list == NULL) {
		RRR_MSG_0("List with handle %u not found in %s\n", stats_handle, __func__);
		assert(0);
		ret = 1;
		goto out_final;
	}

	struct rrr_msg_stats *new_message = NULL;

	if (rrr_msg_stats_duplicate(&new_message, message) != 0) {
		RRR_MSG_0("Could not duplicate message in %s\n", __func__);
		ret = 1;
		goto out_final;
	}

	if (RRR_STATS_MESSAGE_FLAGS_IS_STICKY(new_message)) {
		__rrr_stats_engine_message_sticky_remove_nolock(list, new_message->path);
	}

	if ((ret = __rrr_stats_engine_message_set_path (
			new_message,
			stats_handle,
			path_prefix
	)) != 0) {
		goto out_free;
	}

	RRR_LL_APPEND(list, new_message);
	new_message = NULL;

	goto out_final;
	out_free:
		rrr_msg_stats_destroy(new_message);
	out_final:
		return ret;
}

static int __rrr_stats_engine_handle_exists_nolock (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle
) {
	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (node->owner_handle == stats_handle) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

static void __rrr_stats_engine_handle_unregister_nolock (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle
) {
	int did_unregister = 0;

	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (node->owner_handle == stats_handle) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
			did_unregister = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stats->named_message_list, __rrr_stats_named_message_list_destroy(node));

	if (did_unregister != 1) {
		RRR_MSG_0("Warning: Statistics handle not found in %s\n", __func__);
	}
}

static int __rrr_stats_engine_handle_register_nolock (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle
) {
	int ret = 0;

	struct rrr_stats_named_message_list *entry = rrr_allocate(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	entry->owner_handle = stats_handle;

	RRR_LL_APPEND(&stats->named_message_list, entry);

	out:
	return ret;
}

int rrr_stats_engine_handle_obtain (
		unsigned int *handle,
		struct rrr_stats_engine *stats
) {
	int ret = 0;

	*handle = 0;

	if (stats->initialized == 0) {
		RRR_DBG_1("Note: Could not create handle in %s, not initialized\n", __func__);
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);

	unsigned int new_handle = 0;
	unsigned int iterations = 0;

	do {
		new_handle = (unsigned int) rrr_rand();
		if (++iterations % 100000 == 0) {
			RRR_MSG_0("Warning: Huge number of handles in statistics engine (%i)\n", iterations);
		}
	} while (__rrr_stats_engine_handle_exists_nolock(stats, new_handle) != 0);

	if (__rrr_stats_engine_handle_register_nolock(stats, new_handle) != 0) {
		RRR_MSG_0("Could not register handle in %s\n", __func__);
		ret = 1;
		goto out_unlock;
	}

	*handle = new_handle;

	out_unlock:
		pthread_mutex_unlock(&stats->main_lock);
	out:
		return ret;
}

void rrr_stats_engine_handle_unregister (
		struct rrr_stats_engine *stats,
		unsigned int handle
) {
	if (stats->initialized == 0) {
		RRR_DBG_1("Warning: Statistics engine was not initialized while unregistering handle\n");
		return;
	}

	pthread_mutex_lock(&stats->main_lock);
	__rrr_stats_engine_handle_unregister_nolock(stats, handle);
	pthread_mutex_unlock(&stats->main_lock);
}

int rrr_stats_engine_post_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const struct rrr_msg_stats *message
) {
	int ret = 0;

	if (stats->initialized == 0) {
		RRR_DBG_1("Warning: Statistics engine was not initialized while posting message\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);
	if (__rrr_stats_engine_message_register_nolock(stats, handle, path_prefix, message) != 0) {
		RRR_MSG_0("Could not register message in %s\n", __func__);
		ret = 1;
		goto out_unlock;
	}

	out_unlock:
		pthread_mutex_unlock(&stats->main_lock);
	out:
		return ret;
}

static int __rrr_stats_engine_send_rrr_message (
		struct rrr_stats_engine *stats,
		const struct rrr_msg_stats *message_preface,
		struct rrr_msg_msg **message
) {
	int ret = 0;

	if (!__rrr_stats_engine_has_clients(stats)) {
		goto out;
	}

	if (__rrr_stats_engine_message_pack (
			message_preface,
			__rrr_stats_engine_multicast_send_intermediate,
			stats
	) != 0) {
		RRR_MSG_0("Error while sending preface in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (__rrr_stats_engine_rrr_message_to_network (
			message,
			__rrr_stats_engine_multicast_send_intermediate,
			stats
	) != 0) {
		RRR_MSG_0("Error while sending message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_stats_engine_push_stream_message (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle,
		const char *path_prefix,
		const struct rrr_msg_stats *message
) {
	int ret = 0;

	struct rrr_msg_stats *message_copy = NULL;
	uint16_t write_amount = 0;

	STREAM_LOCK(stats);

	if (stats->in_send_ctx_tid == rrr_gettid()) {
		goto out;
	}

	if ((ret = rrr_msg_stats_duplicate(&message_copy, message)) != 0) {
		goto out;
	}

	if ((ret = __rrr_stats_engine_message_set_path (
			message_copy,
			stats_handle,
			path_prefix
	)) != 0) {
		goto out;
	}

	RRR_LL_APPEND(&stats->log_stream, message_copy);
	message_copy = NULL;
	write_amount++;

	out:
	STREAM_UNLOCK();
	if (message_copy)
		rrr_msg_stats_destroy(message_copy);

	if (write_amount > 0) {
		ret |= rrr_event_pass (
				stats->queue,
				RRR_EVENT_FUNCTION_STR_HOOK_DATA_AVAILABLE,
				write_amount,
				 __rrr_stats_engine_event_pass_str_hook_retry_callback,
				stats
		);
	}

	return ret;
}

static int __rrr_stats_engine_push_rrr_message (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle,
		const char *path_prefix,
		const struct rrr_msg_stats *message_preface,
		const struct rrr_msg_msg *message
) {
	int ret = 0;

	struct rrr_msg_msg *message_copy = NULL;
	struct rrr_msg_stats *preface_copy = NULL;
	uint16_t write_amount = 0;

	if ((ret = rrr_msg_stats_duplicate(&preface_copy, message_preface)) != 0) {
		RRR_MSG_0("Could not duplicate preface in %s\n");
		goto out;
	}

	if ((message_copy = rrr_msg_msg_duplicate(message)) == NULL) {
		RRR_MSG_0("Could not duplicate message in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_stats_engine_message_set_path (
			preface_copy,
			stats_handle,
			path_prefix
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_stats_message_pair_list_push (
			&stats->message_pairs,
			&preface_copy,
			&message_copy
	)) != 0) {
		RRR_MSG_0("Could not push message pair in %s\n", __func__);
		goto out;
	}

	write_amount++;

	out:
	if (message_copy)
		rrr_free(message_copy);

	if (preface_copy)
		rrr_free(preface_copy);

	if (write_amount > 0) {
		ret |= rrr_event_pass (
				stats->queue,
				RRR_EVENT_FUNCTION_MSG_HOOK_DATA_AVAILABLE,
				write_amount,
				__rrr_stats_engine_event_pass_msg_hook_retry_callback,
				NULL
		);
	}

	return ret;
}

int rrr_stats_engine_push_rrr_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const char *path_postfix,
		const struct rrr_msg_msg *message,
		const char **hop_names,
		uint32_t hop_count
) {
	int ret = 0;

	struct rrr_msg_stats preface;

	STREAM_LOCK(stats);

	if ((ret = rrr_msg_stats_init_rrr_msg_preface (
			&preface,
			path_postfix,
			hop_names,
			hop_count
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_stats_engine_push_rrr_message (
			stats,
			handle,
			path_prefix,
			&preface,
			message
	)) != 0) {
		goto out;
	}

	out:
	STREAM_UNLOCK();
	return ret;
}

static int __rrr_stats_engine_push_text_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const char *data,
		int (*init_func)(struct rrr_msg_stats *, const void *, uint32_t)
) {
	int ret = 0;

	struct rrr_msg_stats message_tmp;
	char *str_tmp = NULL;

	if ((str_tmp = rrr_strdup(data)) == NULL) {
		RRR_MSG_0("Could not duplicate string in %s\n", __func__);
		ret = 1;
		goto out;
	}

	rrr_length str_size = rrr_length_inc_bug_const(rrr_length_from_size_t_bug_const (strlen(str_tmp)));

	if (str_size > RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		str_size = RRR_STATS_MESSAGE_DATA_MAX_SIZE;
		str_tmp[RRR_STATS_MESSAGE_DATA_MAX_SIZE - 1] = '\0';
	}

	if ((ret = init_func (
			&message_tmp,
			str_tmp,
			str_size
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_stats_engine_push_stream_message (
			stats,
			handle,
			path_prefix,
			&message_tmp
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(str_tmp);
	return ret;
}

int rrr_stats_engine_push_log_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const char *data
) {
	return __rrr_stats_engine_push_text_message (
			stats,
			handle,
			path_prefix,
			data,
			rrr_msg_stats_init_log
	);
}

int rrr_stats_engine_push_event_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const char *data
) {
	return __rrr_stats_engine_push_text_message (
			stats,
			handle,
			path_prefix,
			data,
			rrr_msg_stats_init_event
	);
}
