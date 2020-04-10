/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include <read.h>

#include "../global.h"
#include "gnu.h"
#include "stats_engine.h"
#include "stats_message.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "rrr_socket_client.h"
#include "read.h"
#include "linked_list.h"
#include "vl_time.h"
#include "random.h"

struct rrr_stats_client {
	struct rrr_stats_engine *engine;
};

static int __rrr_stats_client_new (struct rrr_stats_client **target, struct rrr_stats_engine *engine) {
	struct rrr_stats_client *client = malloc(sizeof(*client));
	if (client == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_stats_client_new\n");
		return 1;
	}

	client->engine = engine;

	*target = client;

	return 0;
}

static void __rrr_stats_client_destroy (struct rrr_stats_client *client) {
	free(client);
}

static int __rrr_stats_client_new_void (void **target, void *private_data) {
	return __rrr_stats_client_new ((struct rrr_stats_client **) target, private_data);
}

static void __rrr_stats_client_destroy_void (void *client) {
	__rrr_stats_client_destroy (client);
}

static int __rrr_stats_named_message_list_destroy (struct rrr_stats_named_message_list *list) {
	RRR_LL_DESTROY(list, struct rrr_stats_message, rrr_stats_message_destroy(node));
	free(list);
	return 0;
}

static void __rrr_stats_named_message_list_collection_clear (struct rrr_stats_named_message_list_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_stats_named_message_list, __rrr_stats_named_message_list_destroy(node));
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

int rrr_stats_engine_init (struct rrr_stats_engine *stats) {
	int ret = 0;
	char *filename = NULL;

	memset (stats, '\0', sizeof(*stats));

	if (pthread_mutex_init(&stats->main_lock, 0) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in rrr_stats_engine_init\n");
		ret = 1;
		goto out;
	}

	pid_t pid = getpid();
	if (rrr_asprintf(&filename, RRR_TMP_PATH "/" RRR_STATS_SOCKET_PREFIX ".%i", pid) <= 0) {
		RRR_MSG_ERR("Could not generate filename for statistics socket\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	unlink(filename); // OK to ignore errors

	if (rrr_socket_unix_create_bind_and_listen(&stats->socket, "rrr_stats_engine", filename, 2, 1, 0) != 0) {
		RRR_MSG_ERR("Could not create socket for statistics engine with filename '%s'\n", filename);
		ret = 1;
		goto out_destroy_mutex;
	}

	if (rrr_socket_client_collection_init(&stats->client_collection, stats->socket, "rrr_stats_engine") != 0) {
		RRR_MSG_ERR("Could not initialize client collection in statistics engine\n");
		ret = 1;
		goto out_close_socket;
	}

	RRR_DBG_1("Statistics engine started, listening at %s\n", filename);
	stats->initialized = 1;

	goto out;

//	out_destroy_client_collection:
//		rrr_socket_client_collection_clear(&stats->client_collection);
	out_close_socket:
		rrr_socket_close(stats->socket);
	out_destroy_mutex:
		pthread_mutex_destroy(&stats->main_lock);
	out:
		RRR_FREE_IF_NOT_NULL(filename);
		return ret;
}

void rrr_stats_engine_cleanup (struct rrr_stats_engine *stats) {
	if (stats->initialized == 0) {
		return;
	}

	// Not waterproof, cleanup should not be called before threads have exited. This
	// is not possible, of course, if some thread is hanged up in which we take a
	// certain risk by destroying the mutex at program exit.
	pthread_mutex_lock(&stats->main_lock);

	rrr_socket_client_collection_clear(&stats->client_collection);
	__rrr_stats_named_message_list_collection_clear(&stats->named_message_list);

	stats->initialized = 0;

	pthread_mutex_unlock(&stats->main_lock);

	rrr_socket_close_ignore_unregistered(stats->socket);
	stats->socket = 0;
	pthread_mutex_destroy(&stats->main_lock);
}

struct rrr_stats_engine_read_callback_data {
	struct rrr_stats_engine *engine;
};

static int __rrr_stats_engine_read_callback (struct rrr_read_session *read_session, void *arg) {
	struct rrr_stats_engine *stats = arg;

	(void)(stats);

	// TODO : Handle data from client
	RRR_DBG_3("STATS RX size %li, data ignored\n", read_session->target_size);

	return 0;
}

static int __rrr_stats_engine_send_message_to_clients (struct rrr_stats_engine *stats, struct rrr_stats_message *message) {
	struct rrr_stats_message_packed message_packed;
	size_t total_size;

	rrr_stats_message_pack_and_flip (
			&message_packed,
			&total_size,
			message
	);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) &message_packed,
			RRR_SOCKET_MSG_TYPE_TREE_DATA,
			total_size,
			message->timestamp
	);

	rrr_socket_msg_checksum_and_to_network_endian (
			(struct rrr_socket_msg *) &message_packed
	);

	RRR_DBG_3("STATS TX size %lu sticky %i path %s\n",
			total_size,
			RRR_STATS_MESSAGE_FLAGS_IS_STICKY(message),
			message->path
	);

	return rrr_socket_client_collection_multicast_send (
			&stats->client_collection,
			(struct rrr_socket_msg *) &message_packed,
			total_size
	);
}

static int __rrr_stats_engine_send_messages_from_list (struct rrr_stats_engine *stats, struct rrr_stats_named_message_list *list) {
	int ret = 0;

	int has_clients = (rrr_socket_client_collection_count(&stats->client_collection) > 0 ? 1 : 0);

	uint64_t time_now = rrr_time_get_64();
	uint64_t sticky_send_limit = time_now - RRR_STATS_ENGINE_STICKY_SEND_INTERVAL_MS * 1000;

	// TODO : Consider having separate queue for sticky messages

	RRR_LL_ITERATE_BEGIN(list, struct rrr_stats_message);
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
			if (__rrr_stats_engine_send_message_to_clients(stats, node) != 0) {
				RRR_MSG_ERR("Error while sending message in __rrr_stats_engine_send_messages_from_list\n");
				ret = 1;
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, rrr_stats_message_destroy(node));

	out:
	return ret;
}

static int __rrr_stats_engine_send_messages (struct rrr_stats_engine *stats) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (__rrr_stats_engine_send_messages_from_list(stats, node) != 0) {
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_stats_engine_tick (struct rrr_stats_engine *stats) {
	int ret = 0;

	if (stats->initialized == 0) {
		RRR_DBG_1("Warning: Statistics engine was not initialized in main tick function\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);

	if (rrr_socket_client_collection_accept (
			&stats->client_collection,
			__rrr_stats_client_new_void,
			stats,
			__rrr_stats_client_destroy_void
	) != 0) {
		RRR_MSG_ERR("Error while accepting connections in rrr_stats_engine_tick\n");
		ret = 1;
		goto out_unlock;
	}

	struct rrr_stats_engine_read_callback_data callback_data = { stats };

	// Read from clients
	if ((ret = rrr_socket_client_collection_read (
			&stats->client_collection,
			sizeof(struct rrr_socket_msg),
			1024,
			0,
			RRR_SOCKET_READ_METHOD_RECVFROM,
			rrr_read_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__rrr_stats_engine_read_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_ERR("Error while reading from clients in stats engine\n");
		ret = 1;
		goto out_unlock;
	}

	// Send data to clients
	if ((ret = __rrr_stats_engine_send_messages(stats)) != 0) {
		RRR_MSG_ERR("Error while sending messages in rrr_stats_engine_tick\n");
		ret = 1;
		goto out_unlock;
	}

	out_unlock:
		pthread_mutex_unlock(&stats->main_lock);
	out:
		return ret;
}

static void __rrr_stats_engine_message_sticky_remove (
		struct rrr_stats_named_message_list *list,
		const char *path
) {
	RRR_LL_ITERATE_BEGIN(list, struct rrr_stats_message);
		if (RRR_STATS_MESSAGE_FLAGS_IS_STICKY(node) && strcmp(path, node->path) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(list, rrr_stats_message_destroy(node));
}

static int __rrr_stats_engine_message_register_nolock (
		struct rrr_stats_engine *stats,
		unsigned int stats_handle,
		const char *path_prefix,
		const struct rrr_stats_message *message
) {
	int ret = 0;
	char prefix_tmp[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1];

	struct rrr_stats_named_message_list *list = __rrr_stats_named_message_list_get(&stats->named_message_list, stats_handle);

	if (list == NULL) {
		RRR_MSG_ERR("List with handle %u not found in __rrr_stats_engine_message_register_nolock\n", stats_handle);
		ret = 1;
		goto out;
	}

	struct rrr_stats_message *new_message;

	if (rrr_stats_message_duplicate(&new_message, message) != 0) {
		RRR_MSG_ERR("Could not duplicate message in __rrr_stats_engine_message_register_nolock\n");
		ret = 1;
		goto out;
	}

	if (RRR_STATS_MESSAGE_FLAGS_IS_STICKY(new_message)) {
		__rrr_stats_engine_message_sticky_remove(list, new_message->path);
	}

	ret = snprintf(prefix_tmp, RRR_STATS_MESSAGE_PATH_MAX_LENGTH, "%s/%u/%s", path_prefix, stats_handle, message->path);
	if (ret >= RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_ERR("Path was too long in __rrr_stats_engine_message_register_nolock\n");
		ret = 1;
		goto out;
	}
	ret = 0;

	if (rrr_stats_message_set_path(new_message, prefix_tmp) != 0) {
		RRR_MSG_ERR("Could not set path in new message in __rrr_stats_engine_message_register_nolock\n");
		ret = 1;
		goto out;
	}

	RRR_LL_APPEND(list, new_message);
	new_message = NULL;

	out:
	if (new_message != NULL) {
		rrr_stats_message_destroy(new_message);
	}
	return ret;
}

static int __rrr_stats_engine_handle_exists_nolock (struct rrr_stats_engine *stats, unsigned int stats_handle) {
	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (node->owner_handle == stats_handle) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

static void __rrr_stats_engine_handle_unregister_nolock (struct rrr_stats_engine *stats, unsigned int stats_handle) {
	int did_unregister = 0;

	RRR_LL_ITERATE_BEGIN(&stats->named_message_list, struct rrr_stats_named_message_list);
		if (node->owner_handle == stats_handle) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
			did_unregister = 1;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stats->named_message_list, __rrr_stats_named_message_list_destroy(node));

	if (did_unregister != 1) {
		RRR_MSG_ERR("Warning: Statistics handle not found in __rrr_stats_engine_unregister_handle_nolock\n");
	}
}

static int __rrr_stats_engine_handle_register_nolock (struct rrr_stats_engine *stats, unsigned int stats_handle) {
	int ret = 0;

	struct rrr_stats_named_message_list *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_ERR("Could not allocate memory in _rrr_stats_engine_register_handle_nolock\n");
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
		RRR_DBG_1("Note: Could not create handle in rrr_stats_engine_handle_obtain, not initialized\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);

	unsigned int new_handle = 0;
	unsigned int iterations = 0;

	do {
		new_handle = rrr_rand();
		if (++iterations % 100000 == 0) {
			RRR_MSG_ERR("Warning: Huge number of handles in statistics engine (%i)\n", iterations);
		}
	} while (__rrr_stats_engine_handle_exists_nolock(stats, new_handle) != 0);

	if (__rrr_stats_engine_handle_register_nolock(stats, new_handle) != 0) {
		RRR_MSG_ERR("Could not register handle in rrr_stats_engine_obtain_handle\n");
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
		const struct rrr_stats_message *message
) {
	int ret = 0;

	if (stats->initialized == 0) {
		RRR_DBG_1("Warning: Statistics engine was not initialized while posting message\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);
	if (__rrr_stats_engine_message_register_nolock(stats, handle, path_prefix, message) != 0) {
		RRR_MSG_ERR("Could not register message in rrr_stats_engine_post_message\n");
		ret = 1;
		goto out_unlock;
	}

	out_unlock:
		pthread_mutex_unlock(&stats->main_lock);
	out:
		return ret;
}
