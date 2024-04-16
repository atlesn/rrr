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

//#include <uv.h>
#include <raft.h>
//#include <raft/uv.h>
#include <unistd.h>
#include <fcntl.h>

#include "server.h"
#include "common.h"
#include "channel.h"
#include "channel_struct.h"
#include "message_store.h"

#include "../allocator.h"
#include "../array.h"
#include "../fork.h"
#include "../common.h"
#include "../rrr_strerror.h"
#include "../random.h"
#include "../rrr_path_max.h"
#include "../read_constants.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"
#include "../util/rrr_time.h"
#include "../util/rrr_endian.h"
#include "../util/gnu.h"
#include "../util/crc32.h"

#define RRR_RAFT_SERVER_DBG_EVENT(msg, ...) \
    RRR_DBG_3("Raft [%i][server] " msg "\n", state->bridge->server_id, __VA_ARGS__)

#define RRR_RAFT_SERVER_DBG_FILE(name, msg, ...) \
    RRR_DBG_3("Raft [%i][server][%s] " msg "\n", state->bridge->server_id, name, __VA_ARGS__)

#define RRR_RAFT_BRIDGE_DBG_ARGS(msg, ...) \
    RRR_DBG_3("Raft [%i][bridge] " msg "\n", bridge->server_id, __VA_ARGS__)

#define RRR_RAFT_BRIDGE_DBG(msg) \
    RRR_DBG_3("Raft [%i][bridge] " msg "\n", bridge->server_id)

#define RRR_RAFT_FILE_NAME_TEMPLATE_CLOSED_SEGMENT "%016llu-%016llu"
#define RRR_RAFT_FILE_NAME_PREFIX_METADATA "metadata"

#define RRR_RAFT_FILE_ARGS_CLOSED_SEGMENT(from, to) \
    RRR_RAFT_FILE_NAME_TEMPLATE_CLOSED_SEGMENT, (unsigned long long) from, (unsigned long long) to

#define RRR_RAFT_ARENA_SENTINEL

#define RRR_RAFT_DISK_FORMAT 1 /* Same format as C-raft */

struct rrr_raft_server_fsm_result {
	uint32_t req_index;
	enum rrr_raft_code code;
	struct rrr_msg_msg *msg;
};

struct rrr_raft_server_fsm_result_collection {
	struct rrr_raft_server_fsm_result *results;
	size_t wpos;
	size_t capacity;
};

enum rrr_raft_task_type {
	RRR_RAFT_TASK_TIMEOUT = 1,
	RRR_RAFT_TASK_READ_FILE = 2,
	RRR_RAFT_TASK_BOOTSTRAP = 3,
	RRR_RAFT_TASK_WRITE_FILE = 4
};

enum rrr_raft_file_type {
	RRR_RAFT_FILE_TYPE_CONFIGURATION = 1,
	RRR_RAFT_FILE_TYPE_METADATA = 2
};

struct rrr_raft_task_cb_data {
	void *ptr;
	union {
		char data[sizeof(uint64_t) * 3];
	};
};

struct rrr_raft_arena {
	void *data;
	size_t pos;
	size_t size;
};

typedef size_t rrr_raft_arena_handle;

#define RRR_RAFT_BRIDGE_READFILE_CB_ARGS \
    const char *name, char *buf, size_t buf_size, struct rrr_raft_task_cb_data *cb_data

#define RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS \
    const char *name, const char *data, size_t data_size, struct rrr_raft_task_cb_data *cb_data

struct rrr_raft_task {
	enum rrr_raft_task_type type;
	union {
		struct {
			uint64_t time;
		} timeout;
		struct {
			enum rrr_raft_file_type type;
			rrr_raft_arena_handle name;
			// Set by implementation if file exists and called upon acknowledge
			// until it returns 0 which means completion
			ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS);
			struct rrr_raft_task_cb_data cb_data;
		} readfile;
		struct {
			struct raft_configuration *configuration;
		} bootstrap;
		struct {
			enum rrr_raft_file_type type;
			rrr_raft_arena_handle name;
			// Set by implementation and called upon acknowledge
			// multiple times and the last time with 0 size which means completion
			ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS);
			struct rrr_raft_task_cb_data cb_data;
		} writefile;
	};
};

struct rrr_raft_task_list {
	struct rrr_raft_arena arena;
	rrr_raft_arena_handle tasks;
	size_t count;
	size_t capacity;
};

enum rrr_raft_bridge_state {
	RRR_RAFT_BRIDGE_STATE_STARTED = 1,
	RRR_RAFT_BRIDGE_STATE_CONFIGURED
};

struct rrr_raft_bridge_metadata {
	unsigned long long version;
	raft_term term;
	raft_id voted_for;
};

struct rrr_raft_bridge {
	struct raft *raft;
	int server_id;
	enum rrr_raft_bridge_state state;
	struct rrr_raft_bridge_metadata metadata;
	struct raft_configuration configuration;
};

struct rrr_raft_server_state {
	struct rrr_raft_channel *channel;
	struct rrr_raft_message_store *message_store_state;
	struct rrr_raft_bridge *bridge;
	struct rrr_raft_task_list *tasks;
	struct raft_configuration *configuration;
/*	uint32_t change_req_index;
	uint32_t transfer_req_index;
	uint32_t snapshot_req_index;*/
	struct rrr_raft_server_fsm_result_collection *fsm_results;
	struct {
		rrr_event_handle raft_timeout;
		rrr_event_handle socket;
	} events;
};

static inline void *__rrr_raft_server_malloc (void *data, size_t size) {
	(void)(data);
	return rrr_allocate(size);
}

static inline void __rrr_raft_server_free (void *data, void *ptr) {
	(void)(data);
	return rrr_free(ptr);
}

static inline void *__rrr_raft_server_calloc (void *data, size_t nmemb, size_t size) {
	(void)(data);
	return rrr_callocate(nmemb, size);
}

static inline void *__rrr_raft_server_realloc (void *data, void *ptr, size_t size) {
	(void)(data);
	return rrr_reallocate(ptr, size);
}

static inline void *__rrr_raft_server_aligned_alloc (void *data, size_t alignment, size_t size) {
	(void)(data);
	return rrr_aligned_allocate(alignment, size);
}

static inline void __rrr_raft_server_aligned_free (void *data, size_t alignment, void *ptr) {
	(void)(data);
	return rrr_aligned_free(alignment, ptr);
}

static void __rrr_raft_arena_cleanup (
		struct rrr_raft_arena *arena
) {
	RRR_FREE_IF_NOT_NULL(arena->data);
	arena->pos = 0;
	arena->size = 0;
}

static void __rrr_raft_arena_reset (
		struct rrr_raft_arena *arena
) {
	arena->pos = 0;
}

static rrr_raft_arena_handle __rrr_raft_arena_alloc (
		struct rrr_raft_arena *arena,
		size_t size
) {
	static const size_t align = sizeof(uint64_t);
	static const size_t alloc_min = 65536;

	size_t size_new, pos;
	void *data_new;

	assert(size > 0);

	size += align - (size % align);
#ifdef RRR_RAFT_ARENA_SENTINEL
	size += sizeof(uint64_t);
	if (arena->data != NULL && * (uint64_t *) (arena->data + arena->pos - sizeof(uint64_t)) != 0xdeadbeefdeadbeef) {
		RRR_BUG("BUG: Sentinel overwritten in %s, data is %016llx\n",
			__func__,
			(unsigned long long) * (uint64_t *) (arena->data + arena->pos - sizeof(uint64_t))
		);
	}
#endif /* RRR_RAFT_ARENA_SENTINEL */

	if (arena->pos + size > arena->size) {
		size_new = arena->size + size;
		size_new += alloc_min - (size_new % alloc_min);
		assert(size_new > arena->size);

		if ((data_new = rrr_reallocate(arena->data, size_new)) == NULL) {
			RRR_BUG("CRITICAL: Failed to allocate memory in %s\n", __func__);
		}

		arena->data = data_new;
		arena->size = size_new;
	}

#ifdef RRR_RAFT_ARENA_SENTINEL
	* (uint64_t *) (arena->data + arena->pos + size - sizeof(uint64_t)) = 0xdeadbeefdeadbeef;
#endif

	pos = arena->pos;
	arena->pos += size;
	return pos;
}

static inline void *__rrr_raft_arena_resolve (
		struct rrr_raft_arena *arena,
		rrr_raft_arena_handle handle
) {
	assert(handle < arena->pos);
	return arena->data + handle;
}

#define ARENA_RESOLVE(handle) \
    (arena->data + handle)

static rrr_raft_arena_handle __rrr_raft_arena_strdup (
		struct rrr_raft_arena *arena,
		const char *str
) {
	rrr_raft_arena_handle handle;
	char *data;
	size_t len;

	len = strlen(str);
	handle = __rrr_raft_arena_alloc(arena, len);
	data = ARENA_RESOLVE(handle);
	memcpy(data, str, len + 1);

	return handle;
}

static rrr_raft_arena_handle __rrr_raft_arena_memdup (
		struct rrr_raft_arena *arena,
		void *ptr,
		size_t size
) {
	rrr_raft_arena_handle handle_new;
	char *ptr_new;

	handle_new = __rrr_raft_arena_alloc(arena, size);
	ptr_new = ARENA_RESOLVE(handle_new);

	memcpy(ptr_new, ptr, size);

	return handle_new;
}

static rrr_raft_arena_handle __rrr_raft_arena_vasprintf (
		struct rrr_raft_arena *arena,
		const char *format,
		va_list args
) {
	char *tmp;
	rrr_raft_arena_handle handle;
	int bytes;

	if ((bytes = rrr_vasprintf(&tmp, format, args)) < 0) {
		RRR_BUG("CRITICAL: Failed to allocate memory in %s\n", __func__);
	}

	handle = __rrr_raft_arena_memdup(arena, tmp, bytes + 1);

	rrr_free(tmp);

	return handle;
}

static rrr_raft_arena_handle __rrr_raft_arena_realloc (
		struct rrr_raft_arena *arena,
		rrr_raft_arena_handle handle,
		size_t size,
		size_t oldsize
) {
	rrr_raft_arena_handle handle_new;
	void *ptr, *data;

	handle_new = __rrr_raft_arena_alloc(arena, size);
	data = ARENA_RESOLVE(handle_new);

	if (oldsize > 0) {
		ptr = ARENA_RESOLVE(handle);

		if (oldsize < size) {
			memcpy(data, ptr, oldsize);
		}
		else {
			memcpy(data, ptr, size);
		}
	}

	return handle_new;
}

static void __rrr_raft_task_list_push (
		struct rrr_raft_task_list *list,
		struct rrr_raft_task *task
) {
	struct rrr_raft_arena *arena = &list->arena;

	size_t capacity_new;
	struct rrr_raft_task *tasks;
	rrr_raft_arena_handle tasks_handle_new;

	if (list->count == list->capacity) {
		capacity_new = list->capacity + 4;
		tasks_handle_new = __rrr_raft_arena_realloc (
				&list->arena,
				list->tasks,
				sizeof(*tasks) * capacity_new,
				sizeof(*tasks) * list->capacity
		);
		tasks = ARENA_RESOLVE(tasks_handle_new);

		memset(tasks + list->capacity, '\0', sizeof(*tasks) * (capacity_new - list->capacity));

		list->capacity = capacity_new;
		list->tasks = tasks_handle_new;
	}
	else {
		tasks = ARENA_RESOLVE(list->tasks);
	}

	tasks[list->count++] = *task;
}

static void __rrr_raft_task_list_cleanup (
		struct rrr_raft_task_list *list
) {
	__rrr_raft_arena_cleanup(&list->arena);
}

static struct rrr_raft_task *__rrr_raft_task_list_get (
		struct rrr_raft_task_list *list
) {
	struct rrr_raft_arena *arena = &list->arena;
	return ARENA_RESOLVE(list->tasks);
}

static inline void *__rrr_raft_task_list_resolve (
		struct rrr_raft_task_list *list,
		rrr_raft_arena_handle handle
) {
	struct rrr_raft_arena *arena = &list->arena;
	return ARENA_RESOLVE(handle);
}

#define TASK_LIST_RESOLVE(handle) \
    (__rrr_raft_task_list_resolve(list, handle))

static rrr_raft_arena_handle __rrr_raft_task_list_strdup (
		struct rrr_raft_task_list *list,
		const char *str
) {
	struct rrr_raft_arena *arena = &list->arena;
	return __rrr_raft_arena_strdup(arena, str);
}

static rrr_raft_arena_handle __rrr_raft_task_list_asprintf (
		struct rrr_raft_task_list *list,
		const char *format,
		...
) {
	static rrr_raft_arena_handle handle;
	va_list args;

	va_start(args, format);

	handle = __rrr_raft_arena_vasprintf(&list->arena, format, args);

	va_end(args);

	return handle;
}

static void __rrr_raft_server_fsm_result_clear (
		struct rrr_raft_server_fsm_result *result
) {
	result->req_index = 0;
	result->code = 0;
	RRR_FREE_IF_NOT_NULL(result->msg);
}

static void __rrr_raft_server_fsm_result_set (
		struct rrr_raft_server_fsm_result *result,
		uint32_t req_index,
		struct rrr_msg_msg **msg,
		enum rrr_raft_code code
) {
	assert(result->msg == NULL);

	result->req_index = req_index;
	result->code = code;
	result->msg = *msg;

	*msg = NULL;
}

static int __rrr_raft_server_fsm_result_collection_push (
		struct rrr_raft_server_fsm_result_collection *results,
		uint32_t req_index,
		struct rrr_msg_msg **msg,
		enum rrr_raft_code code
) {
	int ret = 0;

	size_t i, capacity_new;
	struct rrr_raft_server_fsm_result *slot;

	for (i = 0; i < results->wpos; i++) {
		if ((slot = results->results + i)->msg != NULL)
			continue;

		__rrr_raft_server_fsm_result_set(slot, req_index, msg, code);

		goto out;
	}

	if (results->wpos == results->capacity) {
		capacity_new = results->capacity + 32;
		if ((slot = rrr_reallocate(results->results, sizeof(*slot) * capacity_new)) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memset(slot + results->capacity, '\0', sizeof(*slot) * (capacity_new - results->capacity));
		results->results = slot;
		results->capacity = capacity_new;
	}

	slot = results->results + results->wpos++;

	__rrr_raft_server_fsm_result_set(slot, req_index, msg, code);

	out:
	return ret;
}

static void __rrr_raft_server_fsm_result_collection_pull (
		struct rrr_raft_server_fsm_result *result,
		struct rrr_raft_server_fsm_result_collection *results,
		uint32_t req_index
) {
	size_t i;
	struct rrr_raft_server_fsm_result *slot;

	for (i = 0; i < results->wpos; i++) {
		if ((slot = results->results + i)->req_index != req_index) 
			continue;

		*result = *slot;
		*slot = (struct rrr_raft_server_fsm_result) {0};

		return;
	}

	RRR_BUG("BUG: Request %u not found in %s\n", req_index, __func__);
}

static void __rrr_raft_server_fsm_result_collection_clear (
		size_t *cleared_count,
		struct rrr_raft_server_fsm_result_collection *results
) {
	*cleared_count = 0;

	for (size_t i = 0; i < results->wpos; i++) {
		if (results->results[i].msg)
			(*cleared_count)++;
		__rrr_raft_server_fsm_result_clear(results->results + i);
	}
}

static enum rrr_raft_code __rrr_raft_server_status_translate (
		int status
) {
	switch (status) {
		case 0:
			return 0;
		case RAFT_LEADERSHIPLOST:
		case RAFT_NOTLEADER:
			return RRR_RAFT_NOT_LEADER;
	};

	return RRR_RAFT_ERROR;
}

static int __rrr_raft_server_make_opt_response_server_fields (
		struct rrr_array *array,
		struct raft *raft
) {
	int ret = 0;

	struct rrr_raft_server server_tmp;
	struct raft_server *raft_server;
	int ret_tmp, catch_up;
	unsigned i;
	size_t address_len;

	for (i = 0; i < raft->configuration.n; i++) {
		server_tmp = (struct rrr_raft_server) {0};

		raft_server = raft->configuration.servers + i;
		address_len = strlen(raft_server->address);

		assert(address_len < sizeof(server_tmp.address));
		memcpy(server_tmp.address, raft_server->address, address_len + 1);

		server_tmp.id = raft_server->id;

		switch (raft_server->role) {
			case RAFT_STANDBY:
				server_tmp.status = RRR_RAFT_STANDBY;
				break;
			case RAFT_VOTER:
				server_tmp.status = RRR_RAFT_VOTER;
				break;
			case RAFT_SPARE:
				server_tmp.status = RRR_RAFT_SPARE;
				break;
			default:
				RRR_BUG("Unknown role %i in %s\n", raft_server->role, __func__);
		};

		if (raft->state == RAFT_LEADER) {
			if ((ret_tmp = raft_catch_up (raft, raft_server->id, &catch_up)) != 0) {
				RRR_MSG_0("Failed to get catch up status for server %i in %s: %s %s\n",
					raft_server->id, __func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}

			switch (catch_up) {
				case RAFT_CATCH_UP_NONE:
					server_tmp.catch_up = RRR_RAFT_CATCH_UP_NONE;
					break;
				case RAFT_CATCH_UP_RUNNING:
					server_tmp.catch_up = RRR_RAFT_CATCH_UP_RUNNING;
					break;
				case RAFT_CATCH_UP_ABORTED:
					server_tmp.catch_up = RRR_RAFT_CATCH_UP_ABORTED;
					break;
				case RAFT_CATCH_UP_FINISHED:
					server_tmp.catch_up = RRR_RAFT_CATCH_UP_FINISHED;
					break;
				default:
					RRR_BUG("BUG: Unknown catch up code %i from raft library in %s\n",
						catch_up, __func__);
			};
		}
		else {
			server_tmp.catch_up = RRR_RAFT_CATCH_UP_UNKNOWN;
		}

		if ((ret = rrr_raft_opt_array_field_server_push (
				array,
				&server_tmp
		)) != 0) {
			RRR_MSG_0("Failed to push server in %s\n", __func__);
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_raft_server_make_opt_response (
		struct rrr_msg_msg **result,
		struct raft *raft,
		rrr_u32 req_index
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;
	struct rrr_array array_tmp = {0};
	raft_id leader_id;
	const char *leader_address;

	*result = NULL;

	raft_leader(raft, &leader_id, &leader_address);

	ret |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_IS_LEADER,
			raft->state == RAFT_LEADER
	);
	ret |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_LEADER_ID,
			leader_id
	);
	ret |= rrr_array_push_value_str_with_tag (
			&array_tmp,
			RRR_RAFT_FIELD_LEADER_ADDRESS,
			leader_address != NULL ? leader_address : ""
	);

	if (ret != 0) {
		RRR_MSG_0("Failed to push array values in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_raft_server_make_opt_response_server_fields (
			&array_tmp,
			raft
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_new_message_from_array (
			&msg,
			&array_tmp,
			rrr_time_get_64(),
			NULL,
			0
	)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_OPT);
	msg->msg_value = req_index;

	*result = msg;
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_raft_server_send_msg (
		struct rrr_raft_channel *channel,
		struct rrr_msg *msg
) {
	rrr_u32 total_size = MSG_TOTAL_SIZE(msg);

	if (RRR_MSG_IS_RRR_MESSAGE(msg)) {
		rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) msg);
	}
	rrr_msg_checksum_and_to_network_endian(msg);

	if (write(channel->fd_server, msg, total_size) != total_size) {
		if (errno == EPIPE) {
			return RRR_READ_EOF;
		}
		RRR_MSG_0("Failed to send message in %s: %s\n",
			__func__, rrr_strerror(errno));
		return RRR_READ_HARD_ERROR;
	}

	return RRR_READ_OK;
}

static int __rrr_raft_server_send_msg_in_loop (
		struct rrr_raft_server_state *state,
		struct rrr_msg *msg
) {
	int ret = 0;

	if ((ret = __rrr_raft_server_send_msg(state->channel, msg)) != 0) {
		if (ret == RRR_READ_EOF) {
			rrr_event_dispatch_exit(state->channel->queue);
			ret = 0;
			goto out;
		}

		RRR_MSG_0("Failed to send message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}


/*
static void __rrr_raft_server_change_cb_final (
		struct rrr_raft_server_state *callback_data,
		uint64_t req_index,
		int ok,
		enum rrr_raft_code code
) {
	struct rrr_msg msg_ack = {0};
	struct rrr_msg_msg *msg = NULL;

	rrr_msg_populate_control_msg (
			&msg_ack,
			ok ? RRR_MSG_CTRL_F_ACK : RRR_MSG_CTRL_F_NACK_REASON(code),
			req_index
	);

	if (__rrr_raft_server_make_opt_response (
			&msg,
			callback_data->raft,
			req_index
	) != 0) {
		return;
	}

	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);
	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, (struct rrr_msg *) msg);

	rrr_free(msg);
}

static void __rrr_raft_server_server_change_cb (
		struct raft_change *req,
		int status
) {
	struct rrr_raft_server_state *callback_data = req->data;

	enum rrr_raft_code code = __rrr_raft_server_status_translate(status);

	assert(callback_data->change_req_index > 0);

	__rrr_raft_server_change_cb_final (
			callback_data,
			callback_data->change_req_index,
			status == 0,
			code
	);

	req->data = NULL;
	callback_data->change_req_index = 0;
}

static void __rrr_raft_server_leadership_transfer_cb (
		struct raft_transfer *req
) {
	struct rrr_raft_server_state *callback_data = req->data;
	struct raft *raft = callback_data->raft;

	const char *address;
	raft_id id;
	enum rrr_raft_code code;

	assert(callback_data->transfer_req_index > 0);

	raft_leader(raft, &id, &address);

	if (id != (long long unsigned) callback_data->server_id) {
		RRR_DBG_1("Leader transfer OK to %llu %s\n", id, address);
		code = RRR_RAFT_OK;
	}
	else {
		RRR_DBG_1("Leader transfer NOT OK to %llu %s\n", id, address);
		code = RRR_RAFT_ERROR;
	}

	__rrr_raft_server_change_cb_final (
			callback_data,
			callback_data->transfer_req_index,
			req->id == 0 || id == req->id,
			code
	);

	req->data = NULL;
	callback_data->transfer_req_index = 0;
}

static void __rrr_raft_server_suggest_snapshot_cb (
		struct raft_suggest_snapshot *req,
		int status
) {
	struct rrr_raft_server_state *callback_data = req->data;

	struct rrr_msg msg_ack = {0};

	enum rrr_raft_code code = __rrr_raft_server_status_translate(status);

	rrr_msg_populate_control_msg (
			&msg_ack,
			code == RRR_RAFT_OK ? RRR_MSG_CTRL_F_ACK : RRR_MSG_CTRL_F_NACK_REASON(code),
			callback_data->snapshot_req_index
	);

	__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);

	req->data = NULL;
	callback_data->snapshot_req_index = 0;
}
*/
static int __rrr_raft_server_handle_cmd (
		struct rrr_raft_server_state *callback_data,
		rrr_u32 req_index,
		const struct rrr_msg_msg *msg
) {
//	struct raft *raft = callback_data->raft;

	(void)(callback_data);
	(void)(req_index);

	int ret = 0;

	struct rrr_array array_tmp = {0};
//	int ret_tmp;
//	int role;
	int64_t cmd, id;
	struct rrr_raft_server *servers;
	uint16_t version_dummy;

	if ((ret = rrr_array_message_append_to_array (
			&version_dummy,
			&array_tmp,
			msg
	)) != 0) {
		goto out;
	}

	if (rrr_array_get_value_signed_64_by_tag (
			&cmd,
			&array_tmp,
			RRR_RAFT_FIELD_CMD,
			0
	) != 0) {
		RRR_BUG("BUG: Command field missing in %s\n", __func__);
	}

	// Switch 1 of 2 (preparation)
	switch (cmd) {
		case RRR_RAFT_CMD_SERVER_ASSIGN:
		case RRR_RAFT_CMD_SERVER_ADD:
		case RRR_RAFT_CMD_SERVER_DEL: {
			if ((ret = rrr_raft_opt_array_field_server_get (
					&servers,
					&array_tmp
			)) != 0) {
				goto out;
			}

			// Only exactly one server may be added/deleted
			assert(servers && servers[0].id > 0 && servers[1].id == 0);

			assert(0 && "Del server not implemented\n");

//			assert(callback_data->change_req.data == NULL && callback_data->change_req_index == 0);
//			callback_data->change_req.data = callback_data;
//			callback_data->change_req_index = req_index;
		} break;
		case RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER: {
			if (rrr_array_get_value_signed_64_by_tag (
					&id,
					&array_tmp,
					RRR_RAFT_FIELD_ID,
					0
			) != 0) {
				RRR_BUG("BUG: ID field not set in transfer command in %s\n", __func__);
			}

			assert(0 && "Transfer leadership not implemented");

//			assert(callback_data->transfer_req.data == NULL && callback_data->transfer_req_index == 0);
//			callback_data->transfer_req.data = callback_data;
//			callback_data->transfer_req_index = req_index;
		} break;
		case RRR_RAFT_CMD_SNAPSHOT: {
			assert(0 && "snapshot cmd not implemented");
//			assert(callback_data->snapshot_req.data == NULL && callback_data->snapshot_req_index == 0);
//			callback_data->snapshot_req.data = callback_data;
//			callback_data->snapshot_req_index = req_index;
		} break;
		default:
			RRR_BUG("BUG: Unknown command %" PRIi64 " in %s\n", cmd, __func__);
	};

	// Switch 2 of 2 (execution)
	switch (cmd) {
		case RRR_RAFT_CMD_SERVER_ASSIGN: {
			switch (servers[0].status) {
				case RRR_RAFT_STANDBY:
//					role = RAFT_STANDBY;
					break;
				case RRR_RAFT_VOTER:
//					role = RAFT_VOTER;
					break;
				case RRR_RAFT_SPARE:
//					role = RAFT_SPARE;
					break;
				default:
					RRR_BUG("BUG: Unknown state %i in %s\n",
						servers[0].status, __func__);
			};

			assert(0 && "Assign not implemented");

/*			if ((ret_tmp = raft_assign (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					role,
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server assign failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_ADD: {
			RRR_DBG_1("Raft CMD add server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			assert(0 && "Server add not implemented");

/*			if ((ret_tmp = raft_add (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					servers[0].address,
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server add failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_DEL: {
			RRR_DBG_1("Raft CMD delete server %" PRIi64 " address %s\n", servers[0].id, servers[0].address);

			assert(0 && "Server del not implemented");

/*			if ((ret_tmp = raft_remove (
					raft,
					&callback_data->change_req,
					rrr_int_from_slength_bug_const(servers[0].id),
					__rrr_raft_server_server_change_cb
			)) != 0) {
				RRR_MSG_0("Server delete failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER: {
			RRR_DBG_1("Raft CMD transfer leadership to %" PRIi64 "\n", id);

			assert(0 && "Leadership transfer not implemented");

/*			if ((ret_tmp = raft_transfer (
					raft,
					&callback_data->transfer_req,
					rrr_int_from_slength_bug_const(id),
					__rrr_raft_server_leadership_transfer_cb
			)) != 0) {
				RRR_MSG_0("Server leadership transfer failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/
		} break;
		case RRR_RAFT_CMD_SNAPSHOT: {
			RRR_DBG_1("Raft CMD snapshot suggestion\n");

			assert(0 && "Snapshot suggestion not implemented");

/*			if ((ret_tmp = raft_suggest_snapshot (
					raft,
					&callback_data->snapshot_req,
					__rrr_raft_server_suggest_snapshot_cb
			)) != 0) {
				RRR_MSG_0("Snapshot suggestion failed in %s: %s %s\n",
					__func__, raft_errmsg(raft), raft_strerror(ret_tmp));
				ret = 1;
				goto out;
			}*/

		} break;
		default:
			RRR_BUG("BUG: Unknown command %" PRIi64 " in %s\n", cmd, __func__);
	};

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_raft_server_make_get_response (
		struct rrr_msg_msg **result,
		struct rrr_raft_message_store *message_store_state,
		rrr_u32 req_index,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	if ((ret = rrr_raft_message_store_get (
			result,
			message_store_state,
			MSG_TOPIC_PTR(msg),
			MSG_TOPIC_LENGTH(msg)
	)) != 0) {
		goto out;
	}

	assert(*result == NULL || MSG_IS_PUT(*result));

	if (*result)
		(*result)->msg_value = req_index;

	out:
	return ret;
}
/*
static void __rrr_raft_server_apply_cb (
		struct raft_apply *req,
		int status,
		void *result
) {
	struct rrr_raft_server_state *callback_data = req->data;
	uint32_t req_index = rrr_u32_from_ptr_bug_const(result);

	struct rrr_raft_server_fsm_result fsm_result;
	struct rrr_msg msg_ack = {0};
	enum rrr_raft_code code;

	__rrr_raft_server_fsm_result_collection_pull(&fsm_result, &callback_data->fsm_results, req_index);

	assert(fsm_result.msg != NULL && fsm_result.req_index == req_index);

	// Check errors from raft library
	if (status != 0) {
	       	if (status != RAFT_NOTLEADER) {
			RRR_MSG_0("Warning: Apply error: %s (%d)\n",
				raft_errmsg(callback_data->raft), status);
		}
		code = __rrr_raft_server_status_translate(status);
		goto nack;
	}

	// Check errors from FSM apply callback
	if (fsm_result.code != 0) {
		code = fsm_result.code;
		goto nack;
	}

	goto ack;
	ack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_ACK, fsm_result.msg->msg_value);
		goto send_msg;
	nack:
		rrr_msg_populate_control_msg(&msg_ack, RRR_MSG_CTRL_F_NACK_REASON(code), fsm_result.msg->msg_value);
		goto send_msg;

	send_msg:
		__rrr_raft_server_send_msg_in_loop(callback_data->channel, callback_data->loop, &msg_ack);
		__rrr_raft_server_fsm_result_clear(&fsm_result);

	goto out;
	out:
		raft_free(req);
}
*/
static int __rrr_raft_server_read_msg_cb (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_state *state = arg2;
	struct rrr_raft_bridge *bridge = state->bridge;
//	struct raft *raft = state->raft;

	(void)(arg1);

	int ret = 0;

//	int ret_tmp;
	struct raft_buffer buf = {0};
//	struct raft_apply *req;
	struct rrr_msg msg = {0};
	struct rrr_msg_msg *msg_msg = NULL;

	assert((*message)->msg_value > 0);

	if (MSG_IS_OPT(*message)) {
		if (MSG_IS_ARRAY(*message)) {
			ret = __rrr_raft_server_handle_cmd (
					state,
					(*message)->msg_value,
					(*message)
			);
			goto out;
		}

		if ((ret = __rrr_raft_server_make_opt_response (
				&msg_msg,
				bridge->raft,
				(*message)->msg_value
		)) != 0) {
			goto out;
		}

		goto out_send_msg_msg;
	}

	if (MSG_IS_GET(*message)) {
		if ((ret = __rrr_raft_server_make_get_response (
				&msg_msg,
				state->message_store_state,
				(*message)->msg_value,
				(*message)
		)) != 0) {
			goto out;
		}

		rrr_msg_populate_control_msg (
				&msg,
				msg_msg != NULL
					? RRR_MSG_CTRL_F_ACK
					: RRR_MSG_CTRL_F_NACK_REASON(RRR_RAFT_ENOENT),
				(*message)->msg_value
		);

		goto out_send_ctrl_msg;
	}

	if (bridge->raft->state != RAFT_LEADER) {
		RRR_MSG_0("Warning: Refusing message to be stored. Not leader.\n");
		rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_NACK_REASON(RRR_RAFT_NOT_LEADER), (*message)->msg_value);
		goto out_send_ctrl_msg;
	}

	buf.len = MSG_TOTAL_SIZE(*message) + 8 - MSG_TOTAL_SIZE(*message) % 8;
	if ((buf.base = raft_calloc(1, buf.len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for buffer in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// Message in message store on disk stored with network endianess
	memcpy(buf.base, *message, MSG_TOTAL_SIZE(*message));
	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) buf.base);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf.base);

	assert(0 && "Raft apply not implemented");

/*
	if ((req = raft_malloc(sizeof(*req))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for request in %s\n", __func__);
		ret = 1;
		goto out;
	}
*/
//	req->data = state;
/*
	if ((ret_tmp = raft_apply(raft, req, &buf, 1, __rrr_raft_server_apply_cb)) != 0) {
		// It appears that this data is usually freed also
		// upon error conditions.
		buf.base = NULL;

		RRR_MSG_0("Apply failed in %s: %s\n", __func__, raft_errmsg(raft));
		ret = 1;
		goto out;
	}
	else {
		buf.base = NULL;
	}
*/
	goto out;
//	out_free_req:
//		raft_free(req);
	out_send_ctrl_msg:
		// Status messages are to be emitted before result messages
		assert(0 && "Apply status message not implemented");
//		__rrr_raft_server_send_msg_in_loop(state->channel, state->loop, &msg);
	out_send_msg_msg:
		if (msg_msg != NULL) {
			__rrr_raft_server_send_msg_in_loop(state, (struct rrr_msg *) msg_msg);
		}
	out:
		RRR_FREE_IF_NOT_NULL(msg_msg);
		if (buf.base != NULL)
			raft_free(buf.base);
		return ret;
}

static int __rrr_raft_server_msg_to_host (
		struct rrr_msg_msg *msg,
		rrr_length actual_length
) {
	int ret = 0;

	rrr_length stated_length;
	int ret_tmp;

	if ((ret_tmp = rrr_msg_get_target_size_and_check_checksum (
			&stated_length,
			(struct rrr_msg *) msg,
			actual_length
	)) != 0) {
		RRR_MSG_0("Failed to get size of message in %s: %i\n", __func__, ret_tmp);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (actual_length < stated_length) {
		RRR_MSG_0("Actual length does not hold message stated size %" PRIrrrl "<%" PRIrrrl " in %s\n",
			actual_length, stated_length, __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify((struct rrr_msg *) msg, stated_length) != 0) {
		RRR_MSG_0("Header validation failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_check_data_checksum_and_length((struct rrr_msg *) msg, stated_length) != 0) {
		RRR_MSG_0("Data checksum validation failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify(msg, stated_length) != 0) {
		RRR_MSG_0("Message endian conversion failed in %s\n", __func__);
		ret = RAFT_MALFORMED;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_raft_server_buf_msg_to_host (
		struct rrr_msg_msg **msg,
		const struct raft_buffer *buf
) {
	int ret = 0;

	struct rrr_msg_msg *msg_tmp;

	assert(buf->len >= sizeof(*msg_tmp) - 1);
	assert(buf->len <= UINT32_MAX);

	if ((msg_tmp = rrr_allocate(buf->len)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for message in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	memcpy(msg_tmp, buf->base, buf->len);

	if ((ret = __rrr_raft_server_msg_to_host (msg_tmp, buf->len)) != 0) {
		goto out;
	}

	*msg = msg_tmp;
	msg_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int __rrr_raft_server_read_msg_ctrl_cb (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	struct rrr_raft_server_state *state = arg2;

	(void)(arg1);

	struct rrr_msg msg = {0};

	assert(RRR_MSG_CTRL_F_HAS(message, RRR_MSG_CTRL_F_PING));

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);

	return __rrr_raft_server_send_msg_in_loop(state, &msg);
}

static void __rrr_raft_server_read_cb (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_raft_server_state *state = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp;
	uint64_t bytes_read_dummy;

	if ((ret_tmp = rrr_socket_read_message_split_callbacks (
			&bytes_read_dummy,
			&state->channel->read_sessions,
			state->channel->fd_server,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_READ_MESSAGE_FLUSH_OVERSHOOT,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			__rrr_raft_server_read_msg_cb,
			NULL,
			NULL,
			__rrr_raft_server_read_msg_ctrl_cb,
			NULL,
			NULL, /* first cb data */
			state
	)) != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
		RRR_MSG_0("Read failed in %s: %i\n", __func__, ret_tmp);
		rrr_event_dispatch_break(state->channel->queue);
	}
}

/*
static int __rrr_raft_server_fsm_apply_cb (
		struct raft_fsm *fsm,
		const struct raft_buffer *buf,
		void **result
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;
	int was_found;
	enum rrr_raft_code code = 0;
	uint32_t req_index;

	*result = NULL;

	assert(buf->len <= UINT32_MAX);

	if ((ret = __rrr_raft_server_buf_msg_to_host(&msg_tmp, buf)) != 0) {
		RRR_MSG_0("Message decoding failed in %s\n", __func__);
		goto out_critical;
	}

	req_index = msg_tmp->msg_value;

	RRR_DBG_3("Raft message %" PRIu32 " being applied in state machine in server %i\n",
		req_index, callback_data->server_id);

	if ((ret = rrr_raft_message_store_push (
			&was_found,
			callback_data->message_store_state,
			msg_tmp
	)) != 0) {
		RRR_MSG_0("Failed to push message to message store during application to state machine in server %i\n",
			callback_data->server_id);
		goto out_critical;
	}

	if ((MSG_IS_DEL(msg_tmp) || MSG_IS_PAT(msg_tmp)) && !was_found) {
		code = RRR_RAFT_ENOENT;
	}

	// If we are leader, the apply_cb giving feedback to
	// the client must see the message which has been applied
	// to the state machine.
	if (__rrr_raft_server_fsm_result_collection_push (
			&callback_data->fsm_results,
			req_index,
			&msg_tmp,
			code
	) != 0) {
		RRR_MSG_0("Failed to push result in %s\n", __func__);
		goto out_critical;
	}

	*result = rrr_ptr_from_biglength_bug_const(req_index);

	goto out_free;
	out_critical:
		assert(ret != 0);
		callback_data->ret = 1;
		uv_stop(callback_data->loop);
	out_free:
		RRR_FREE_IF_NOT_NULL(msg_tmp);
		return ret;
}

struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data {
	struct raft_buffer *bufs;
	size_t i;
};

static int __rrr_raft_server_fsm_message_store_snapshot_iterate_callback (
		const struct rrr_msg_msg *msg,
		void *arg
) {
	struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data *callback_data = arg;

	int ret = 0;

	struct raft_buffer *buf;
	
	buf = callback_data->bufs + callback_data->i;

	if ((buf->base = raft_malloc(MSG_TOTAL_SIZE(msg))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	memcpy(buf->base, msg, MSG_TOTAL_SIZE(msg));

	rrr_msg_msg_prepare_for_network((struct rrr_msg_msg *) buf->base);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) buf->base);

	RRR_ASSERT(sizeof(buf->len) >= sizeof(MSG_TOTAL_SIZE(msg)),buf_len_must_hold_max_message_size);

	buf->len = MSG_TOTAL_SIZE(msg);

	callback_data->i++;

	out:
	return ret;
}

static int __rrr_raft_server_fsm_message_store_snapshot (
		struct raft_buffer *res_bufs[],
		unsigned *res_n_bufs,
		struct rrr_raft_server_state *callback_data
) {
	struct rrr_raft_message_store *store = callback_data->message_store_state;

	int ret = 0;

	struct raft_buffer *bufs, *buf;
	size_t count, i;

	count = rrr_raft_message_store_count(store);

	if ((bufs = raft_calloc(1, sizeof(*bufs) * count)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = RAFT_NOMEM;
		goto out;
	}

	struct rrr_raft_server_fsm_message_store_snapshot_iterate_callback_data iterate_callback_data = {
		bufs,
		0
	};

	if ((ret = rrr_raft_message_store_iterate (
			store,
			__rrr_raft_server_fsm_message_store_snapshot_iterate_callback,
			&iterate_callback_data
	)) != 0) {
		goto out_free;
	}

	assert(iterate_callback_data.i == count);

	*res_bufs = bufs;
	*res_n_bufs = count;

	goto out;
	out_free:
		for (i = 0; i < count; i++) {
			if ((buf = bufs + i) == NULL)
				break;
			raft_free(buf->base);
		}
		raft_free(bufs);
	out:
		return ret;
}

static int  __rrr_raft_server_fsm_snapshot_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *bufs[],
		unsigned *n_bufs
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	RRR_DBG_3("Raft insert snapshot server %i\n", callback_data->server_id);

	return __rrr_raft_server_fsm_message_store_snapshot (bufs, n_bufs, callback_data);
}

static int __rrr_raft_server_fsm_restore_cb (
		struct raft_fsm *fsm,
		struct raft_buffer *buf
) {
	struct rrr_raft_server_state *callback_data = fsm->data;

	int ret = 0;

	struct rrr_msg_msg *msg;
	size_t pos;
	int was_found;

	assert(buf->len <= UINT32_MAX);

	RRR_DBG_3("Raft restore snapshot server %i\n", callback_data->server_id);

	for (pos = 0; pos < buf->len; rrr_size_t_add_bug(&pos, MSG_TOTAL_SIZE(msg))) {
		assert(buf->len - pos >= sizeof(struct rrr_msg_msg) - 1);

		msg = (void *) buf->base + pos;

		if ((ret = __rrr_raft_server_msg_to_host(msg, buf->len)) != 0) {
			RRR_MSG_0("Message decoding failed in %s\n", __func__);
			goto out;
		}

		RRR_DBG_3("Raft message %i being applied in state machine in server %i during restore\n",
			msg->msg_value, callback_data->server_id);

		if ((ret = rrr_raft_message_store_push (
				&was_found,
				callback_data->message_store_state,
				msg
		)) != 0) {
			RRR_MSG_0("Message push failed in %s\n", __func__);
			goto out;
		}
	}

	assert(pos == buf->len);

	// Only free upon successful return value
	raft_free(buf->base);

	out:
	return ret;
}

*/

static void __rrr_raft_bridge_start (
		struct raft_event *event,
		struct rrr_raft_bridge *bridge
) {
	assert(!(bridge->state & RRR_RAFT_BRIDGE_STATE_STARTED));

	event->time = rrr_time_get_64() / 1000; 
	event->capacity = 0;
	event->type = RAFT_START;

	// TODO : Load persisted metadata here
	//        - Set current_term, voted_for, metadata, entries and n_entries

	event->start.term = 0;
	event->start.voted_for = 0;
	event->start.metadata = NULL;
	event->start.start_index = 0;
	event->start.entries = NULL;
	event->start.n_entries = 0;
}
		
static void __rrr_raft_bridge_cleanup (
		struct rrr_raft_bridge *bridge
) {
	raft_configuration_close(&bridge->configuration);
}

static int __rrr_raft_bridge_configuration_clone (
		struct raft_configuration *dest,
		const struct raft_configuration *src
) {
	int ret = 0;

	unsigned i, j;
	struct raft_configuration conf;

	assert(dest->servers == NULL && dest->n == 0);

	if ((conf.servers = rrr_allocate(sizeof(*conf.servers) * src->n)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for servers in %s\n", __func__);
		ret = 1;
		goto out;
	}

	for (i = 0; i < src->n; i++) {
		conf.servers[i].id = src->servers[i].id;
		conf.servers[i].role = src->servers[i].role;
		if ((conf.servers[i].address = rrr_strdup(src->servers[i].address)) == NULL) {
			RRR_MSG_0("Failed to allocate memory for server name in %s\n", __func__);
			ret = 1;
			goto out_free_servers;
		}
	}

	conf.n = src->n;

	*dest = conf;

	goto out;
	out_free_servers:
		for (j = 0; j < i; j++) {
			rrr_free(conf.servers[j].address);
		}
		rrr_free(conf.servers);
	out:
		return ret;
}

static void __rrr_raft_bridge_set_term (
		struct rrr_raft_bridge *bridge,
		raft_term term
) {
	bridge->metadata.version++;
	bridge->metadata.term = term;
	bridge->metadata.voted_for = 0;
}

static int __rrr_raft_bridge_read_file (
		char **data,
		size_t *data_size,
		ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	ssize_t bytes;
	char buf[65536];
	char *result = NULL, *result_new;
	size_t result_size = 0, result_pos = 0;

	do {
		if ((bytes = read_cb(name, buf, sizeof(buf), cb_data)) < 0) {
			ret = 1;
			goto out;
		}
		else if (bytes > 0) {
			if (result_pos + bytes > result_size) {
				if ((result_new = rrr_reallocate(result, result_size + sizeof(buf))) == NULL) {
					RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
					ret = 1;
					goto out;
				}
				result_size += sizeof(buf);
				result = result_new;
			}
			memcpy(result + result_pos, buf, bytes);
			result_pos += bytes;
		}
	} while (bytes > 0);

	*data = result;
	*data_size = result_pos;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

#define READ(buf)                           \
    char *rpos = (char *) buf; if (1)       \

#define READ_U64(n)                         \
    (n) = rrr_be64toh(* (uint64_t *) rpos); \
    rpos += sizeof(uint64_t)

static int __rrr_raft_bridge_read_metadata (
		struct rrr_raft_bridge_metadata *metadata,
		struct rrr_raft_bridge *bridge,
		ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	(void)(bridge);

	char *data = NULL;
	size_t data_size;
	uint64_t format, version, term, voted_for;

	metadata->version = 0;
	metadata->term = 0;
	metadata->voted_for = 0;

	if ((ret = __rrr_raft_bridge_read_file (&data, &data_size, read_cb, name, cb_data)) != 0) {
		goto out;
	}

	if (data_size == 0) {
		goto out;
	}

	if (data_size != 4 * sizeof(uint64_t)) {
		RRR_MSG_0("Warning: Incorrect size %llu for metadata file '%s', ignoring it\n", (unsigned long long) data_size, name);
		goto out;
	}

	READ(data) {
		READ_U64(format);
		READ_U64(version);
		READ_U64(term);
		READ_U64(voted_for);
	}

	if (format != RRR_RAFT_DISK_FORMAT) {
		RRR_MSG_0("Warning: Incorrect format %llu for metadata file '%s', ignoring it\n", (unsigned long long) format, name);
		goto out;
	}

	metadata->version = version;
	metadata->term = term;
	metadata->voted_for = voted_for;

	out:
	RRR_FREE_IF_NOT_NULL(data);
	return ret;
}

static int __rrr_raft_bridge_write (
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		const char *data,
		size_t data_size,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	size_t pos;
	ssize_t bytes;

	for (pos = 0; pos < data_size; pos += bytes) {
		if ((bytes = write_cb(name, data + pos, data_size - pos, cb_data)) < 0) {
			ret = 1;
			goto out;
		}
		assert(bytes > 0);
	}

	assert(pos == data_size);

	if ((bytes = write_cb(name, NULL, 0, cb_data)) < 0) {
		ret = 1;
		goto out;
	}
	assert(bytes == 0);

	out:
	return ret;
}

#define WRITE(buf)                          \
    char *wpos = (char *) (buf); if (1)     \

#define WRITE_U8(n)                         \
    * (uint8_t *) wpos = n;                 \
    wpos += sizeof(uint8_t)

#define WRITE_U32(n)                        \
    * (uint32_t *) wpos = rrr_htobe64(n);   \
    wpos += sizeof(uint32_t)

#define WRITE_U64(n)                        \
    * (uint64_t *) wpos = rrr_htobe64(n);   \
    wpos += sizeof(uint64_t)

#define WRITE_STR(str)                      \
    do {size_t len = strlen(str);           \
        memcpy(wpos, str, len + 1);         \
	wpos += len + 1;                    \
    } while(0)

#define WRITE_POS()                         \
    wpos

#define WRITE_INC(n)                        \
   wpos += n

#define WRITE_VERIFY(buf,len)               \
    assert((uintptr_t) wpos - (uintptr_t) (buf) == (uintptr_t) len)

static int __rrr_raft_bridge_write_metadata (
		struct rrr_raft_bridge *bridge,
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	(void)(bridge);

	uint64_t data[4];

	WRITE(data) {
		WRITE_U64(RRR_RAFT_DISK_FORMAT);
		WRITE_U64(bridge->metadata.version);
		WRITE_U64(bridge->metadata.term);
		WRITE_U64(bridge->metadata.voted_for);
	}
	WRITE_VERIFY(data,sizeof(data));

	return __rrr_raft_bridge_write(write_cb, name, (const char *) data, sizeof(data), cb_data);
}

static int __rrr_raft_bridge_encode_configuration (
		char **data,
		size_t *data_size,
		const struct raft_configuration *conf
) {
	int ret = 0;

	size_t total_size = 0;
	unsigned i;
	struct raft_server *server;
	char *buf = NULL;

	total_size += sizeof(uint8_t);  /* Format */
	total_size += sizeof(uint64_t); /* Server count */

	for (i = 0; i < conf->n; i++) {
		server = conf->servers + i;
		assert(server->address != NULL);
		total_size += sizeof(uint64_t);            /* Server ID */
		total_size += strlen(server->address) + 1; /* Server address */
		total_size += sizeof(uint8_t);             /* Voting flag */
	}

	if ((buf = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	WRITE(buf) {
		WRITE_U8(RRR_RAFT_DISK_FORMAT);
		WRITE_U64(conf->n);
		for (i = 0; i < conf->n; i++) {
			server = conf->servers + i;
			WRITE_U64(server->id);
			WRITE_STR(server->address);
			WRITE_U8(server->role);
		}
	}
	WRITE_VERIFY(buf,total_size);

	*data = buf;
	*data_size = total_size;
	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

#define BATCH_HEADER_SIZE(n) (                        \
        sizeof(uint64_t) +       /* Entry count */    \
        sizeof(uint64_t) * 2 * n /* Entry headers */  \
    )

#define WRITE_BATCH_HEADER(entries, entry_count, crc)                                         \
    do {char *wpos_begin = wpos; WRITE_U64(entry_count);                                      \
        for (const struct raft_entry *entry = entries; entry < entries + entry_count; entry++) { \
	    WRITE_U64(entry->term);                                                           \
	    WRITE_U8(entry->type);                                                            \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
            WRITE_U32(entry->buf.len);                                                        \
	}                                                                                     \
        crc = rrr_crc32buf_init(wpos_begin, wpos - wpos_begin, crc);                          \
    } while (0)

#define WRITE_BATCH_DATA(entries, entry_count, crc)                                           \
    do {                                                                                      \
        for (const struct raft_entry *entry = entries; entry < entries + entry_count; entry++) { \
	    memcpy(wpos, entry->buf.base, entry->buf.len);                                    \
	    crc = rrr_crc32buf_init(wpos, entry->buf.len, crc);                               \
	    wpos += entry->buf.len;                                                           \
	}                                                                                     \
    } while (0)

static int __rrr_raft_bridge_encode_entries (
		char **data,
		size_t *data_size,
		size_t preamble_size,
		const struct raft_entry *entries,
		unsigned entry_count
) {
	int ret = 0;

	size_t total_size = 0;
	char *crc1_pos, *crc2_pos, *buf = NULL;
	uint32_t crc1 = 0xffffffff, crc2 = 0xffffffff;
	unsigned i;

	total_size += preamble_size;
	total_size += sizeof(uint32_t) * 2;  /* Checksums */
	total_size += BATCH_HEADER_SIZE(entry_count);
	for (i = 0; i < entry_count; i++) {
		total_size += entries[i].buf.len;
	}

	if ((buf = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %sn\n", __func__);
		ret = 1;
		goto out;
	}

	WRITE(buf) {
		WRITE_INC(preamble_size);
		crc1_pos = WRITE_POS();
		WRITE_U32(0);
		crc2_pos = WRITE_POS();
		WRITE_U32(0);
		WRITE_BATCH_HEADER(entries, entry_count, crc1);
		WRITE_BATCH_DATA(entries, entry_count, crc2);
	}
	WRITE_VERIFY(buf, total_size);

	* (uint32_t *) crc1_pos = crc1;
	* (uint32_t *) crc2_pos = crc2;

	*data = buf;
	*data_size = total_size;
	buf = NULL;

	out:
	return ret;
}

static int __rrr_raft_bridge_encode_closed_segment (
		char **data,
		size_t *data_size,
		const char *conf,
		size_t conf_size,
		raft_term conf_term
) {
	int ret = 0;

	struct raft_entry entry = {0};

	entry.term = conf_term;
	entry.type = RAFT_CHANGE;
	entry.buf.base = (void *) conf;
	entry.buf.len = conf_size;

	if ((ret = __rrr_raft_bridge_encode_entries (
			data,
			data_size,
			sizeof(uint64_t),
			&entry,
			1
	)) != 0) {
		goto out;
	}

	WRITE(*data) {
		WRITE_U64(RRR_RAFT_DISK_FORMAT);	
	}

	out:
	return ret;
}

static int __rrr_raft_bridge_write_first_closed_segment_with_configuration (
		const struct raft_configuration *conf,
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	char *configuration_data = NULL, *data = NULL;
	size_t configuration_data_size, data_size;

	if ((ret = __rrr_raft_bridge_encode_configuration (
			&configuration_data,
			&configuration_data_size,
			conf
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_raft_bridge_encode_closed_segment (
			&data,
			&data_size,
			configuration_data,
			configuration_data_size,
			1
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_raft_bridge_write (
			write_cb,
			name,
			data,
			data_size,
			cb_data
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(configuration_data);
	RRR_FREE_IF_NOT_NULL(data);
	return ret;
}

static int __rrr_raft_bridge_acknowledge (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	int ret_tmp = 0;
	struct rrr_raft_task *task, *tasks, task_new;
	struct rrr_raft_task_list list_new = {0};
	//struct raft_event event;
	struct raft_event event;
	struct raft_update update;
	struct rrr_raft_bridge_metadata metadata1, metadata2;
//	uint64_t now;

	assert(list->count > 0);

	tasks = __rrr_raft_task_list_get(list);

//	now = rrr_time_get_64() / 1000;

	for (size_t i = 0; i < list->count; i++) {
		task = tasks + i;

		switch (task->type) {
			case RRR_RAFT_TASK_TIMEOUT:
			// TODO : Check for early timeout
/*				if (time < now) {
					RRR_RAFT_BRIDGE_DBG("early timeout, set again");
					__rrr_raft_task_list_push(&list_new, task);
					break;
				}
				else {*/
					RRR_RAFT_BRIDGE_DBG("timeout");
					event.type = RAFT_TIMEOUT;
					event.time = rrr_time_get_64() / 1000;
					goto step;
//				}
			case RRR_RAFT_TASK_READ_FILE:
				switch (task->readfile.type) {
					case RRR_RAFT_FILE_TYPE_METADATA:
						if (strcmp((char *) TASK_LIST_RESOLVE(task->readfile.name), "metadata1") == 0) {
							RRR_RAFT_BRIDGE_DBG("loading metadata1");

							if ((ret = __rrr_raft_bridge_read_metadata (
									&metadata1,
									bridge,
									task->readfile.read_cb,
									"metadata1",
									&task->readfile.cb_data
							)) != 0) {
								goto out_cleanup;
							}
						}
						else {
							RRR_RAFT_BRIDGE_DBG("loading metadata2");

							if ((ret = __rrr_raft_bridge_read_metadata (
									&metadata2,
									bridge,
									task->readfile.read_cb,
									"metadata2",
									&task->readfile.cb_data
							)) != 0) {
								goto out_cleanup;
							}

							if (metadata1.version == 0 && metadata2.version == 0) {
								bridge->metadata.version = 0;
								bridge->metadata.term = 0;
								bridge->metadata.voted_for = 0;
							}
							else if (metadata1.version == metadata2.version) {
								RRR_MSG_0("Both metadata1 and metadata2 contained the same version number\n");
								ret = 1;
								goto out_cleanup;
							}
							else {
								if (metadata1.version > metadata2.version) {
									bridge->metadata = metadata1;
								}
								else {
									bridge->metadata = metadata2;
								}

								RRR_RAFT_BRIDGE_DBG("metadata loaded");

								bridge->state |= RRR_RAFT_BRIDGE_STATE_CONFIGURED;
							}

							if (!(bridge->state & RRR_RAFT_BRIDGE_STATE_CONFIGURED)) {
								RRR_RAFT_BRIDGE_DBG("no metadata loaded, calling for bootstrap");

								task_new.type = RRR_RAFT_TASK_BOOTSTRAP;
								__rrr_raft_task_list_push(&list_new, &task_new);
							}
							else {
								__rrr_raft_bridge_start(&event, bridge);
								goto step;
							}
						}
						break;
					default:
						RRR_BUG("BUG: Unknown read file type %i in %s\n",
							task->readfile.type, __func__);
				};
				break;
			case RRR_RAFT_TASK_BOOTSTRAP:
				__rrr_raft_bridge_set_term(bridge, 1);
				if ((ret = __rrr_raft_bridge_configuration_clone(&bridge->configuration, task->bootstrap.configuration)) != 0) {
					goto out_cleanup;
				}

				// Write metadata
				task_new.type = RRR_RAFT_TASK_WRITE_FILE;
				task_new.writefile.type = RRR_RAFT_FILE_TYPE_METADATA;
				task_new.writefile.name = __rrr_raft_task_list_strdup (
						&list_new,
						bridge->metadata.version % 2 == 1
							? RRR_RAFT_FILE_NAME_PREFIX_METADATA "1"
							: RRR_RAFT_FILE_NAME_PREFIX_METADATA "2"
				);
				__rrr_raft_task_list_push(&list_new, &task_new);

				// Write configuration as first segment
				task_new.type = RRR_RAFT_TASK_WRITE_FILE;
				task_new.writefile.type = RRR_RAFT_FILE_TYPE_CONFIGURATION;
				task_new.writefile.name = __rrr_raft_task_list_asprintf (
						&list_new,
						RRR_RAFT_FILE_ARGS_CLOSED_SEGMENT(1, 1)
				);
				__rrr_raft_task_list_push(&list_new, &task_new);
				break;
			case RRR_RAFT_TASK_WRITE_FILE:
				switch (task->writefile.type) {
					case RRR_RAFT_FILE_TYPE_METADATA:
						if ((ret = __rrr_raft_bridge_write_metadata (
								bridge,
								task->writefile.write_cb,
								(char *) TASK_LIST_RESOLVE(task->writefile.name),
								&task->writefile.cb_data
						)) != 0) {
							goto out_cleanup;
						}
						break;
					case RRR_RAFT_FILE_TYPE_CONFIGURATION:
						if ((ret = __rrr_raft_bridge_write_first_closed_segment_with_configuration (
								&bridge->configuration,
								task->writefile.write_cb,
								(char *) TASK_LIST_RESOLVE(task->writefile.name),
								&task->writefile.cb_data
						)) != 0) {
							goto out_cleanup;
						}
						
						__rrr_raft_bridge_start(&event, bridge);
						goto step;
					default:
						RRR_BUG("BUG: Unknown write file type %i in %s\n",
							task->writefile.type, __func__);
				};
				break;
			default:
				RRR_BUG("BUG: Unkown type %i in %s\n",
					task->type, __func__);
		};

		continue;

		step:

		if ((ret_tmp = raft_step(bridge->raft, &event, &update)) != 0) {
			RRR_MSG_0("Step failed in %s: %s\n", __func__, raft_strerror(ret_tmp));
			ret = 1;
			goto out_cleanup;
		}

		if (update.flags & RAFT_UPDATE_CURRENT_TERM) {
			assert(0 && "Update current term not implemented");
		}

		if (update.flags & RAFT_UPDATE_VOTED_FOR) {
			assert(0 && "Update voted for not implemented");
		}

		if (update.flags & RAFT_UPDATE_ENTRIES) {
			assert(0 && "Update entries not implemented");
		}

		if (update.flags & RAFT_UPDATE_SNAPSHOT) {
			assert(0 && "Update snapshot not implemented");
		}

		if (update.flags & RAFT_UPDATE_MESSAGES) {
			assert(0 && "Update messages not implemented");
		}

		if (update.flags & RAFT_UPDATE_STATE) {
			assert(0 && "Update state not implemented");
		}

		if (update.flags & RAFT_UPDATE_COMMIT_INDEX) {
			assert(0 && "Update commit index not implemented");
		}

		if (update.flags & RAFT_UPDATE_TIMEOUT) {
			// Ignore, only push timeout task if
			// there are no other tasks.
			continue;
		}

		assert(0 && "Not reachable");
	}


	if (list_new.count == 0) {
		task_new.type = RRR_RAFT_TASK_TIMEOUT;
		task_new.timeout.time = raft_timeout(bridge->raft);
		__rrr_raft_task_list_push(&list_new, &task_new);
	}

	__rrr_raft_task_list_cleanup(list);
	*list = list_new;

	goto out_final;
	out_cleanup:
		__rrr_raft_task_list_cleanup(&list_new);
	out_final:
		return ret;
}

static int __rrr_raft_bridge_begin (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	struct rrr_raft_task task;

	assert(list->count == 0);

	assert (!(bridge->state & RRR_RAFT_BRIDGE_STATE_STARTED));

	RRR_RAFT_BRIDGE_DBG("starting, requesting metadata to be loaded from disk");

	task.type = RRR_RAFT_TASK_READ_FILE;
	task.readfile.type = RRR_RAFT_FILE_TYPE_METADATA;
	task.readfile.name = __rrr_raft_task_list_strdup(list, RRR_RAFT_FILE_NAME_PREFIX_METADATA "1");
	__rrr_raft_task_list_push(list, &task);

	task.type = RRR_RAFT_TASK_READ_FILE;
	task.readfile.type = RRR_RAFT_FILE_TYPE_METADATA;
	task.readfile.name = __rrr_raft_task_list_strdup(list, RRR_RAFT_FILE_NAME_PREFIX_METADATA "2");
	__rrr_raft_task_list_push(list, &task);

	goto out;

	out:
	return ret;
}

struct rrr_raft_server_file_read_cb_data {
	int fd;
};

static ssize_t __rrr_raft_server_file_read_cb (RRR_RAFT_BRIDGE_READFILE_CB_ARGS) {
	struct rrr_raft_server_state *state = cb_data->ptr;
	struct rrr_raft_server_file_read_cb_data *file_read_cb_data = (struct rrr_raft_server_file_read_cb_data *) cb_data->data;

	ssize_t bytes;

	if (file_read_cb_data->fd <= 0) {
		if ((file_read_cb_data->fd = rrr_socket_open(name, O_RDONLY, 0777, __func__, 0)) <= 0) {
			if (errno == ENOENT) {
				RRR_RAFT_SERVER_DBG_FILE(name, "file does not exist while opening for reading%s", "");
				bytes = 0;
				goto out;
			}

			RRR_MSG_0("Failed to open file %s for reading in %s: %s\n", name, __func__, rrr_strerror(errno));
			bytes = -1;
			goto out;
		}

		RRR_RAFT_SERVER_DBG_FILE(name, "opened file for reading%s", "");
	}

	assert(buf_size > 0);

	if ((bytes = read(file_read_cb_data->fd, buf, buf_size)) < 0) {
		RRR_MSG_0("Failed to read in %s: %s\n", __func__, rrr_strerror(errno));
		bytes = -1;
		goto out;
	}
	else if (bytes == 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "closing file after reading%s", "");
		assert(file_read_cb_data->fd > 0);
		goto out;
	}

	out:
	return bytes;
}

struct rrr_raft_server_file_write_cb_data {
	int fd;
};

static ssize_t __rrr_raft_server_file_write_cb (RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS) {
	struct rrr_raft_server_state *state = cb_data->ptr;
	struct rrr_raft_server_file_write_cb_data *file_write_cb_data = (struct rrr_raft_server_file_write_cb_data *) cb_data->data;

	ssize_t bytes;

	if (file_write_cb_data->fd <= 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "open file to write %llu bytes", (unsigned long long) data_size);

		if ((file_write_cb_data->fd = rrr_socket_open(name, O_CREAT|O_TRUNC|O_RDWR|O_SYNC, 0777, __func__, 0)) <= 0) {
			RRR_MSG_0("Failed to open file %s for writing in %s: %s\n", name, __func__, rrr_strerror(errno));
			bytes = -1;
			goto out;
		}
	}

	if (data_size == 0) {
		RRR_RAFT_SERVER_DBG_FILE(name, "closing file after writing%s", "");
		assert(file_write_cb_data->fd > 0);
		rrr_socket_close(file_write_cb_data->fd);
		bytes = 0;
		goto out;
	}

	if ((bytes = write(file_write_cb_data->fd, data, data_size)) <= 0) {
		RRR_MSG_0("Failed to write to file in %s: %s\n", __func__, rrr_strerror(errno));
		bytes = -1;
		goto out;
	}

	out:
	return bytes;
}

static int __rrr_raft_server_process_tasks (
		struct rrr_raft_server_state *state
) {
	struct rrr_raft_task_list *list = state->tasks;

	int ret = 0;

	uint64_t diff, now;
	struct rrr_raft_task *task, *tasks;
	struct rrr_raft_server_file_write_cb_data *file_write_cb_data;
	struct rrr_raft_server_file_read_cb_data *file_read_cb_data;

	if (list->count == 0) {
		goto out;
	}

	tasks = __rrr_raft_task_list_get(list);

	now = rrr_time_get_64() / 1000;

	for (size_t i = 0; i < list->count; i++) {
		task = tasks + i;

		switch (task->type) {
			case RRR_RAFT_TASK_TIMEOUT:
				diff = task->timeout.time - now;
				if (diff >= task->timeout.time) {
					diff = 10000;
				}

				RRR_RAFT_SERVER_DBG_EVENT("set timeout to %" PRIu64 " ms", diff);
				EVENT_INTERVAL_SET(state->events.raft_timeout, diff * 1000);
				EVENT_ADD(state->events.raft_timeout);
				break;
			case RRR_RAFT_TASK_READ_FILE:
				// TODO : Read actual file
				RRR_RAFT_SERVER_DBG_EVENT("set read file cb for type %i '%s'",
					task->readfile.type, (char *) TASK_LIST_RESOLVE(task->readfile.name));
				RRR_ASSERT(sizeof(file_read_cb_data) <= sizeof(task->readfile.cb_data.data),cb_data_must_hold_server_cb_data);
				file_read_cb_data = (struct rrr_raft_server_file_read_cb_data *) task->readfile.cb_data.data;
				file_read_cb_data->fd = -1;
				task->readfile.read_cb = __rrr_raft_server_file_read_cb;
				task->readfile.cb_data.ptr = state;
				break;
			case RRR_RAFT_TASK_BOOTSTRAP:
				task->bootstrap.configuration = state->configuration;
				break;
			case RRR_RAFT_TASK_WRITE_FILE:
				RRR_RAFT_SERVER_DBG_EVENT("set write file cb for type %i '%s'",
					task->writefile.type, (char *) TASK_LIST_RESOLVE(task->writefile.name));
				RRR_ASSERT(sizeof(file_write_cb_data) <= sizeof(task->writefile.cb_data.data),cb_data_must_hold_server_cb_data);
				file_write_cb_data = (struct rrr_raft_server_file_write_cb_data *) task->writefile.cb_data.data;
				file_write_cb_data->fd = -1;
				task->writefile.write_cb = __rrr_raft_server_file_write_cb;
				task->writefile.cb_data.ptr = state;
				break;
			default:
				RRR_BUG("BUG: Unknown task type %i in %s\n",
					task->type, __func__);
		};
	}

	out:
	return ret;
}

static int __rrr_raft_server_process_and_acknowledge (
		struct rrr_raft_server_state *state
) {
	int ret = 0;

	struct rrr_raft_task *task;

	if ((ret = __rrr_raft_server_process_tasks(state)) != 0) {
		goto out;
	}

	if ((ret = __rrr_raft_bridge_acknowledge(state->tasks, state->bridge)) != 0) {
		goto out;
	}

	assert(state->tasks->count > 0);


	task = __rrr_raft_task_list_get(state->tasks);

	if (task->type != RRR_RAFT_TASK_TIMEOUT) {
		// TODO : Consider tight loop instead of activating timeout
		EVENT_ACTIVATE(state->events.raft_timeout);
	}

	out:
	return ret;
}

static void __rrr_raft_server_timeout_cb (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_raft_server_state *state = arg;

	(void)(fd);
	(void)(flags);

	if (__rrr_raft_server_process_and_acknowledge (state) != 0) {
		rrr_event_dispatch_break(state->channel->queue);
	}
}

int rrr_raft_server (
		struct rrr_raft_channel *channel,
		const char *log_prefix,
		const struct rrr_raft_server *servers,
		size_t servers_self,
		const char *dir,
		int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
) {
	int ret = 0;

	int was_found, ret_tmp;
	int channel_fds[2];
	size_t cleared_count;
	struct raft raft = {0};
	struct raft_configuration configuration;
	struct rrr_raft_server_fsm_result_collection fsm_results = {0};
	struct rrr_raft_server_state state = {0};
	struct rrr_raft_message_store *message_store_state;
	struct rrr_event_collection events = {0};
	struct rrr_raft_bridge bridge = {0};
	struct rrr_raft_task_list tasks = {0};
	static struct raft_heap rrr_raft_heap = {
		NULL,                            /* data */
		__rrr_raft_server_malloc,        /* malloc */
		__rrr_raft_server_free,          /* free */
		__rrr_raft_server_calloc,        /* calloc */
		__rrr_raft_server_realloc,       /* realloc */
		__rrr_raft_server_aligned_alloc, /* aligned_alloc */
		__rrr_raft_server_aligned_free   /* aligned_free */
	};

	RRR_DBG_1("Starting raft server %i dir %s address %s\n",
		servers[servers_self].id, dir, servers[servers_self].address);

	rrr_raft_channel_fds_get(channel_fds, channel);
	// rrr_socket_close_all_except_array_no_unlink(channel_fds, sizeof(channel_fds)/sizeof(channel_fds[0]));

	// TODO : Send logs on socket. XXX also enable unregister on function out
	// rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_raft_server_log_hook, channel, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
	assert(was_found);
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	rrr_config_set_log_prefix(log_prefix);

	rrr_event_collection_init(&events, channel->queue);

	if ((ret = rrr_event_collection_push_periodic (
			&state.events.raft_timeout,
			&events,
			__rrr_raft_server_timeout_cb,
			&state,
			1 * 10 * 1000 // Initial timeout 10 ms
	)) != 0) {
		RRR_MSG_0("Failed to create timeout event in %s\n", __func__);
		goto out_cleanup_events;
	}

	EVENT_ADD(state.events.raft_timeout);

	if ((ret = rrr_event_collection_push_read (
			&state.events.socket,
			&events,
			channel->fd_server,
			__rrr_raft_server_read_cb,
			&state,
			1 * 1000 * 1000 // 1 second timeout
	)) != 0) {
		RRR_MSG_0("Failed to create read event in %s\n", __func__);
		goto out_cleanup_events;
	}

	EVENT_ADD(state.events.socket);

	if (chdir(dir) != 0) {
		RRR_MSG_0("Failed to change directory to %s in %s: %s\n", dir, __func__, rrr_strerror(errno));
		ret = 1;
		goto out_cleanup_events;
	}

	if ((ret = rrr_raft_message_store_new (&message_store_state, patch_cb)) != 0) {
		goto out_cleanup_events;
	}

	state.channel = channel;
	state.message_store_state = message_store_state;
	state.fsm_results = &fsm_results;
	state.configuration = &configuration;

	bridge.raft = &raft;
	bridge.server_id = servers[servers_self].id;
	state.bridge = &bridge;
	state.tasks = &tasks;

	raft_heap_set(&rrr_raft_heap);

	if ((ret_tmp = raft_init (
			&raft,
			NULL,
			NULL,
			servers[servers_self].id,
			servers[servers_self].address
	)) != 0) {
		RRR_MSG_0("Failed to initialize raft in %s: %s: %s\n", __func__,
			raft_strerror(ret_tmp), raft_errmsg(&raft));
		ret = 1;
		goto out_destroy_message_store;
	}

	raft_seed(&raft, rrr_rand());

	raft_configuration_init(&configuration);

	for (; servers->id > 0; servers++) {
		if ((ret_tmp = raft_configuration_add (
				&configuration,
				servers->id,
				servers->address,
				RAFT_VOTER
		)) != 0) {
			RRR_MSG_0("Failed to add to raft configuration in %s: %s\n", __func__,
				raft_strerror(ret_tmp));
			ret = 1;
			goto out_cleanup_configuration;
		}
	}
/*
	if ((ret_tmp = raft_bootstrap(&raft, &configuration)) != 0 && ret_tmp != RAFT_CANTBOOTSTRAP) {
		RRR_MSG_0("Failed to bootstrap raft in %s: %s\n",
			__func__, raft_strerror(ret_tmp));
		goto out_raft_callback_data_cleanup;
	}

	raft_set_snapshot_threshold(&raft, 32);
	raft_set_snapshot_trailing(&raft, 16);
	raft_set_pre_vote(&raft, true);

	uv_handle_set_data((uv_handle_t *) &poll_server, &callback_data);

	if ((ret_tmp = raft_start(&raft)) != 0) {
		RRR_MSG_0("Failed to start raft: %s\n", raft_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	ret_tmp = uv_run(&loop, UV_RUN_DEFAULT);
*/

	if ((ret = __rrr_raft_bridge_begin (&tasks, &bridge)) != 0) {
		goto out_cleanup_configuration;
	}

	if ((ret = __rrr_raft_server_process_and_acknowledge(&state)) != 0) {
		goto out_cleanup_bridge;
	}

	ret = rrr_event_dispatch(channel->queue);

	RRR_DBG_1("Event loop completed in raft server, result was %i\n", ret_tmp);

	// TODO : Some expected results are registered when messages are restored and applied, and
	//        in those cases the final apply callback is never called and the results persists.
	//        This might not matter as restoration only happens during startup, but we have to
	//        search past those results each time. Maybe deal with this situation.
	__rrr_raft_server_fsm_result_collection_clear(&cleared_count, &fsm_results);
	RRR_DBG_1("Cleared %llu expected results in raft server %i\n",
		cleared_count, state.bridge->server_id);

	goto out_cleanup_bridge;
	out_cleanup_bridge:
		__rrr_raft_bridge_cleanup(&bridge);
//	out_cleanup_tasks:
		__rrr_raft_task_list_cleanup(&tasks);
	out_cleanup_configuration:
		raft_configuration_close(&configuration);
//	out_raft_close:
		raft_close(&raft, NULL);
//	out_cleanup_fsm_results:
		__rrr_raft_server_fsm_result_collection_clear(&cleared_count, &fsm_results);
	out_destroy_message_store:
		rrr_raft_message_store_destroy(message_store_state);
	out_cleanup_events:
		rrr_event_collection_clear(&events);
//	out:
		// TODO : Enable once handle is registered
		// rrr_log_hook_unregister(log_hook_handle);
		RRR_DBG_1("raft server %s pid %i exit\n", log_prefix, getpid());

/*		if (req != NULL) {
			raft_free(req);
		}*/

		return ret;
}
