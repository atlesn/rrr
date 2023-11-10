/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_CLIENT_H
#define RRR_SOCKET_CLIENT_H

#include <sys/types.h>
#include <sys/socket.h>

#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "rrr_socket_send_chunk.h"

#include "../rrr_types.h"
#include "../read.h"
#include "../util/linked_list.h"

#define RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS      \
    int *socket_read_flags,                                 \
    int *do_soft_error_propagates,                          \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS \
    struct rrr_read_session *read_session,                  \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS        \
    struct rrr_read_session *read_session,                  \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS               \
    struct rrr_read_session *read_session,                  \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    struct rrr_array *array_final,                          \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS               \
    struct rrr_read_session *read_session,                  \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    int is_hard_err,                                        \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_ACCEPT_CALLBACK_ARGS              \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    void *private_data,                                     \
    void *arg

#define RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS         \
    int was_sent,                                           \
    int fd,                                                 \
    const void *data,                                       \
    rrr_biglength data_size,                                \
    rrr_biglength data_pos,                                 \
    void *chunk_private_data,                               \
    void *callback_arg

#define RRR_SOCKET_CLIENT_SEND_START_END_CALLBACK_ARGS      \
    RRR_SOCKET_SEND_CHUNK_START_END_CALLBACK_ARGS

#define RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS            \
    int fd,                                                 \
    const struct sockaddr *addr,                            \
    socklen_t addr_len,                                     \
    const char *addr_string,                                \
    enum rrr_socket_client_collection_create_type create_type, \
    short was_finalized,                                    \
    void *arg

struct rrr_socket_client_collection;
struct rrr_event_queue;
struct rrr_read_session;
struct rrr_array;

enum rrr_socket_client_collection_create_type {
	RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT,
	RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND,
	RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_INBOUND,
	RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN,
	RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_FILE
};

#define RRR_SOCKET_CLIENT_CREATE_TYPE_STR(type)                                        \
    (type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT ? "PERSISTENT" :      \
     type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND ? "OUTBOUND" :          \
     type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_INBOUND ? "INBOUND" :            \
     type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_LISTEN ? "LISTEN" :              \
     type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_FILE ? "FILE" : "UNKNOWN")

int rrr_socket_client_collection_new (
		struct rrr_socket_client_collection **target,
		struct rrr_event_queue *queue,
		const char *creator
);
void rrr_socket_client_collection_set_connect_timeout (
		struct rrr_socket_client_collection *collection,
		uint64_t connect_timeout_us
);
void rrr_socket_client_collection_set_idle_timeout (
		struct rrr_socket_client_collection *collection,
		uint64_t idle_timeout_us
);
void rrr_socket_client_collection_destroy (
		struct rrr_socket_client_collection *collection
);
int rrr_socket_client_collection_count (
		struct rrr_socket_client_collection *collection
);
void rrr_socket_client_collection_send_chunk_iterate (
		struct rrr_socket_client_collection *collection,
		void (*callback)(int *do_remove, const void *data, rrr_biglength data_size, rrr_biglength data_pos, void *chunk_private_data, void *arg),
		void *callback_arg
);
void rrr_socket_client_collection_close_outbound_when_send_complete (
		struct rrr_socket_client_collection *collection
);
void rrr_socket_client_collection_send_push_const_multicast (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const void *data,
		rrr_biglength size,
		rrr_length send_chunk_limit
);
int rrr_socket_client_collection_send_push (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		rrr_biglength data_size
);
int rrr_socket_client_collection_send_push_with_private_data (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		void **data,
		rrr_biglength data_size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
);
int rrr_socket_client_collection_send_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		const void *data,
		rrr_biglength data_size
);
void rrr_socket_client_collection_close_when_send_complete_by_address (
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len
);
void rrr_socket_client_collection_close_when_send_complete_by_address_string (
		struct rrr_socket_client_collection *collection,
		const char *addr_string
);
void rrr_socket_client_collection_close_when_send_complete_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
);
int rrr_socket_client_collection_migrate_by_fd (
		struct rrr_socket_client_collection *target,
		struct rrr_socket_client_collection *source,
		int fd
);
void rrr_socket_client_collection_close_by_fd (
		struct rrr_socket_client_collection *collection,
		int fd
);
int rrr_socket_client_collection_has_fd (
		struct rrr_socket_client_collection *collection,
		int fd
);
int rrr_socket_client_collection_send_push_const_by_address_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data
);
int rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const char *addr_string,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*resolve_callback)(
				size_t *address_count,
				struct sockaddr ***addresses,
				socklen_t **address_lengths,
				void *callback_data
		),
		void *resolve_callback_data,
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data,
		int (*data_prepare_callback)(const void **data, rrr_biglength *size, void *callback_data, void *private_data),
		void *data_prepare_callback_data
);
int rrr_socket_client_collection_send_push_const_by_host_and_port_connect_as_needed (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		const char *host,
		uint16_t port,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data),
		int (*connect_callback)(int *fd, const struct sockaddr *addr, socklen_t addr_len, void *callback_data),
		void *connect_callback_data,
		void (*data_prepare_callback)(const void **data, rrr_biglength *size, void *callback_data, void *private_data),
		void *data_prepare_callback_data
);
int rrr_socket_client_collection_sendto_push_const (
		rrr_length *send_chunk_count,
		struct rrr_socket_client_collection *collection,
		int fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const void *data,
		rrr_biglength size,
		void (*chunk_private_data_new)(void **chunk_private_data, void *arg),
		void *chunk_private_data_arg,
		void (*chunk_private_data_destroy)(void *chunk_private_data)
);
int rrr_socket_client_collection_listen_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd
);
int rrr_socket_client_collection_connected_fd_push (
		struct rrr_socket_client_collection *collection,
		int fd,
		enum rrr_socket_client_collection_create_type create_type
);
void rrr_socket_client_collection_send_notify_setup (
		struct rrr_socket_client_collection *collection,
		void (*notify)(RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS),
		void *arg
);
void rrr_socket_client_collection_send_notify_setup_with_gates (
		struct rrr_socket_client_collection *collection,
		void (*notify)(RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS),
		void (*start)(RRR_SOCKET_CLIENT_SEND_START_END_CALLBACK_ARGS),
		void (*end)(RRR_SOCKET_CLIENT_SEND_START_END_CALLBACK_ARGS),
		void *arg
);
void rrr_socket_client_collection_fd_close_notify_setup (
		struct rrr_socket_client_collection *collection,
		void (*callback)(RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS),
		void *callback_arg
);
void rrr_socket_client_collection_event_setup (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		rrr_biglength read_step_max_size,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		RRR_MSG_TO_HOST_AND_VERIFY_CALLBACKS_COMMA,
		void *callback_arg
);

void rrr_socket_client_collection_event_setup_raw (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		rrr_biglength read_step_max_size,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		int (*get_target_size)(RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS),
		void *get_target_size_arg,
		void (*error_callback)(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS),
		void *error_callback_arg,
		int (*complete_callback)(RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS),
		void *complete_callback_arg
);

void rrr_socket_client_collection_event_setup_array_tree (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		rrr_biglength read_step_max_size,
		unsigned int message_max_size,
		int (*array_callback)(RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS),
		void *array_callback_arg,
		void (*error_callback)(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS),
		void *error_callback_arg,
		int (*accept_callback)(RRR_SOCKET_CLIENT_ACCEPT_CALLBACK_ARGS),
		void *accept_callback_arg
);
void rrr_socket_client_collection_event_setup_ignore (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg,
		int read_flags_socket,
		void (*callback_set_read_flags)(RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS),
		void *callback_set_read_flags_arg
);
void rrr_socket_client_collection_event_setup_write_only (
		struct rrr_socket_client_collection *collection,
		int (*callback_private_data_new)(void **target, int fd, void *private_arg),
		void (*callback_private_data_destroy)(void *private_data),
		void *callback_private_data_arg
);

#endif /* RRR_SOCKET_CLIENT_H */
