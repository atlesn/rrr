/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_H
#define RRR_NET_TRANSPORT_H

#include <sys/types.h>
#include <pthread.h>
#include <sys/socket.h>

#include "net_transport_defines.h"
#include "net_transport_types.h"
#include "net_transport_ctx.h"

#include "../rrr_types.h"
#include "../event/event.h"
#include "../read.h"
#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../socket/rrr_socket_send_chunk.h"

struct rrr_net_transport;
struct rrr_net_transport_config;
struct rrr_net_transport_handle;
struct rrr_net_transport_data_vector;
struct rrr_socket_datagram;
struct rrr_net_transport_connection_id_pair;
struct rrr_nullsafe_str;
struct rrr_event_queue;

#define RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS     \
    int64_t *stream_id,                                        \
    struct rrr_net_transport_vector *data_vector,              \
    size_t *data_vector_count,                                 \
    int *fin,                                                  \
    void *arg

#define RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS         \
    int64_t stream_id,                                         \
    int is_blocked,                                            \
    void *arg

#define RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS             \
    int64_t stream_id,                                         \
    size_t bytes,                                              \
    void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS  \
    struct rrr_net_transport_handle *handle,                   \
    void *arg

#define RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS           \
    struct rrr_net_transport_handle *handle,                   \
    const struct sockaddr *sockaddr,                           \
    socklen_t socklen,                                         \
    void *arg

#define RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS     \
    struct rrr_net_transport_handle *handle,                   \
    void *arg

#define RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS             \
    struct rrr_net_transport_handle *handle,                   \
    void *arg

#define RRR_NET_TRANSPORT_WRITE_CALLBACK_FINAL_ARGS            \
    struct rrr_net_transport_handle *handle,                   \
    void *arg

#define RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS                             \
    int (**cb_get_message)(RRR_NET_TRANSPORT_STREAM_GET_MESSAGE_CALLBACK_ARGS), \
    int (**cb_blocked)(RRR_NET_TRANSPORT_STREAM_BLOCKED_CALLBACK_ARGS),         \
    int (**cb_ack)(RRR_NET_TRANSPORT_STREAM_ACK_CALLBACK_ARGS),                 \
    void **cb_arg,                                                              \
    struct rrr_net_transport *transport,                                        \
    rrr_net_transport_handle handle,                                            \
    int64_t stream_id,                                                          \
    int flags,                                                                  \
    void *arg

#define RRR_NET_TRANSPORT_HEAD(type)                                        \
    RRR_LL_NODE(type);                                                      \
    const struct rrr_net_transport_methods *methods;                        \
    struct rrr_net_transport_handle_collection handles;                     \
    struct rrr_event_queue *event_queue;                                    \
    struct rrr_event_collection events;                                     \
    rrr_event_handle event_read_add;                                        \
    uint64_t first_read_timeout_ms;                                         \
    uint64_t soft_read_timeout_ms;                                          \
    uint64_t hard_read_timeout_ms;                                          \
    rrr_length send_chunk_count_limit;                                      \
    struct timeval first_read_timeout_tv;                                   \
    struct timeval soft_read_timeout_tv;                                    \
    struct timeval hard_read_timeout_tv;                                    \
    void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS);  \
    void *accept_callback_arg;                                              \
    int (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS);  \
    void *handshake_complete_callback_arg;                                  \
    int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS);       \
    void *read_callback_arg;                                                \
    int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS); \
    void *stream_open_callback_arg;                                         \
    char application_name[16]

#define RRR_NET_TRANSPORT_PRE_DESTROY_ARGS                                  \
    struct rrr_net_transport_handle *handle,                                \
    void *submodule_private_ptr,                                            \
    void *application_private_ptr

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#define RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS                           \
    void **submodule_private_ptr,                                          \
    int *submodule_fd,                                                     \
    const struct rrr_net_transport_connection_id_pair *connection_ids,     \
    const struct rrr_socket_datagram *datagram,                            \
    void *arg

#define RRR_NET_TRANSPORT_MODIFY_CALLBACK_ARGS                             \
    void **submodule_private_ptr,                                          \
    int *submodule_fd,                                                     \
    void *arg

int rrr_net_transport_handle_allocate_and_add (
		rrr_net_transport_handle *handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		const struct rrr_net_transport_connection_id_pair *connection_ids,
		const struct rrr_socket_datagram *datagram,
		int (*submodule_callback)(RRR_NET_TRANSPORT_ALLOCATE_CALLBACK_ARGS),
		void *submodule_callback_arg
);
int rrr_net_transport_handle_ptr_modify (
		struct rrr_net_transport_handle *handle,
		int (*submodule_callback)(RRR_NET_TRANSPORT_MODIFY_CALLBACK_ARGS),
		void *submodule_callback_arg
);
#endif

int rrr_net_transport_connect_and_close_after_callback (
		struct rrr_net_transport *transport,
		uint16_t port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
int rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		uint16_t port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
void rrr_net_transport_handle_touch (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle
);
void rrr_net_transport_handle_close_with_reason (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle handle,
		uint32_t submodule_close_reason,
		int (*pre_destroy)(RRR_NET_TRANSPORT_PRE_DESTROY_ARGS)
);
void rrr_net_transport_handle_ptr_close (
		struct rrr_net_transport_handle *handle
);
rrr_net_transport_handle rrr_net_transport_handle_get_by_match (
		struct rrr_net_transport *transport,
		const char *string,
		uint64_t number
);
rrr_net_transport_handle rrr_net_transport_handle_get_by_cid (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id *cid
);
rrr_net_transport_handle rrr_net_transport_handle_get_by_cid_pair (
		struct rrr_net_transport *transport,
		const struct rrr_net_transport_connection_id_pair *cids
);
int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_handle_cid_push (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id *cid
);
int rrr_net_transport_handle_cids_push (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id_pair *cids
);
int rrr_net_transport_handle_cid_remove (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const struct rrr_net_transport_connection_id *cid
);
int rrr_net_transport_bind_and_listen_dualstack (
		struct rrr_net_transport *transport,
		uint16_t port,
		void (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),
		void *arg
);
void rrr_net_transport_event_activate_all_connected_read (
		struct rrr_net_transport *transport
);
int rrr_net_transport_is_tls (
		struct rrr_net_transport *transport
);
void rrr_net_transport_notify_read_all_connected (
		struct rrr_net_transport *transport
);
int rrr_net_transport_iterate_by_mode_and_do (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_handle_notify_read (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle
);
int rrr_net_transport_handle_match_data_set (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		const char *string,
		uint64_t number
);
int rrr_net_transport_handle_migrate (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		uint16_t port,
		const char *host,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
);
void rrr_net_transport_handle_ptr_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
);
void rrr_net_transport_handle_ptr_pre_destroy_function_set (
		struct rrr_net_transport_handle *handle,
		int (*pre_destroy)(RRR_NET_TRANSPORT_PRE_DESTROY_ARGS)
);
int rrr_net_transport_handle_check_handshake_complete (
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle
);
int rrr_net_transport_handle_stream_open (
		int64_t *result,
		struct rrr_net_transport *transport,
		rrr_net_transport_handle transport_handle,
		int flags
);
void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
);
void rrr_net_transport_stats_get (
		rrr_length *listening_count,
		rrr_length *connected_count,
		struct rrr_net_transport *transport
);
int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		const char *application_name,
		int flags,
		struct rrr_event_queue *queue,
		const char *alpn_protos,
		unsigned int alpn_protos_length,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		rrr_length send_chunk_count_limit,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		int (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg,
		int (*stream_open_callback)(RRR_NET_TRANSPORT_STREAM_OPEN_CALLBACK_ARGS),
		void *stream_open_callback_arg
);
int rrr_net_transport_new_simple (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		const char *application_name,
		int flags,
		struct rrr_event_queue *queue
);
void rrr_net_transport_destroy (
		struct rrr_net_transport *transport
);
void rrr_net_transport_destroy_void (
		void *arg
);

#endif /* RRR_NET_TRANSPORT_H */
