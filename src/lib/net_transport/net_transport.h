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

#include "../event/event.h"
#include "../read.h"
#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../socket/rrr_socket_send_chunk.h"

struct rrr_read_session;
struct rrr_net_transport;
struct rrr_net_transport_config;
struct rrr_net_transport_handle;
struct rrr_nullsafe_str;
struct rrr_event_queue;

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS  \
    struct rrr_net_transport_handle *handle,                   \
    void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS        \
    void **submodule_private_ptr,                              \
    int *submodule_fd,                                         \
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

#define RRR_NET_TRANSPORT_HEAD(type)                                        \
    RRR_LL_NODE(type);                                                      \
    const struct rrr_net_transport_methods *methods;                        \
    struct rrr_net_transport_handle_collection handles;                     \
    struct rrr_event_queue *event_queue;                                    \
    struct rrr_event_collection events;                                     \
    rrr_event_handle event_maintenance;                                     \
    rrr_event_handle event_read_add;                                        \
    uint64_t first_read_timeout_ms;                                         \
    uint64_t soft_read_timeout_ms;                                          \
    uint64_t hard_read_timeout_ms;                                          \
    int send_chunk_count_limit;                                             \
    struct timeval first_read_timeout_tv;                                   \
    struct timeval soft_read_timeout_tv;                                    \
    struct timeval hard_read_timeout_tv;                                    \
    void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS);  \
    void *accept_callback_arg;                                              \
    void (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS);  \
    void *handshake_complete_callback_arg;                                  \
    int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS);       \
    void *read_callback_arg

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS
int rrr_net_transport_handle_allocate_and_add (
		int *handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*submodule_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS),
		void *submodule_callback_arg
);
#endif

#define RRR_NET_TRANSPORT_CTX_FD(handle) rrr_net_transport_ctx_get_fd(handle)
#define RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle) rrr_net_transport_ctx_get_private_ptr(handle)
#define RRR_NET_TRANSPORT_CTX_HANDLE(handle) rrr_net_transport_ctx_get_handle(handle)

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
);
int rrr_net_transport_handle_close_tag_list_push (
		struct rrr_net_transport *transport,
		int handle
);
void rrr_net_transport_stats_get (
		int *handle_count,
		struct rrr_net_transport *transport
);
int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		int flags,
		struct rrr_event_queue *queue,
		const char *alpn_protos,
		unsigned int alpn_protos_length
);
void rrr_net_transport_destroy (
		struct rrr_net_transport *transport
);
void rrr_net_transport_destroy_void (
		void *arg
);
int rrr_net_transport_handle_close (
		struct rrr_net_transport *transport,
		int transport_handle
);
int rrr_net_transport_connect_and_close_after_callback (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
int rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
int rrr_net_transport_handle_get_by_match (
		struct rrr_net_transport *transport,
		const char *string,
		uint64_t number
);
int rrr_net_transport_is_tls (
		struct rrr_net_transport *transport
);
void rrr_net_transport_ctx_notify_read (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_notify_read_all_connected (
		struct rrr_net_transport *transport
);
int rrr_net_transport_ctx_get_fd (
		struct rrr_net_transport_handle *handle
);
void *rrr_net_transport_ctx_get_private_ptr (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_get_handle (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_handle_match_data_set (
		struct rrr_net_transport_handle *handle,
		const char *string,
		uint64_t number
);
int rrr_net_transport_ctx_check_alive (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max_size,
		uint64_t ratelimit_interval_us,
		ssize_t ratelimit_max_bytes,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);
int rrr_net_transport_ctx_send_waiting_chunk_count (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
);
int rrr_net_transport_ctx_send_urgent (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
);
int rrr_net_transport_ctx_send_push_nullsafe (
		struct rrr_net_transport_handle *handle,
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_net_transport_ctx_read (
		uint64_t *bytes_read,
		struct rrr_net_transport_handle *handle,
		char *buf,
		size_t buf_size
);
int rrr_net_transport_ctx_handle_has_application_data (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_handle_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
);
void rrr_net_transport_ctx_handle_pre_destroy_function_set (
		struct rrr_net_transport_handle *handle,
		int (*pre_destroy_function)(struct rrr_net_transport_handle *handle, void *ptr)
);
void rrr_net_transport_ctx_get_socket_stats (
		uint64_t *bytes_read_total,
		uint64_t *bytes_written_total,
		uint64_t *bytes_total,
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_is_tls (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_connected_address_to_str (
		char *buf,
		size_t buf_size,
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_connected_address_get (
		const struct sockaddr **addr,
		socklen_t *addr_len,
		const struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_selected_proto_get (
		const char **proto,
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_iterate_with_callback (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_match_data_set (
		struct rrr_net_transport *transport,
		int transport_handle,
		const char *string,
		uint64_t number
);
int rrr_net_transport_check_handshake_complete (
		struct rrr_net_transport *transport,
		int transport_handle
);
int rrr_net_transport_bind_and_listen_dualstack (
		struct rrr_net_transport *transport,
		unsigned int port,
		void (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),
		void *arg
);
int rrr_net_transport_accept_all_handles (
		struct rrr_net_transport *transport,
		int at_most_one_accept,
		void (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *callback_arg
);
void rrr_net_transport_event_activate_all_connected_read (
		struct rrr_net_transport *transport
);
int rrr_net_transport_event_setup (
		struct rrr_net_transport *transport,
		uint64_t first_read_timeout_ms,
		uint64_t soft_read_timeout_ms,
		uint64_t hard_read_timeout_ms,
		int send_chunk_count_limit,
		void (*accept_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),
		void *accept_callback_arg,
		void (*handshake_complete_callback)(RRR_NET_TRANSPORT_HANDSHAKE_COMPLETE_CALLBACK_ARGS),
		void *handshake_complete_callback_arg,
		int (*read_callback)(RRR_NET_TRANSPORT_READ_CALLBACK_FINAL_ARGS),
		void *read_callback_arg
);

#endif /* RRR_NET_TRANSPORT_H */
