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

#ifndef RRR_NET_TRANSPORT_STRUCT_H
#define RRR_NET_TRANSPORT_STRUCT_H

#include <sys/types.h>
#include <pthread.h>

#include "net_transport.h"
#include "net_transport_defines.h"

#include "../read.h"
#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../event/event_collection.h"

struct rrr_read_session;
struct rrr_net_transport;
struct rrr_net_transport_config;
struct rrr_nullsafe_str;

struct rrr_net_transport_handle_close_tag_node {
	RRR_LL_NODE(struct rrr_net_transport_handle_close_tag_node);
	int transport_handle;
};

#define RRR_NET_TRANSPORT_CONNECT_ARGS                         \
    int *handle,                                               \
    struct sockaddr *addr,                                     \
    socklen_t *socklen,                                        \
    struct rrr_net_transport *transport,                       \
    unsigned int port,                                         \
    const char *host

#define RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD                                \
    struct rrr_net_transport_handle *handle;                                     \
    int (*get_target_size)(struct rrr_read_session *read_session, void *arg);    \
    void *get_target_size_arg;                                                   \
    int (*complete_callback)(struct rrr_read_session *read_session, void *arg);  \
    void *complete_callback_arg;

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS                \
    struct rrr_net_transport *transport,                                            \
    int transport_handle,                                                           \
    void (*final_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg,                                                       \
    void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS                                      \
    struct rrr_net_transport *transport,                                            \
    unsigned int port,                                                              \
    int do_ipv6,                                                                    \
    int (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS),  \
    void *callback_arg,                                                             \
    void (*callback_final)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),  \
    void *callback_final_arg

#define RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS                \
    struct rrr_net_transport *transport,                                   \
    int transport_handle,                                                  \
    const struct sockaddr *sockaddr,                                       \
    socklen_t socklen,                                                     \
    void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg,                                              \
    void *arg

#define RRR_NET_TRANSPORT_ACCEPT_ARGS                                      \
    int *did_accept,                                                       \
    struct rrr_net_transport_handle *listen_handle,                        \
    int (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS),  \
    void *callback_arg,                                                    \
    void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg

#define RRR_NET_TRANSPORT_READ_MESSAGE_ARGS                                     \
    uint64_t *bytes_read,                                                       \
    struct rrr_net_transport_handle *handle,                                    \
    int read_attempts,                                                          \
    ssize_t read_step_initial,                                                  \
    ssize_t read_step_max_size,                                                 \
    ssize_t read_max_size,                                                      \
    uint64_t ratelimit_interval_us,                                             \
    ssize_t ratelimit_max_bytes,                                                \
    int (*get_target_size)(struct rrr_read_session *read_session, void *arg),   \
    void *get_target_size_arg,                                                  \
    int (*complete_callback)(struct rrr_read_session *read_session, void *arg), \
    void *complete_callback_arg

#define RRR_NET_TRANSPORT_READ_ARGS                            \
    uint64_t *bytes_read,                                      \
    struct rrr_net_transport_handle *handle,                   \
    char *buf,                                                 \
    size_t buf_size

#define RRR_NET_TRANSPORT_POLL_ARGS                  \
    unsigned char *want_read,                        \
    unsigned char *want_write,                       \

struct rrr_net_transport_read_callback_data {
	RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD;
};

struct rrr_net_transport_methods {
	void (*destroy)(
			struct rrr_net_transport *transport
	);
	int (*connect)(RRR_NET_TRANSPORT_CONNECT_ARGS);
	int (*bind_and_listen)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS);
	int (*accept)(RRR_NET_TRANSPORT_ACCEPT_ARGS);
	// Only call close() from parent mode destroy function
	int (*close)(
			struct rrr_net_transport_handle *handle
	);
	int (*read_message)(RRR_NET_TRANSPORT_READ_MESSAGE_ARGS);
	int (*read)(RRR_NET_TRANSPORT_READ_ARGS);
	int (*send)(
			uint64_t *bytes_written,
			struct rrr_net_transport_handle *handle,
			const void *data,
			ssize_t size
	);
	int (*poll)(
    		struct rrr_net_transport_handle *handle
	);
	int (*handshake)(
			struct rrr_net_transport_handle *handle
	);
	int (*is_tls)(void);
	void (*selected_proto_get)(
			const char **proto,
			struct rrr_net_transport_handle *handle
	);
};

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);

	int lock_count;
	struct rrr_net_transport *transport;
	int handle;
	enum rrr_net_transport_socket_mode mode;
	struct rrr_read_session_collection read_sessions;

	int submodule_fd;

	struct rrr_event_collection events;
	rrr_event_handle event_handshake;
	rrr_event_handle event_read;
	rrr_event_handle event_write;
	rrr_event_handle event_first_read_timeout;
	rrr_event_handle event_hard_read_timeout;

	uint64_t bytes_read_total;
	uint64_t bytes_written_total;

	struct rrr_socket_send_chunk_collection send_chunks;

	struct sockaddr_storage connected_addr;
	socklen_t connected_addr_len;

	// Like SSL data or plain FD
	void *submodule_private_ptr;

	// Like HTTP session
	void *application_private_ptr;
	void (*application_ptr_destroy)(void *ptr);

	// Optionally used to find existing connections to remotes
	char *match_string;
	uint64_t match_number;

	// Transport handshake is complete, application may be called
	int handshake_complete;

	// Called first when we try to destroy. When it returns 0,
	// we go ahead with destruction and call ptr_destroy. Only
	// used from within the iterator function.
	int (*application_ptr_iterator_pre_destroy)(struct rrr_net_transport_handle *handle, void *ptr);
};

struct rrr_net_transport_handle_close_tag_list {
	RRR_LL_HEAD(struct rrr_net_transport_handle_close_tag_node);
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	int next_handle_position;

	struct rrr_net_transport_handle_close_tag_list close_tags;
};

struct rrr_net_transport {
    RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport);
};

#endif /* RRR_NET_TRANSPORT_STRUCT_H */
