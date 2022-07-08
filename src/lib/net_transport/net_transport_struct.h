/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "net_transport.h"
#include "net_transport_defines.h"
#include "net_transport_connection_id.h"

#include "../rrr_types.h"
#include "../read.h"
#include "../read_constants.h"
#include "../socket/rrr_socket.h"
#include "../util/linked_list.h"
#include "../event/event_collection_struct.h"

struct rrr_read_session;
struct rrr_net_transport;
struct rrr_net_transport_config;
struct rrr_nullsafe_str;

#define RRR_NET_TRANSPORT_DESTROY_ARGS                         \
    struct rrr_net_transport *transport
    
#define RRR_NET_TRANSPORT_CONNECT_ARGS                         \
    rrr_net_transport_handle *handle,                          \
    struct sockaddr *addr,                                     \
    socklen_t *socklen,                                        \
    struct rrr_net_transport *transport,                       \
    uint16_t port,                                             \
    const char *host

#define RRR_NET_TRANSPORT_MIGRATE_ARGS                         \
    struct rrr_net_transport_handle *handle,                   \
    struct sockaddr *addr,                                     \
    socklen_t *socklen,                                        \
    struct rrr_net_transport *transport,                       \
    uint16_t port,                                             \
    const char *host

#define RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD                                                      \
    struct rrr_net_transport_handle *handle;                                                           \
    int (*get_target_size)(struct rrr_read_session *read_session, void *arg);                          \
    void *get_target_size_arg;                                                                         \
    void (*get_target_size_error)(struct rrr_read_session *read_session, int is_hard_err, void *arg);  \
    void *get_target_size_error_arg;                                                                   \
    int (*complete_callback)(struct rrr_read_session *read_session, void *arg);                        \
    void *complete_callback_arg;

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS                \
    struct rrr_net_transport *transport,                                            \
    rrr_net_transport_handle transport_handle,                                      \
    void (*final_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg,                                                       \
    void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS                                      \
    struct rrr_net_transport *transport,                                            \
    uint16_t port,                                                                  \
    int do_ipv6,                                                                    \
    int (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS),  \
    void *callback_arg,                                                             \
    void (*callback_final)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),  \
    void *callback_final_arg

#define RRR_NET_TRANSPORT_DECODE_ARGS                                      \
    struct rrr_net_transport_connection_id_pair *connection_ids,           \
    struct rrr_socket_datagram *datagram,                                  \
    uint8_t *buf,                                                          \
    size_t buf_size,                                                       \
    struct rrr_net_transport_handle *listen_handle

#define RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS                \
    struct rrr_net_transport *transport,                                   \
    rrr_net_transport_handle transport_handle,                             \
    const struct sockaddr *sockaddr,                                       \
    socklen_t socklen,                                                     \
    void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg,                                              \
    void *arg

#define RRR_NET_TRANSPORT_ACCEPT_ARGS                                      \
    rrr_net_transport_handle *new_handle,                                  \
    struct rrr_net_transport_handle *listen_handle,                        \
    const struct rrr_net_transport_connection_id_pair *connection_ids,     \
    const struct rrr_socket_datagram *datagram,                            \
    int (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS),  \
    void *callback_arg,                                                    \
    void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),  \
    void *final_callback_arg

#define RRR_NET_TRANSPORT_CLOSE_ARGS                           \
    struct rrr_net_transport_handle *handle

#define RRR_NET_TRANSPORT_READ_MESSAGE_ARGS                                     \
    uint64_t *bytes_read,                                                       \
    struct rrr_net_transport_handle *handle,                                    \
    const rrr_biglength read_step_initial,                                      \
    const rrr_biglength read_step_max_size,                                     \
    const rrr_biglength read_max_size,                                          \
    uint64_t ratelimit_interval_us,                                             \
    const rrr_biglength ratelimit_max_bytes,                                    \
    int (*get_target_size)(struct rrr_read_session *read_session, void *arg),   \
    void *get_target_size_arg,                                                  \
    void (*get_target_size_error)(struct rrr_read_session *read_session, int is_hard_err, void *arg), \
    void *get_target_size_error_arg,                                            \
    int (*complete_callback)(struct rrr_read_session *read_session, void *arg), \
    void *complete_callback_arg

#define RRR_NET_TRANSPORT_READ_ARGS                            \
    uint64_t *bytes_read,                                      \
    struct rrr_net_transport_handle *handle,                   \
    char *buf,                                                 \
    rrr_biglength buf_size

#define RRR_NET_TRANSPORT_READ_STREAM_ARGS                         \
    uint64_t *bytes_read,                                          \
    struct rrr_net_transport_handle *handle,                       \
    int (*callback)(RRR_NET_TRANSPORT_READ_STREAM_CALLBACK_ARGS),  \
    void *callback_arg

#define RRR_NET_TRANSPORT_RECEIVE_ARGS                         \
    struct rrr_net_transport_handle *handle,                   \
    const struct rrr_socket_datagram *datagram

#define RRR_NET_TRANSPORT_POLL_ARGS                            \
    struct rrr_net_transport_handle *handle

#define RRR_NET_TRANSPORT_HANDSHAKE_ARGS                       \
    struct rrr_net_transport_handle *handle

#define RRR_NET_TRANSPORT_STREAM_OPEN_ARGS                     \
    int64_t *result,                                           \
    struct rrr_net_transport_handle *handle,                   \
    int flags,                                                 \
    void *stream_data,                                         \
    void (*stream_data_destroy)(void *stream_data)

#define RRR_NET_TRANSPORT_STREAM_COUNT_ARGS                    \
    struct rrr_net_transport_handle *handle

#define RRR_NET_TRANSPORT_STREAM_CONSUME_ARGS                  \
    struct rrr_net_transport_handle *handle,                   \
    int64_t stream_id,                                         \
    size_t consumed

#define RRR_NET_TRANSPORT_SEND_ARGS                            \
    rrr_biglength *bytes_written,                              \
    struct rrr_net_transport_handle *handle,                   \
    const void *data,                                          \
    rrr_biglength size

#define RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS              \
    char **proto,                                              \
    struct rrr_net_transport_handle *handle

struct rrr_net_transport_read_callback_data {
	RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD;
};

struct rrr_net_transport_methods {
	// Destroy handle
	void (*destroy)(RRR_NET_TRANSPORT_DESTROY_ARGS);

	// Create outbound connection
	int (*connect)(RRR_NET_TRANSPORT_CONNECT_ARGS);

	// Migrate outbound connection
	int (*migrate)(RRR_NET_TRANSPORT_MIGRATE_ARGS);

	// Start listening on inbound connections (server mode)
	int (*bind_and_listen)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS);

	// Decode datagram and get identifiers for datagram oriented transports
	int (*decode)(RRR_NET_TRANSPORT_DECODE_ARGS);

	// Create handle on datagram oriented transport or accept
	// connection + create handle on connection oriented transport
	int (*accept)(RRR_NET_TRANSPORT_ACCEPT_ARGS);

	// Close handle nicely, only call close() from parent mode destroy function
	int (*close)(RRR_NET_TRANSPORT_CLOSE_ARGS);

	// Read message on connection oriented handle
	int (*read_message)(RRR_NET_TRANSPORT_READ_MESSAGE_ARGS);

	// Read data on non-stream oriented handle
	int (*read)(RRR_NET_TRANSPORT_READ_ARGS);

	// Read data on stream oriented handle
	int (*read_stream)(RRR_NET_TRANSPORT_READ_STREAM_ARGS);

	// Receive data on datagram-oriented transport handle. After the
	// main (listen ) handle has received data and identified the
	// corresponding handle, receive is called.
	int (*receive)(RRR_NET_TRANSPORT_RECEIVE_ARGS);

	// Send data on stream-oriented transport handle. Causes the stream_open
	// callback given to rrr_net_transport_new to be called from which the
	// application must return data delivery callbacks.
	int (*stream_open)(RRR_NET_TRANSPORT_STREAM_OPEN_ARGS);

	// Count number of open streams on stream-oriented transport handle. Note
	// that only streams which the submodule actually keeps track of is counted.
	uint64_t (*stream_count)(RRR_NET_TRANSPORT_STREAM_COUNT_ARGS);

	// Must be called 
	int (*stream_consume)(RRR_NET_TRANSPORT_STREAM_CONSUME_ARGS);

	// Send data on non-stream oriented transport
	int (*send)(RRR_NET_TRANSPORT_SEND_ARGS);

	// Check for data on non-stream oriented transport
	int (*poll)(RRR_NET_TRANSPORT_POLL_ARGS);

	// Perform handshake on non-stream oriented transport
	int (*handshake)(RRR_NET_TRANSPORT_HANDSHAKE_ARGS);

	// Check if transport is TLS
	int (*is_tls)(void);

	// Get selected ALPN protocol
	int (*selected_proto_get)(RRR_NET_TRANSPORT_SELECTED_PROTO_GET_ARGS);
};

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);

	rrr_net_transport_handle handle;

	struct rrr_net_transport *transport;
	enum rrr_net_transport_socket_mode mode;

	// Used for stream type communication
	int submodule_fd;
	struct rrr_read_session_collection read_sessions;

	// Used for datagram type communication
	struct rrr_net_transport_connection_id_collection cids;

	struct rrr_event_collection events;
	rrr_event_handle event_handshake;
	rrr_event_handle event_read;
	rrr_event_handle event_read_notify;
	rrr_event_handle event_write;
	rrr_event_handle event_first_read_timeout;
	rrr_event_handle event_hard_read_timeout;

	uint64_t bytes_read_total;
	uint64_t bytes_written_total;

	uint64_t noread_strike_prev_read_bytes;
	uint64_t noread_strike_count;

	struct rrr_socket_send_chunk_collection send_chunks;
	int close_when_send_complete;
	int close_now;

#ifdef RRR_NET_TRANSPORT_READ_RET_DEBUG
	unsigned int read_ret_debug_ok;
	unsigned int read_ret_debug_incomplete;
	unsigned int read_ret_debug_soft_error;
	unsigned int read_ret_debug_hard_error;
	unsigned int read_ret_debug_eof;
#endif

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

	// Like error code in a close frame
	uint32_t submodule_close_reason;

	// Called first when we try to destroy. When it returns 0,
	// we go ahead with destruction and call ptr_destroy. Only
	// used from within the iterator function. Both submodule and
	// application layer may set this function. Submodule should
	// override any function set by application layer as needed.
	int (*iterator_pre_destroy)(RRR_NET_TRANSPORT_PRE_DESTROY_ARGS);
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	rrr_net_transport_handle next_handle_position;
};

struct rrr_net_transport {
    RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport);
};

#endif /* RRR_NET_TRANSPORT_STRUCT_H */
