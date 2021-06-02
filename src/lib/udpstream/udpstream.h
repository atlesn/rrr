/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

// This API is used to provide regulated safe delivery of messages using
// UDP. This is useful for lossy connections and where TCP timers or head of line
// blocking cause issues.

// NOT SAFE ON OPEN NETWORKS, IMPLEMENT AT OWN RISK

// A client may be configured to accept connections from other clients. Two
// clients will together create a stream which they use to transfer data.
// Received data must be acknowledged to the sender.

// A large message might be split up into smaller frames, this is handled
// automatically and the API user only sends in whole messages of arbitrary
// size and the receiver will get them out exactly as sent.

// There is also support for "assured single delivery"/"ASD" of messages. But this
// requires the API user to hold sent and received messages. This API
// however, provides message types to handle this the way MQTT QoS2 works
// and will send the appropriate ACK messages back an forward even if a
// client does not actually implement ASD. If a client chooses not to, it must
// provide a dummy callback function to the API.

// Data sent to UDP-stream is copied, indicated by using const pointers. For data given to
// back to the API user using the data callback function upon receival, it is expected that
// the callback takes care of this memory or frees it, also on errors. If not, it will always
// leak. This is indicated with the pointer being non-const.

#ifndef RRR_UDPSTREAM_H
#define RRR_UDPSTREAM_H

#include <inttypes.h>

#include "../read.h"
#include "../read_constants.h"
#include "../ip/ip.h"
#include "../util/rrr_endian.h"
#include "../util/linked_list.h"
#include "../event/event_collection.h"

#define RRR_UDPSTREAM_OK                  RRR_READ_OK
#define RRR_UDPSTREAM_HARD_ERR            RRR_READ_HARD_ERROR
#define RRR_UDPSTREAM_SOFT_ERR            RRR_READ_SOFT_ERROR
#define RRR_UDPSTREAM_NOT_READY           RRR_READ_INCOMPLETE

#define RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS (1<<0)
#define RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP (1<<1)
#define RRR_UDPSTREAM_FLAGS_FIXED_CONNECT_HANDLE (1<<2)

// These parameters are useful to upstream framework, it's tuning
// parameters should derive from these values.

#define RRR_UDPSTREAM_RESEND_INTERVAL_FRAME_MS 1000
#define RRR_UDPSTREAM_BUFFER_LIMIT 1500
#define RRR_UDPSTREAM_WINDOW_SIZE_MAX RRR_UDPSTREAM_BUFFER_LIMIT*2
#define RRR_UDPSTREAM_WINDOW_SIZE_INITIAL RRR_UDPSTREAM_WINDOW_SIZE_MAX/4

#define RRR_UDPSTREAM_HEADER_FIELDS                            \
    uint8_t flags_and_type;                                    \
    uint8_t version;                                           \
    uint16_t stream_id;                                        \
    union {                                                    \
        uint32_t frame_id;                                     \
        uint32_t connect_handle;                               \
        uint32_t window_size;                                  \
    };                                                         \
    union {                                                    \
        struct rrr_udpstream_ack_data ack_data;                \
        uint64_t application_data;                             \
    };                                                         \
    uint16_t data_size

#define RRR_UDPSTREAM_RECEIVE_CALLBACK_ARGS                    \
    void **joined_data,                                        \
    void *allocation_handle,                                   \
    void *udpstream_callback_arg

#define RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS                  \
    uint32_t size,                                             \
    const struct sockaddr *remote_addr,                        \
    socklen_t remote_addr_len,                                 \
    int (*receive_callback)(RRR_UDPSTREAM_RECEIVE_CALLBACK_ARGS),\
    void *udpstream_callback_arg,                              \
    void *arg

#define RRR_UDPSTREAM_VALIDATOR_CALLBACK_ARGS                  \
    RRR_READ_COMMON_GET_TARGET_LENGTH_FROM_MSG_RAW_ARGS

#define RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_ARGS              \
    void **joined_data,                                        \
    const struct rrr_udpstream_receive_data *receive_data,     \
    void *arg

struct rrr_udpstream_ack_data {
	uint32_t ack_id_first;
	uint32_t ack_id_last;
};

struct rrr_udpstream_frame_packed {
	uint32_t header_crc32;

	RRR_UDPSTREAM_HEADER_FIELDS;

	uint32_t data_crc32;
	char data[1];
} __attribute((packed));

struct rrr_udpstream_frame {
	RRR_LL_NODE(struct rrr_udpstream_frame);

	uint64_t last_send_time;
	int unacknowledged_count;
	int ack_grace;

	struct sockaddr *source_addr;
	socklen_t source_addr_len;

	RRR_UDPSTREAM_HEADER_FIELDS;

	void *data;
};

struct rrr_udpstream_frame_buffer {
	RRR_LL_HEAD(struct rrr_udpstream_frame);
	uint32_t frame_id_max;
	uint32_t frame_id_counter;
	uint32_t frame_id_prev_boundary_pos;
};

struct rrr_udpstream_stream {
	RRR_LL_NODE(struct rrr_udpstream_stream);
	struct rrr_udpstream_frame_buffer receive_buffer;
	struct rrr_udpstream_frame_buffer send_buffer;
	uint16_t stream_id;
	uint32_t connect_handle;
	struct sockaddr *remote_addr;
	socklen_t remote_addr_len;
	uint64_t last_seen;
	uint32_t window_size_to_remote;
	uint32_t window_size_from_remote;
	int window_size_regulation_from_application;
	int invalidated;
	int hard_reset_received;
};

struct rrr_udpstream_stream_collection {
	RRR_LL_HEAD(struct rrr_udpstream_stream);
};

// Used when data is delivered to the API user after receiving a full message
struct rrr_udpstream_receive_data {
	void *allocation_handle;
	ssize_t data_size;
	uint32_t connect_handle;
	uint16_t stream_id;
	uint64_t application_data;
	const struct sockaddr *addr;
	socklen_t addr_len;
};

// The API user must allocate this struct either statically or dynamically.
// Before freeing it, the clear function must be called. Before using, the init
// function must be called.
struct rrr_udpstream {
	struct rrr_ip_data ip;
	int flags;

	struct rrr_udpstream_stream_collection streams;
	struct rrr_read_session_collection read_sessions;

	struct rrr_event_queue *queue;
	struct rrr_event_collection events;

	rrr_event_handle event_read;
	rrr_event_handle event_write;
	rrr_event_handle event_periodic;

	unsigned int event_read_current_timeout;

	int (*upstream_event_write)(int *no_more_writes, void *arg);
	void *upstream_event_write_arg;
	int (*upstream_event_read)(int *no_more_reads, int *ready_for_delivery, void *arg);
	void *upstream_event_read_arg;
	int (*upstream_control_frame_callback)(uint32_t connect_handle, uint64_t application_data, void *arg);
	void *upstream_control_frame_callback_arg;
	int (*upstream_allocator_callback) (RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS);
	void *upstream_allocator_callback_arg;
	int (*upstream_validator_callback)(RRR_UDPSTREAM_VALIDATOR_CALLBACK_ARGS);
	void *upstream_validator_callback_arg;
	int (*upstream_final_callback)(RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_ARGS);
	void *upstream_final_callback_arg;

	void *send_buffer;
	ssize_t send_buffer_size;
};

struct rrr_udpstream_send_data {
	const void *data;
	ssize_t data_size;
	uint32_t connect_handle;
	uint16_t stream_id;
	uint64_t application_data;
	const struct sockaddr *addr;
	socklen_t addr_len;
};

// Not to be dereferenced by application
struct rrr_udpstream_process_receive_buffer_callback_data;

// Clear and initialize a UDP-stream
void rrr_udpstream_clear (
		struct rrr_udpstream *stream
);
int rrr_udpstream_init (
		struct rrr_udpstream *stream,
		struct rrr_event_queue *queue,
		int flags,
		int (*upstream_event_write)(int *no_more_writes, void *arg),
		void *upstream_event_write_arg,
		int (*upstream_event_read)(int *no_more_reads, int *ready_for_delivery, void *arg),
		void *upstream_event_read_arg,
		int (*upstream_control_frame_callback)(uint32_t connect_handle, uint64_t application_data, void *arg),
		void *upstream_control_frame_callback_arg,
		int (*upstream_allocator_callback) (RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS),
		void *upstream_allocator_callback_arg,
		int (*upstream_validator_callback)(RRR_UDPSTREAM_VALIDATOR_CALLBACK_ARGS),
		void *upstream_validator_callback_arg,
		int (*upstream_final_callback)(RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_ARGS),
		void *upstream_final_callback_arg
);

// Change the flags after initialization, may be called at any time
void rrr_udpstream_set_flags (
		struct rrr_udpstream *data,
		int flags
);

// A callback function for allocating memory for final message must be provided. With this,
// it is possible to wrap any data copying from message chunks to the final messages inside
// locks to provide memory fence.
//
// The costum allocator must call the callback with the provided arguments. A pointer to a
// buffer of the required size is to be given in joined_data. If the pointer has not been
// set to NULL when the callback returns, the allocator must free the memory.
//
// If the pointer to the buffer is part of another data structure which has also been allocated,
// a pointer to this data structure may be sent in allocation_handle.

/* Disabled, currently not used
int rrr_udpstream_default_allocator (
		uint32_t size,
		int (*callback)(void **joined_data, void *allocation_handle, void *udpstream_data),
		void *udpstream_data,
		void *arg
);
*/

// Check if a particular stream ID is registered
int rrr_udpstream_stream_exists (
		struct rrr_udpstream *data,
		uint16_t stream_id
);

// For most calls, the original connect handle obtained when connecting is used
// to distinguish different streams.

// Check if the provided address matches that of the registered connect handle
int rrr_udpstream_connection_check_address_equal (
		struct rrr_udpstream *data,
		uint32_t connect_handle,
		const struct sockaddr *addr,
		socklen_t addr_len
);

// Get the status of a connection
int rrr_udpstream_connection_check (
		struct rrr_udpstream *data,
		uint32_t connect_handle
);
int rrr_udpstream_regulate_window_size (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		int window_size_change
);
int rrr_udpstream_send_control_frame (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		uint64_t application_data
);
int rrr_udpstream_queue_outbound_data (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		const void *data,
		ssize_t data_size,
		uint64_t application_data
);
void rrr_udpstream_close (
		struct rrr_udpstream *data
);
int rrr_udpstream_bind_v6_priority (
		struct rrr_udpstream *data,
		unsigned int local_port
);
int rrr_udpstream_bind_v4_only (
		struct rrr_udpstream *data,
		unsigned int local_port
);
int rrr_udpstream_connect_raw (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen
);
int rrr_udpstream_connect (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const char *remote_host,
		const char *remote_port
);
void rrr_udpstream_dump_stats (
		struct rrr_udpstream *data
);

#endif /* RRR_UDPSTREAM_H */
