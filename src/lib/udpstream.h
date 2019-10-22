/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_UDPSTREAM_H
#define RRR_UDPSTREAM_H

#include <inttypes.h>
#include <endian.h>
#include <pthread.h>

#include "linked_list.h"
#include "rrr_socket.h"
#include "ip.h"

#define RRR_UDPSTREAM_VERSION 1
#define RRR_UDPSTREAM_BUFFER_MAX 250
#define RRR_UDPSTREAM_BURST_RECEIVE_MAX 100000
//#define RRR_UDPSTREAM_FRAME_SIZE_MAX 1024
#define RRR_UDPSTREAM_DATA_SIZE_MAX 20
#define RRR_UDPSTREAM_TIMEOUT_MS 5000
#define RRR_UDPSTREAM_RESEND_INTERVAL_MS 1000
#define RRR_UDPSTREAM_FRAME_ID_MAX 4294967295
#define RRR_UDPSTREAM_UNACKNOWLEDGED_LIMIT 5
#define RRR_UDPSTREAM_SEND_BURST_LIMIT 100
#define RRR_UDPSTREAM_SEND_SIZE_MAX 67584
#define RRR_UDPSTREAM_WINDOW_SIZE_MIN 75
#define RRR_UDPSTREAM_WINDOW_SIZE_INITIAL RRR_UDPSTREAM_FRAME_ID_MAX/2
#define RRR_UDPSTREAM_WINDOW_SIZE_MAX 25000

#define RRR_UDPSTREAM_OK 0
#define RRR_UDPSTREAM_ERR 1
#define RRR_UDPSTREAM_UNKNOWN_CONNECT_ID 2
#define RRR_UDPSTREAM_NOT_READY 3
#define RRR_UDPSTREAM_BUFFER_FULL 4
#define RRR_UDPSTREAM_RESET 5
#define RRR_UDPSTREAM_IDS_EXHAUSTED 6

#define RRR_UDPSTREAM_FRAME_FLAGS_CONNECT		(1<<0)
#define RRR_UDPSTREAM_FRAME_FLAGS_RESET			(1<<1)
#define RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY		(1<<2)
#define RRR_UDPSTREAM_FRAME_FLAGS_FRAME_ACK		(1<<3)
#define RRR_UDPSTREAM_FRAME_FLAGS_DELIVERY_ACK	(1<<4)
#define RRR_UDPSTREAM_FRAME_FLAGS_RELEASE_ACK	(1<<5)

#define RRR_UDPSTREAM_FRAME_FLAGS(frame) \
	((frame)->flags)
#define RRR_UDPSTREAM_FRAME_VERSION(frame) \
	((frame)->version)

#define RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame) \
	(be32toh((frame)->header_crc32))
#define RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame) \
	(be16toh((frame)->data_size))
#define RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame) \
	(sizeof(*(frame)) - 1 + RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame))
#define RRR_UDPSTREAM_FRAME_PACKED_DATA_PTR(frame) \
	(&(frame)->data)
#define RRR_UDPSTREAM_FRAME_PACKED_VERSION(frame) \
	((frame)->version)
#define RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(frame) \
	(be16toh((frame)->stream_id))
#define RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(frame) \
	(be32toh((frame)->frame_id))
#define RRR_UDPSTREAM_FRAME_PACKED_CONNECT_HANDLE(frame) \
	(be32toh((frame)->connect_handle))
#define RRR_UDPSTREAM_FRAME_PACKED_ACK_FIRST(frame) \
	(be32toh((frame)->ack_data.ack_id_first))
#define RRR_UDPSTREAM_FRAME_PACKED_ACK_LAST(frame) \
	(be32toh((frame)->ack_data.ack_id_last))
#define RRR_UDPSTREAM_FRAME_PACKED_BOUNDARY_ID(frame) \
	(be64toh((frame)->boundary_id))
#define RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame) \
	(be32toh((frame)->data_crc32))

#define RRR_UDPSTREAM_FRAME_IS_CONNECT(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_CONNECT) != 0)
#define RRR_UDPSTREAM_FRAME_IS_RESET(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_RESET) != 0)
#define RRR_UDPSTREAM_FRAME_IS_BOUNDARY(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY) != 0)
#define RRR_UDPSTREAM_FRAME_IS_FRAME_ACK(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_FRAME_ACK) != 0)
#define RRR_UDPSTREAM_FRAME_IS_DELIVERY_ACK(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_DELIVERY_ACK) != 0)
#define RRR_UDPSTREAM_FRAME_IS_RELEASE_ACK(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_RELEASE_ACK) != 0)

#define RRR_UDPSTREAM_HEADER_FIELDS 			\
	uint8_t flags;								\
	uint8_t version;							\
	uint16_t stream_id;							\
	union {										\
		uint32_t frame_id;						\
		uint32_t connect_handle;				\
	};											\
	union {										\
		struct rrr_udpstream_ack_data ack_data; \
		uint64_t boundary_id;					\
	};											\
	uint16_t data_size

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
	int64_t window_size;
	int invalidated;
};

struct rrr_udpstream_stream_collection {
	RRR_LL_HEAD(struct rrr_udpstream_stream);
};

#define RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS (1<<0)

struct rrr_udpstream {
	struct ip_data ip;
	int flags;
	struct rrr_udpstream_stream_collection streams;

	struct rrr_socket_read_session_collection read_sessions;

	pthread_mutex_t lock;

	// Used when receiving connections, find a free ID fast (hopefully)
	uint16_t next_stream_id;

	void *send_buffer;
	ssize_t send_buffer_size;
};

struct rrr_udpstream_receive_data {
	void *data;
	ssize_t data_size;
	uint32_t connect_handle;
	uint16_t stream_id;
	uint64_t boundary_id;
	const struct sockaddr *addr;
	socklen_t addr_len;
};

void rrr_udpstream_clear (
		struct rrr_udpstream *stream
);
void rrr_udpstream_init (
		struct rrr_udpstream *stream,
		int flags
);
void rrr_udpstream_set_flags (
		struct rrr_udpstream *data,
		int flags
);
int rrr_udpstream_do_process_receive_buffers (
		struct rrr_udpstream *data,
		int (*callback_validator)(ssize_t *target_size, void *data, ssize_t data_size, void *arg),
		void *callback_validator_arg,
		int (*callback)(struct rrr_udpstream_receive_data *receive_data, void *arg),
		void *callback_arg
);
int rrr_udpstream_do_read_tasks (
		struct rrr_udpstream *data,
		int (*delivery_listener)(uint16_t stream_id, uint64_t boundary_id, uint8_t frame_flags, void *arg),
		void *delivery_listener_arg
);
int rrr_udpstream_do_send_tasks (
		int *send_count,
		struct rrr_udpstream *data
);
int rrr_udpstream_stream_exists (
		struct rrr_udpstream *data,
		uint16_t stream_id
);
int rrr_udpstream_connection_check (
		struct rrr_udpstream *data,
		uint32_t connect_handle
);
int rrr_udpstream_release_ack_urge (
		struct rrr_udpstream *udpstream_data,
		uint16_t stream_id,
		uint64_t boundary_id,
		const struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_udpstream_queue_outbound_data (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		const void *data,
		ssize_t data_size,
		uint64_t boundary_identifier
);
void rrr_udpstream_close (
		struct rrr_udpstream *data
);
int rrr_udpstream_bind (
		struct rrr_udpstream *data,
		unsigned int local_port
);
int rrr_udpstream_connect_raw (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		struct sockaddr *addr,
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
