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

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "../log.h"
#include "../allocator.h"
#include "udpstream.h"
#include "../read.h"
#include "../random.h"
#include "../event/event.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_read.h"
#include "../socket/rrr_socket_client.h"
#include "../util/macro_utils.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"
#include "../util/crc32.h"
#include "../util/posix.h"
#include "../helpers/string_builder.h"
#include "../ip/ip_util.h"

// Configuration
#define RRR_UDPSTREAM_VERSION 3
#define RRR_UDPSTREAM_VERSION_MINIMUM 2

#define RRR_UDPSTREAM_BURST_LIMIT_RECEIVE 50
#define RRR_UDPSTREAM_BURST_LIMIT_SEND 100

#define RRR_UDPSTREAM_MESSAGE_SIZE_MAX 67584

#define RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT 1024
#define RRR_UDPSTREAM_FRAME_ID_LIMIT 50000000 // 50 mill

#define RRR_UDPSTREAM_BOUNDARY_POS_LOW_MAX 0xfffffff0

#define RRR_UDPSTREAM_CONNECTION_TIMEOUT_MS 240000
#define RRR_UDPSTREAM_CONNECTION_INVALID_TIMEOUT_MS (RRR_UDPSTREAM_CONNECTION_TIMEOUT_MS*2)

#define RRR_UDPSTREAM_RESEND_UNACKNOWLEDGED_LIMIT 5

#define RRR_UDPSTREAM_EVENT_READ_TIMEOUT_MS_SHORT 10
#define RRR_UDPSTREAM_EVENT_READ_TIMEOUT_MS_LONG 50

#define RRR_UDPSTREAM_WINDOW_SIZE_PENALTY_BUFFER_HOLE -5
#define RRR_UDPSTREAM_WINDOW_SIZE_GAIN_BUFFER_COMPLETE -5
#define RRR_UDPSTREAM_WINDOW_SIZE_MIN 10

// Flags and type are stored together, 4 bits each. Lower 4 are for type.

// Current frame is a message boundary (end of a message). Preceding frames
// after previous boundary (if any) including boundary message are to be merged.
#define RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY			(1<<0)

// Regulate window size. Receiver sends this to tell a sender to slow down or
// speed up. Any ACK packet may contain window size regulation.
#define RRR_UDPSTREAM_FRAME_FLAGS_WINDOW_SIZE		(1<<1)

// Used to initiate connection stop. If the reset packet contains a frame id,
// delivery of frames up to this point is completed before the connection
// is closed. If frame id is zero, a hard reset is performed and sending should
// stop immediately and a new stream must be used instead. This might happen
// if a client restarts and gets ready again before the connection times out.
#define RRR_UDPSTREAM_FRAME_TYPE_RESET				0

// Used to initiate a new stream, both request and response
#define RRR_UDPSTREAM_FRAME_TYPE_CONNECT			1

// Used for data transmission
#define RRR_UDPSTREAM_FRAME_TYPE_DATA				3

// Used to acknowledge frames and to regulate window size
#define RRR_UDPSTREAM_FRAME_TYPE_FRAME_ACK			4

// Used for control packets with no data. The application_data field may be used
// by the application to exchange control data. Delivery is not guaranteed like
// with data packets, control packets are just sent immediately.
#define RRR_UDPSTREAM_FRAME_TYPE_CONTROL			5

#define RRR_UDPSTREAM_FRAME_TYPE(frame) \
	((frame)->flags_and_type & 0x0f)
#define RRR_UDPSTREAM_FRAME_FLAGS(frame) \
	((frame)->flags_and_type >> 4)
#define RRR_UDPSTREAM_FRAME_VERSION(frame) \
	((frame)->version)

// Every frame contains a CRC32 checksum. Upon mismatch, frames are dropped and must be re-sent.
// This CRC32 verifies the header only and is used to make sure the data length specified in
// a frame is valid.
#define RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame) \
	(rrr_be32toh((frame)->header_crc32))

#define RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame) \
	(rrr_be16toh((frame)->data_size))
#define RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame) \
	(sizeof(*(frame)) - 1 + RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame))

#define RRR_UDPSTREAM_FRAME_PACKED_DATA_PTR(frame) \
	(&(frame)->data)

#define RRR_UDPSTREAM_FRAME_PACKED_VERSION(frame) \
	((frame)->version)

// Each stream has an ID which is chosen randomly. The sender IP/port is not
// checked when frames are received, and it is not a problem if this changes
// as long as the same stream ID is used and the connection does not time out.
#define RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(frame) \
	(rrr_be16toh((frame)->stream_id))

// Number to identify each frame. Begins with 1 for each new stream. The IDs
// may become exhausted if there are a lot of traffic or for long-lasting streams,
// after which a new stream must be initiated.
#define RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(frame) \
	(rrr_be32toh((frame)->frame_id))

// Identifier chosen randomly to match sent CONNECT frames with received ones. It
// is possible to have collisions (although unlikely), and a client might reject
// a connection if a connect handle is already taken.
#define RRR_UDPSTREAM_FRAME_PACKED_CONNECT_HANDLE(frame) \
	(rrr_be32toh((frame)->connect_handle))

// Frame ACK messages contain an ACK range which specifies a low and high frame ID
// for frames which are received. ACK frames are sent constantly for all messages
// which are currently not delivered to the application. A single data frame may therefore
// be "mentioned" in multiple ACK frames.

// Each time a sender receives an ACK frame,
// it increments the "unacknowledged counter" for frames which was not mentioned in the ACK.
// If this counter reached a specific limit, the frame is re-sent. The way a client sends
// ACK packets will therefore ensure that frames which are missing out (holes in the stream)
// is re-sent.

// If there are missing frames and holes in the receive buffer, a client will request the
// window size to be reduced slightly. If there are no holes, the window size is carefully
// increased.
#define RRR_UDPSTREAM_FRAME_PACKED_ACK_FIRST(frame) \
	(rrr_be32toh((frame)->ack_data.ack_id_first))
#define RRR_UDPSTREAM_FRAME_PACKED_ACK_LAST(frame) \
	(rrr_be32toh((frame)->ack_data.ack_id_last))

#define RRR_UDPSTREAM_FRAME_PACKED_APPLICATION_DATA(frame) \
	(rrr_be64toh((frame)->application_data))

// After a full frame with data is received, this checksum is verified
#define RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame) \
	(rrr_be32toh((frame)->data_crc32))

#define RRR_UDPSTREAM_FRAME_IS_BOUNDARY(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY) != 0)
#define RRR_UDPSTREAM_FRAME_HAS_WINDOW_SIZE(frame) \
	((RRR_UDPSTREAM_FRAME_FLAGS(frame) & RRR_UDPSTREAM_FRAME_FLAGS_WINDOW_SIZE) != 0)

#define RRR_UDPSTREAM_FRAME_IS_CONNECT(frame) \
	((RRR_UDPSTREAM_FRAME_TYPE(frame) == RRR_UDPSTREAM_FRAME_TYPE_CONNECT) != 0)
#define RRR_UDPSTREAM_FRAME_IS_FRAME_ACK(frame) \
	((RRR_UDPSTREAM_FRAME_TYPE(frame) == RRR_UDPSTREAM_FRAME_TYPE_FRAME_ACK) != 0)
#define RRR_UDPSTREAM_FRAME_IS_DATA(frame) \
	((RRR_UDPSTREAM_FRAME_TYPE(frame) == RRR_UDPSTREAM_FRAME_TYPE_DATA) != 0)
#define RRR_UDPSTREAM_FRAME_IS_CONTROL(frame) \
	((RRR_UDPSTREAM_FRAME_TYPE(frame) == RRR_UDPSTREAM_FRAME_TYPE_CONTROL) != 0)
#define RRR_UDPSTREAM_FRAME_IS_RESET(frame) \
	((RRR_UDPSTREAM_FRAME_TYPE(frame) == RRR_UDPSTREAM_FRAME_TYPE_RESET) != 0)

// Forget to send a certain percentage of outbound packets (randomized). Comment out to disable.
//#define RRR_UDPSTREAM_PACKET_LOSS_DEBUG_PERCENT 10

static int __rrr_udpstream_frame_destroy(struct rrr_udpstream_frame *frame) {
	RRR_FREE_IF_NOT_NULL(frame->data);
	RRR_FREE_IF_NOT_NULL(frame->source_addr);
	rrr_free(frame);
	return 0;
}

static int __rrr_udpstream_frame_new_from_data (
		struct rrr_udpstream_frame **target,
		const void *data,
		uint16_t data_size
) {
	int ret = 0;

	*target = NULL;

	struct rrr_udpstream_frame *res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_udpstream_frame_new_from_data A\n");
		ret = 1;
		goto out;
	}
	memset(res, '\0', sizeof(*res));

	if (data_size > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) {
		RRR_BUG("Data size was exceeds maximum in __rrr_udpstream_frame_new_from_data\n");
	}

	if (data_size > 0) {
		res->data = rrr_allocate(data_size);
		if (res->data == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_udpstream_frame_new_from_data B\n");
			ret = 1;
			goto out;
		}
		res->data_size = data_size;
		memcpy(res->data, data, data_size);
	}

	*target = res;
	res = NULL;

	out:
	if (res != NULL) {
		__rrr_udpstream_frame_destroy(res);
	}
	return ret;
}

static int __rrr_udpstream_frame_new_from_packed (
		struct rrr_udpstream_frame **target,
		const struct rrr_udpstream_frame_packed *template,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	struct rrr_udpstream_frame *result = NULL;

	uint16_t data_size = RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(template);
	if ((ret = __rrr_udpstream_frame_new_from_data (&result, template->data, data_size)) != 0) {
		goto out;
	}

	if (addr_len > 0) {
		if ((result->source_addr = rrr_allocate(addr_len)) == NULL) {
			RRR_MSG_0("Could not allocate memory for address in __rrr_udpstream_frame_new_from_packed\n");
			ret = 1;
			goto out;
		}
		memcpy(result->source_addr, addr, addr_len);
	}

	result->source_addr_len = addr_len;
	result->flags_and_type = template->flags_and_type;
	result->version = template->version;
	result->frame_id = RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(template);
	result->stream_id = RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(template);
	if (RRR_UDPSTREAM_FRAME_IS_FRAME_ACK(template)) {
		result->ack_data.ack_id_first = RRR_UDPSTREAM_FRAME_PACKED_ACK_FIRST(template);
		result->ack_data.ack_id_last = RRR_UDPSTREAM_FRAME_PACKED_ACK_LAST(template);
	}
	else {
		result->application_data = RRR_UDPSTREAM_FRAME_PACKED_APPLICATION_DATA(template);
	}

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		__rrr_udpstream_frame_destroy(result);
	}
	return ret;
}

static void __rrr_udpstream_frame_buffer_clear(struct rrr_udpstream_frame_buffer *buffer) {
	RRR_LL_DESTROY(buffer, struct rrr_udpstream_frame, __rrr_udpstream_frame_destroy(node));
}

static void __rrr_udpstream_frame_buffer_init(struct rrr_udpstream_frame_buffer *target) {
	memset(target, '\0', sizeof(*target));
	target->frame_id_max = RRR_UDPSTREAM_FRAME_ID_LIMIT;
}

static int __rrr_udpstream_stream_destroy(struct rrr_udpstream_stream *stream) {
	__rrr_udpstream_frame_buffer_clear(&stream->receive_buffer);
	__rrr_udpstream_frame_buffer_clear(&stream->send_buffer);
	RRR_FREE_IF_NOT_NULL(stream->remote_addr);
	rrr_free(stream);
	return 0;
}

static int __rrr_udpstream_stream_new(struct rrr_udpstream_stream **target) {
	*target = NULL;

	struct rrr_udpstream_stream *res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_udpstream_stream_new\n");
		return 1;
	}
	memset(res, '\0', sizeof(*res));

	__rrr_udpstream_frame_buffer_init(&res->receive_buffer);
	__rrr_udpstream_frame_buffer_init(&res->send_buffer);

	res->last_seen = rrr_time_get_64();
	res->window_size_to_remote = RRR_UDPSTREAM_WINDOW_SIZE_INITIAL;
	res->window_size_from_remote = RRR_UDPSTREAM_WINDOW_SIZE_INITIAL;

	*target = res;

	return 0;
}

static void __rrr_udpstream_stream_collection_clear(struct rrr_udpstream_stream_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_udpstream_stream, __rrr_udpstream_stream_destroy(node));
}

static void __rrr_udpstream_stream_collection_init(struct rrr_udpstream_stream_collection *collection) {
	memset (collection, '\0', sizeof(*collection));
}

void rrr_udpstream_set_flags (
		struct rrr_udpstream *data,
		int flags
) {
	data->flags = flags;
}

static void __rrr_udpstream_frame_packed_dump (
		const struct rrr_udpstream_frame_packed *frame
) {
	struct rrr_string_builder string_builder = {0};
	RRR_DBG ("-- UDP-stream packed frame size %llu\n", (unsigned long long) RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame));
	RRR_DBG ("Header CRC32 : %" PRIu32 "\n", RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame));
	RRR_DBG ("Data CRC32   : %" PRIu32 "\n", RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame));
	RRR_DBG ("Total size   : %llu\n", (unsigned long long) RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame));
	RRR_DBG ("Data size    : %u\n", RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame));
	RRR_DBG ("Flags        : %u\n", RRR_UDPSTREAM_FRAME_FLAGS(frame));
	RRR_DBG ("Type         : %u\n", RRR_UDPSTREAM_FRAME_TYPE(frame));
	RRR_DBG ("Version      : %u\n", RRR_UDPSTREAM_FRAME_PACKED_VERSION(frame));
	RRR_DBG ("Stream-ID    : %u\n", RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(frame));
	RRR_DBG ("Frame-ID     : %u\n", RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(frame));

	unsigned char *data = (unsigned char *) frame;

	rrr_string_builder_append(&string_builder, "-- 0x");
	for (size_t i = 0; i < RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame); i++) {
		if (i == sizeof(*frame)) {
			rrr_string_builder_append(&string_builder, " -- ");
		}
		rrr_string_builder_append_format(&string_builder, "%02x", *(data + i));
	}
	rrr_string_builder_append(&string_builder, "\n------------\n");
	RRR_DBG("%s", rrr_string_builder_buf(&string_builder));
	rrr_string_builder_clear(&string_builder);
}

static int __rrr_udpstream_checksum_and_send_packed_frame (
		struct rrr_udpstream *udpstream_data,
		const struct sockaddr *addr,
		socklen_t addrlen,
		const struct rrr_udpstream_frame_packed *frame,
		void *data,
		uint16_t data_size,
		int copies
) {
	int ret = 0;

	if (udpstream_data->send_buffer == NULL) {
		udpstream_data->send_buffer = rrr_allocate(RRR_UDPSTREAM_MESSAGE_SIZE_MAX);
		if (udpstream_data->send_buffer == NULL) {
			RRR_MSG_0("Could not allocate send buffer in __rrr_udpstream_checksum_and_send_packed_frame\n");
			ret = 1;
			goto out;
		}
		udpstream_data->send_buffer_size = RRR_UDPSTREAM_MESSAGE_SIZE_MAX;
	}

	if ((size_t) data_size + sizeof(*frame) - 1 > (size_t) udpstream_data->send_buffer_size) {
		RRR_BUG("data size too big in __rrr_udpstream_checksum_and_send_packed_frame\n");
	}

	if (addr == NULL) {
		RRR_BUG("addr was NULL in __rrr_udpstream_checksum_and_send_packed_frame\n");
	}

	struct rrr_udpstream_frame_packed *frame_new = udpstream_data->send_buffer;

	*frame_new = *frame;

	frame_new->version = RRR_UDPSTREAM_VERSION;

	// A packed frame created locally has the payload stored separately
	if (data_size > 0) {
		frame_new->data_crc32 = rrr_htobe32(rrr_crc32buf((char *) data, data_size));
		frame_new->data_size = rrr_htobe16(data_size);
	}
	else {
		frame_new->data_crc32 = 0;
		frame_new->data_size = 0;
	}

	const char *crc32_start_pos = ((char *) frame_new) + sizeof(frame_new->header_crc32);
	const uint32_t crc32_size = sizeof(*frame_new) - sizeof(frame_new->header_crc32) - 1;

	frame_new->header_crc32 = rrr_htobe32(rrr_crc32buf(crc32_start_pos, crc32_size));

	if (data_size > 0) {
		if (data == NULL) {
			RRR_BUG("BUG: Data was NULL in __rrr_udpstream_checksum_and_send_packed_frame\n");
		}
		memcpy(frame_new->data, data, data_size);
	}
	else {
		frame_new->data[0] = '\0';
	}

	RRR_DBG_3("UDP-stream TX %u-%u CS: %" PRIu32 "/%" PRIu32 " S: %llu F/T: %u CH/ID/WS: %u\n",
			rrr_be16toh(frame_new->stream_id),
			rrr_be32toh(frame_new->frame_id),
			rrr_be32toh(frame_new->header_crc32),
			rrr_be32toh(frame_new->data_crc32),
			(unsigned long long int) rrr_be16toh(frame_new->data_size) + sizeof(*frame) - 1,
			frame_new->flags_and_type,
			rrr_be32toh(frame_new->connect_handle)
	);

	if (RRR_DEBUGLEVEL_6) {
		__rrr_udpstream_frame_packed_dump(frame_new);
	}

	while (copies--) {
#ifdef RRR_UDPSTREAM_PACKET_LOSS_DEBUG_PERCENT
		if (rand() % 100 <= RRR_UDPSTREAM_PACKET_LOSS_DEBUG_PERCENT) {
			RRR_DBG_3("UDP-stream TX forgot to send packet :-(\n");
			continue;
		}
#endif

		rrr_length send_chunk_count_dummy = 0;
		if ((ret = rrr_socket_client_collection_sendto_push_const (
				&send_chunk_count_dummy,
				udpstream_data->clients,
				udpstream_data->ip.fd,
				addr,
				addrlen,
				udpstream_data->send_buffer,
				sizeof(*frame) - 1 + data_size,
				NULL,
				NULL,
				NULL
		)) != 0) {
			RRR_MSG_0("Could not push packed frame in __rrr_udpstream_send_packed_frame, return was %i\n", ret);
			goto out;
		}
	}

	out:
	return ret;
}

static struct rrr_udpstream_stream *__rrr_udpstream_create_and_add_stream (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	struct rrr_udpstream_stream *new_stream = NULL;

	if (__rrr_udpstream_stream_new(&new_stream) != 0) {
		return NULL;
	}

	new_stream->remote_addr_len = addr_len;
	new_stream->remote_addr = rrr_allocate(new_stream->remote_addr_len);
	if (new_stream->remote_addr == NULL) {
		RRR_MSG_0("Could not allocate memory for address in __rrr_udpstream_send_connect\n");
		__rrr_udpstream_stream_destroy(new_stream);
		new_stream = NULL;
		goto out;
	}
	memcpy(new_stream->remote_addr, addr, new_stream->remote_addr_len);

	RRR_LL_UNSHIFT(&data->streams, new_stream);

	out:
	return new_stream;
}

static uint16_t __rrr_udpstream_allocate_stream_id (
		struct rrr_udpstream *data
) {
	uint16_t ret = 0;
	uint16_t stream_id = (uint16_t) rrr_rand();

	for (int retries = 0xffff; retries > 0; retries--) {
		int collission = 0;
		RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
			if (node->stream_id == stream_id) {
				collission = 1;
				RRR_LL_ITERATE_BREAK();
			}
		RRR_LL_ITERATE_END();
		if (collission == 0) {
			ret = stream_id;
			break;
		}

		stream_id++;
	}

	return ret;
}

static int __rrr_udpstream_send_frame_ack (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t ack_id_first,
		uint32_t ack_id_last,
		uint32_t window_size,
		int copies
) {
	struct rrr_udpstream_frame_packed frame = {0};

	RRR_DBG_3("UDP-stream TX ACK %u-%u-%u count %i\n",
			stream_id, ack_id_first, ack_id_last, copies);

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_FRAME_ACK;
	frame.stream_id = rrr_htobe16(stream_id);
	frame.ack_data.ack_id_first = rrr_htobe32(ack_id_first);
	frame.ack_data.ack_id_last = rrr_htobe32(ack_id_last);

	if (window_size != 0) {
		frame.flags_and_type |= (RRR_UDPSTREAM_FRAME_FLAGS_WINDOW_SIZE << 4);
		frame.window_size = rrr_htobe32(window_size);
	}

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, copies);
}

static int __rrr_udpstream_send_reset (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t connect_handle
) {
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_RESET;
	frame.stream_id = rrr_htobe16(stream_id);

	// Reset with connect handle is sent if wish to clean any existing stream on remote
	frame.connect_handle = rrr_htobe32(connect_handle);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, 3);
}

static int __rrr_udpstream_stream_send_reset (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream
) {
	if (stream->remote_addr_len == 0 || stream->stream_id == 0) {
		return 0;
	}

	return __rrr_udpstream_send_reset (data, stream->remote_addr, stream->remote_addr_len, stream->stream_id, stream->connect_handle);
}

static int __rrr_udpstream_send_connect_response (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t connect_handle
) {
	
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_CONNECT;
	frame.stream_id = rrr_htobe16(stream_id);
	frame.connect_handle = rrr_htobe32(connect_handle);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, 3);
}

static int __rrr_udpstream_send_frame (
		struct rrr_udpstream *data,
		const struct rrr_udpstream_stream *stream,
		const struct rrr_udpstream_frame *frame
) {
	struct rrr_udpstream_frame_packed frame_packed = {0};

	frame_packed.frame_id = rrr_htobe32(frame->frame_id);
	frame_packed.flags_and_type = frame->flags_and_type;
	frame_packed.stream_id = rrr_htobe16(stream->stream_id);
	frame_packed.application_data = rrr_htobe64(frame->application_data);

	return __rrr_udpstream_checksum_and_send_packed_frame (
			data,
			stream->remote_addr,
			stream->remote_addr_len,
			&frame_packed,
			frame->data,
			frame->data_size,
			1
	);
}

static int __rrr_udpstream_send_and_update_frame (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *frame
) {
	int ret = 0;

	if ((ret = __rrr_udpstream_send_frame(data, stream, frame)) != 0) {
		RRR_MSG_0("Could not send frame in __rrr_udpstream_send_loop\n");
		goto out;
	}
	frame->unacknowledged_count = 0;
	frame->last_send_time = rrr_time_get_64();

	out:
	return ret;
}

static uint32_t __rrr_udpstream_allocate_connect_handle (
		struct rrr_udpstream *data
) {
	uint32_t ret = (uint32_t) rrr_rand();
	for (int retries = 0xffff; retries > 0; retries--) {
		int collission = 0;
		RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
			if (node->connect_handle == ret) {
				collission = 1;
				RRR_LL_ITERATE_BREAK();
			}
		RRR_LL_ITERATE_END();
		if (collission == 0) {
			return ret;
		}
		ret++;
	}

	return 0;
}

static int __rrr_udpstream_send_connect (
		uint32_t *connect_handle_result,
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	uint32_t connect_handle = 0;

	if ((data->flags & RRR_UDPSTREAM_FLAGS_FIXED_CONNECT_HANDLE) != 0) {
		connect_handle = *connect_handle_result;
		if (connect_handle == 0) {
			RRR_BUG("Zero connect handle to __rrr_udpstream_send_connect with FIXED_CONNECT_HANDLE set\n");
		}
	}
	else {
		*connect_handle_result = 0;
		connect_handle = __rrr_udpstream_allocate_connect_handle(data);
		if (connect_handle == 0) {
			RRR_MSG_0("Could not allocate connect handle in __rrr_udpstream_send_connect\n");
			ret = 1;
			goto out;
		}
	}

	{
		struct rrr_udpstream_frame_packed frame = {0};

		frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_CONNECT;
		frame.connect_handle = rrr_htobe32(connect_handle);

		struct rrr_udpstream_stream *stream = NULL;
		if ((stream = __rrr_udpstream_create_and_add_stream(data, addr, addr_len)) == NULL) {
			RRR_MSG_0("Could not add stream to collection in __rrr_udpstream_send_connect\n");
			ret = 1;
			goto out;
		}

		stream->connect_handle = connect_handle;

		if (__rrr_udpstream_checksum_and_send_packed_frame(data, stream->remote_addr, stream->remote_addr_len, &frame, NULL, 0, 3) != 0) {
			RRR_MSG_0("Could not send CONNECT packet in __rrr_udpstream_send_connect\n");
			ret = 1;
			goto out;
		}
	}

	*connect_handle_result = connect_handle;

	out:
	return ret;
}

static void __rrr_udpstream_fd_close_callback (
		int fd,
		const struct sockaddr *addr,
		socklen_t socklen,
		const char *addr_string,
		enum rrr_socket_client_collection_create_type create_type,
		short was_finalized,
		void *arg
) {
	struct rrr_udpstream *data = arg;

	(void)(addr);
	(void)(socklen);
	(void)(addr_string);
	(void)(create_type);
	(void)(was_finalized);

	if (fd != data->ip.fd) {
		RRR_MSG_0("Warning: FD mismatch actual %i vs expected %i in __rrr_udpstream_fd_close_callback\n", fd, data->ip.fd);
		return;
	}

	// Client collection has closed the FD
	rrr_ip_network_reset_hard(&data->ip);
}

static int __rrr_udpstream_frame_packed_validate (
		const struct rrr_udpstream_frame_packed *frame
) {
	uint32_t header_crc32 = RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame);

	const char *crc32_start_pos = ((char *) frame) + sizeof(frame->header_crc32);
	const uint32_t crc32_size = sizeof(*frame) - sizeof(frame->header_crc32) - 1;

	if (rrr_crc32cmp(crc32_start_pos, crc32_size, header_crc32) != 0) {
		RRR_MSG_0("Header CRC32 mismatch in __rrr_udpstream_frame_pack_validate\n");
		if (RRR_DEBUGLEVEL_2) {
			__rrr_udpstream_frame_packed_dump(frame);
		}
		return 1;
	}

	return 0;
}

static int __rrr_udpstream_read_get_target_size (
		RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS
) {
	int ret = RRR_SOCKET_OK;

	(void)(arg);
	(void)(addr);
	(void)(addr_len);
	(void)(private_data);

	struct rrr_udpstream_frame_packed *frame = (struct rrr_udpstream_frame_packed *) read_session->rx_buf_ptr;

	if (read_session->rx_buf_wpos < (ssize_t) sizeof (struct rrr_udpstream_frame_packed) - 1) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
		goto out;
	}

	if (__rrr_udpstream_frame_packed_validate(frame) != 0) {
		RRR_MSG_0("Could not validate received frame in __rrr_udpstream_read_get_target_size\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	rrr_biglength total_size = RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame);

	if (RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame) > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) {
		RRR_MSG_0("UDP-stream received data size exceeded maximum (%" PRIrrrbl " > %i)\n",
			total_size, RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session->target_size = total_size;

	out:
	return ret;
}

static void __rrr_udpstream_read_get_target_size_error (
		RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS
) {
	(void)(read_session);
	(void)(is_hard_err);
	(void)(addr);
	(void)(addr_len);
	(void)(arg);
	(void)(private_data);

	// Any error message goes here
}

static void __rrr_udpstream_set_read_flags_callback (RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS) {
	(void)(arg);
	(void)(socket_read_flags);
	(void)(private_data);

	// Don't close socket upon parse errors
	*do_soft_error_propagates = 0;
}

static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_connect_handle (
		struct rrr_udpstream *data,
		uint32_t connect_handle
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_connect_handle_stream_id_and_addr (
		struct rrr_udpstream *data,
		uint32_t connect_handle,
		uint16_t stream_id,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle &&
			node->remote_addr_len == addr_len &&
			memcmp(node->remote_addr, addr, addr_len) == 0 &&
			node->stream_id == stream_id
		) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_stream_id (
		struct rrr_udpstream *data,
		uint16_t stream_id
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->stream_id == stream_id) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static void __rrr_udpstream_find_and_destroy_stream_by_stream_id (
	struct rrr_udpstream *data,
	uint32_t stream_id
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->stream_id == stream_id) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));
}

static void __rrr_udpstream_find_and_destroy_stream_by_connect_handle (
	struct rrr_udpstream *data,
	uint32_t connect_handle
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));
}

static void __rrr_udpstream_find_and_destroy_stream (
	struct rrr_udpstream *data,
	uint32_t connect_handle,
	uint32_t stream_id
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle && node->stream_id == stream_id) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));
}

static int __rrr_udpstream_update_stream_remote (
		struct rrr_udpstream_stream *stream,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	if (stream->remote_addr == NULL || stream->remote_addr_len != addr_len || memcmp(stream->remote_addr, addr, addr_len) != 0) {
		if (stream->remote_addr_len != addr_len || stream->remote_addr == NULL) {
			RRR_FREE_IF_NOT_NULL(stream->remote_addr);
			if ((stream->remote_addr = rrr_allocate(sizeof(*(stream->remote_addr)))) == NULL) {
				RRR_MSG_0("Could not allocate memory in __rrr_udpstream_update_stream_remote\n");
				ret = 1;
				goto out;
			}
		}
		memcpy(stream->remote_addr, addr, addr_len);
	}

	out:
	return ret;
}

static int __rrr_udpstream_handle_received_connect (
		struct rrr_udpstream *data,
		struct rrr_udpstream_frame *frame,
		const struct sockaddr *src_addr,
		socklen_t addr_len
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = NULL;

	if (frame->data_size != 0) {
		RRR_DBG_3("UDP-stream received CONNECT packet with non-zero payload, dropping it\n");
		goto out;
	}

	stream = __rrr_udpstream_find_stream_by_connect_handle_stream_id_and_addr (data, frame->connect_handle, frame->stream_id, src_addr, addr_len);
	if (stream != NULL && frame->stream_id != 0) {
		// Already connected
		RRR_DBG_3("UDP-stream incoming duplicate CONNECT (response or old unknown stream) stream_id local %" PRIu32 " stream id remote %" PRIu32 "\n",
				stream->stream_id,
				frame->stream_id
		);
		if (stream->stream_id != frame->stream_id) {
			if ((ret = __rrr_udpstream_send_reset(data, src_addr, addr_len, frame->stream_id, frame->connect_handle)) != 0) {
				RRR_MSG_0("Failed to send RST in __rrr_udpstream_handle_received_connect\n");
				goto out;
			}
		}
		goto out;
	}

	stream = __rrr_udpstream_find_stream_by_connect_handle_stream_id_and_addr (data, frame->connect_handle, 0, src_addr, addr_len);
	if (stream != NULL && frame->stream_id != 0) {
		// We are expecting CONNECT response
		if (stream->remote_addr_len != addr_len || memcmp(stream->remote_addr, src_addr, addr_len) != 0) {
			RRR_MSG_0("Received CONNECT response from unexpected remote host\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		if (frame->stream_id == 0) {
			RRR_MSG_0("Received zero stream ID in CONNECT response in __rrr_udpstream_handle_received_connect, connection was rejected\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		struct rrr_udpstream_stream *stream_test = __rrr_udpstream_find_stream_by_stream_id(data, frame->stream_id);
		if (stream_test != NULL) {
			RRR_DBG_3("UDP-stream stream ID collision for connect with handle %u, connection must be closed\n", frame->connect_handle);
			__rrr_udpstream_find_and_destroy_stream_by_connect_handle(data, frame->connect_handle);
			goto out;
		}

		stream->stream_id = frame->stream_id;

		RRR_DBG_3("UDP-stream outbound connection established with stream id %u connect handle was %u\n",
				stream->stream_id, frame->connect_handle);
		goto out;
	}
	else if (stream == NULL && frame->stream_id == 0) {
		// Connect request
		uint16_t stream_id = 0;

		if ((data->flags & RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS) == 0) {
			RRR_MSG_0("Received CONNECT packet with handle %u in __rrr_udpstream_handle_received_connect, but we are neither expecting CONNECT response nor accepting connections\n",
					RRR_UDPSTREAM_FRAME_PACKED_CONNECT_HANDLE(frame));
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		// If stream id is zero, we cannot accept more connections and the connection is rejected
		stream_id = __rrr_udpstream_allocate_stream_id(data);
		if (stream_id > 0) {
			if ((stream = __rrr_udpstream_create_and_add_stream(data, src_addr, addr_len)) == NULL) {
				RRR_MSG_0("Could not push new connection to buffer collections in __rrr_udpstream_handle_received_connect\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}

			// We do not store the address of the remote client. The receive function callback
			// receives the currently used sender address for every message.
			stream->stream_id = stream_id;
			stream->connect_handle = frame->connect_handle;

			RRR_DBG_3("UDP-stream incoming connection established with stream id %u connect handle %u\n",
					stream_id, stream->connect_handle);
		}
		else {
			// This is not considered an error
			RRR_DBG_3("UDP-stream incoming connection rejected\n");
			goto send_response;
		}

		send_response:
		RRR_DBG_3("UDP-stream sending CONNECT response stream id %u connect handle %u address length %u\n",
				stream_id, (stream != NULL ? stream->connect_handle : 0), addr_len);

		if (__rrr_udpstream_send_connect_response(data, src_addr, addr_len, stream_id, frame->connect_handle) != 0) {
			RRR_MSG_0("Could not send connect response in __rrr_udpstream_handle_received_connect\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
	}
	else {
		RRR_DBG_3("UDP-stream unhandled CONNECT stream id %u connect handle %u\n",
				frame->stream_id, frame->connect_handle);
		if ((ret = __rrr_udpstream_send_reset(data, src_addr, addr_len, frame->stream_id, frame->connect_handle)) != 0) {
			RRR_MSG_0("Failed to send reset in __rrr_udpstream_handle_received_connect\n");
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_udpstream_handle_received_frame_ack (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame
) {
	int ret = 0;

	int64_t nag_id = -1;

	if (new_frame->ack_data.ack_id_first == new_frame->ack_data.ack_id_last) {
		if (new_frame->ack_data.ack_id_last == stream->last_ack_id) {
			nag_id = stream->last_ack_id;
		}
		else {
			stream->last_ack_id = new_frame->ack_data.ack_id_last;
		}
	}

	RRR_DBG_3("UDP-stream RX ACK %u-%u-%u%s\n",
			new_frame->stream_id,
			new_frame->ack_data.ack_id_first,
			new_frame->ack_data.ack_id_last,
			nag_id > 0 ? " (nagging)" : ""
	);

	RRR_LL_ITERATE_BEGIN(&stream->send_buffer, struct rrr_udpstream_frame);
		if (node->frame_id >= new_frame->ack_data.ack_id_first && node->frame_id <= new_frame->ack_data.ack_id_last) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->frame_id == nag_id + 1) {
			if ((ret = __rrr_udpstream_send_and_update_frame(data, stream, node)) != 0) {
				RRR_MSG_0("Could not send dup frame in __rrr_udpstream_handle_received_frame_ack\n");
				goto out;
			}
		}
		else {
			node->unacknowledged_count++;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->send_buffer, __rrr_udpstream_frame_destroy(node));

	out:
	return ret;
}

static int __rrr_udpstream_handle_received_frame_control (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame
) {
	int ret = 0;

	RRR_DBG_3("UDP-stream RX CTRL %u-%" PRIu64 "\n",
		new_frame->stream_id, new_frame->application_data);

	if ((ret = data->upstream_control_frame_callback (
			stream->connect_handle,
			new_frame->application_data,
			data->upstream_control_frame_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from control frame listener in __rrr_udpstream_handle_received_frame_control\n");
		goto out;
	}

	out:
	return ret;
}

static int __rrr_udpstream_regulate_window_size (
		struct rrr_udpstream_stream *stream,
		int window_size_adjust
) {
	int64_t tmp = (int64_t) stream->window_size_to_remote + window_size_adjust;

	if (tmp < RRR_UDPSTREAM_WINDOW_SIZE_MIN) {
		tmp = RRR_UDPSTREAM_WINDOW_SIZE_MIN;
	}
	if (tmp > RRR_UDPSTREAM_WINDOW_SIZE_MAX) {
		tmp = RRR_UDPSTREAM_WINDOW_SIZE_MAX;
	}

	stream->window_size_to_remote = (uint32_t) tmp;

	return 0;
}

static int __rrr_udpstream_handle_received_frame (
		struct rrr_udpstream *data,
		const struct rrr_udpstream_frame_packed *frame,
		const struct sockaddr *src_addr,
		socklen_t addr_len
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream_frame *new_frame = NULL;
	struct rrr_udpstream_stream *stream = NULL;

	if (__rrr_udpstream_frame_new_from_packed(&new_frame, frame, src_addr, addr_len) != 0) {
		RRR_MSG_0("Could not allocate internal frame in __rrr_udpstream_handle_received_frame\n");
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	if (new_frame->version < RRR_UDPSTREAM_VERSION_MINIMUM) {
		RRR_DBG_3("UDP-stream received frame with unsupported version %u, minimum version is %u\n",
			frame->version, RRR_UDPSTREAM_VERSION_MINIMUM);
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_CONNECT(new_frame)) {
		ret = __rrr_udpstream_handle_received_connect(data, new_frame, src_addr, addr_len);
		goto out;
	}

	if (new_frame->stream_id != 0) {
		stream = __rrr_udpstream_find_stream_by_stream_id(data, new_frame->stream_id);
	}
	else if (new_frame->connect_handle != 0) {
		stream = __rrr_udpstream_find_stream_by_connect_handle(data, new_frame->connect_handle);
	}
	else {
		RRR_DBG_1("Received UDP-stream packet with zero stream ID and zero connect ID, dropping it\n");
		goto out;
	}

	if (stream == NULL) {
		// Check that unknown packet is not a reset, if not we would keep sending resets back and forward
		if (!RRR_UDPSTREAM_FRAME_IS_RESET(new_frame)) {
			RRR_DBG_3("UDP-stream received packet with unknown stream ID %u, sending reset\n", new_frame->stream_id);
			if (__rrr_udpstream_send_reset(data, src_addr, addr_len, new_frame->stream_id, 0) != 0) {
				RRR_MSG_0("Could not send UDP-stream hard reset in __rrr_udpstream_handle_received_frame\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}
		}
		goto out;
	}

	if ((data->flags & RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP) != 0) {
		if (stream->remote_addr_len != addr_len || memcmp(stream->remote_addr, src_addr, addr_len) != 0) {
			RRR_DBG_1("Remote IP mismatch in received packet for connect handle %u, dropping packet\n", stream->connect_handle);
			goto out;
		}
	}
	else {
		if ((ret = __rrr_udpstream_update_stream_remote(stream, src_addr, addr_len)) != 0) {
			RRR_MSG_0("Could not update remote stream address in __rrr_udpstream_handle_received_frame\n");
			goto out;
		}
	}

	if (RRR_UDPSTREAM_FRAME_IS_RESET(new_frame)) {
		if (new_frame->stream_id == 0 && new_frame->connect_handle != 0) {
			// Reset before connect packet, all streams with matchin connect handle is destroyed
			RRR_DBG_3("UDP-stream RX RST connect handle %" PRIu32 "\n",
					new_frame->connect_handle);
			__rrr_udpstream_find_and_destroy_stream_by_connect_handle (data, new_frame->connect_handle);
		}
		if (new_frame->stream_id != 0 && new_frame->connect_handle == 0) {
			RRR_DBG_3("UDP-stream RX RST stream ID %" PRIu16 "\n",
					new_frame->stream_id);
			__rrr_udpstream_find_and_destroy_stream_by_stream_id (data, new_frame->stream_id);
		}
		else {
			// Reset with both IDs
			RRR_DBG_3("UDP-stream RX RST connect handle %" PRIu32 " stream id %" PRIu16 "\n",
				stream->connect_handle, stream->stream_id);
			__rrr_udpstream_find_and_destroy_stream (data, new_frame->connect_handle, new_frame->stream_id);
		}
		goto out;
	}

	if (new_frame->stream_id == 0) {
		RRR_DBG_3("UDP-stream unknown packet with type/flags %u and zero stream id\n",
				new_frame->flags_and_type);
		goto out;
	}

	stream->last_seen = rrr_time_get_64();

	if (RRR_UDPSTREAM_FRAME_HAS_WINDOW_SIZE(frame)) {
		stream->window_size_from_remote = new_frame->window_size;

		__rrr_udpstream_regulate_window_size(stream, 0); // Just to fix MIN/MAX

		RRR_DBG_3("UDP-stream RX WS %u-%" PRIu32 "\n",
				new_frame->stream_id, stream->window_size_from_remote);
	}

	if (RRR_UDPSTREAM_FRAME_IS_FRAME_ACK(frame)) {
		ret = __rrr_udpstream_handle_received_frame_ack(data, stream, new_frame);
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_CONTROL(frame)) {
		ret = __rrr_udpstream_handle_received_frame_control (
				data,
				stream,
				new_frame
		);
		goto out;
	}

	if (new_frame->frame_id == 0) {
		RRR_DBG_3("UDP-stream received data frame with flags %u and zero frame id\n",
				new_frame->flags_and_type);
		goto out;
	}

	if (stream->receive_buffer.frame_id_counter == 0 && new_frame->frame_id != 1) {
		// First frame must be ID 1, this to be able to filter out "old data" from lost streams
		// which might be retained if we are offline for a bit. If this happens, we must also
		// reset the whole stream and the sender must connect again and obtain a new ID.

		RRR_DBG_3("udpstream id %u dropping frame ID %u as we expect first frame id 1\n",
				new_frame->stream_id, new_frame->frame_id);

		if (__rrr_udpstream_send_reset(data, src_addr, addr_len, new_frame->stream_id, new_frame->connect_handle) != 0) {
			RRR_MSG_0("Could not send UDP-stream reset in __rrr_udpstream_handle_received_frame\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		__rrr_udpstream_find_and_destroy_stream_by_stream_id (data, new_frame->stream_id);

		goto out;
	}

	if (new_frame->frame_id == stream->receive_buffer.frame_id_counter + 1) {
		stream->receive_buffer.frame_id_counter++;
	}

	if (RRR_LL_LAST(&stream->receive_buffer) != NULL && new_frame->frame_id > RRR_LL_LAST(&stream->receive_buffer)->frame_id) {
		goto out_append;
	}

	uint32_t frame_id_max = 0;
	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		if (node->frame_id == new_frame->frame_id) {
			// Already received
			goto out;
		}
		if (new_frame->frame_id < node->frame_id) {
			RRR_LL_ITERATE_INSERT(&stream->receive_buffer, new_frame);
			new_frame = NULL;
			goto out;
		}
		if (node->frame_id < frame_id_max) {
			RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
				RRR_MSG_0("udpstream stream-id %u frame id %u dump recv buffer\n",
						stream->stream_id, node->frame_id);
			RRR_LL_ITERATE_END();
			RRR_BUG("Order error in receive buffer in __rrr_udpstream_handle_received_frame\n");
		}
		frame_id_max = node->frame_id;
	RRR_LL_ITERATE_END();

	out_append:
		RRR_LL_APPEND(&stream->receive_buffer, new_frame);
		new_frame = NULL;

	out:
		if (stream != NULL && RRR_LL_COUNT(&stream->receive_buffer) > 0 && !EVENT_PENDING(data->event_deliver)) {
			EVENT_ADD(data->event_deliver);
		}
		EVENT_ACTIVATE(data->event_deliver);
		if (new_frame != NULL) {
			__rrr_udpstream_frame_destroy(new_frame);
		}
		return ret;
}

static int __rrr_udpstream_read_callback (
		RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream *data = arg;
	struct rrr_udpstream_frame_packed *frame = (struct rrr_udpstream_frame_packed *) read_session->rx_buf_ptr;

	(void)(private_data);

	RRR_DBG_3("UDP-stream RX %u-%u CS: %" PRIu32 "/%" PRIu32 " S: %llu F/T: %u CH/ID/WS: %u\n",
			rrr_be16toh(frame->stream_id),
			rrr_be32toh(frame->frame_id),
			rrr_be32toh(frame->header_crc32),
			rrr_be32toh(frame->data_crc32),
			(unsigned long long int) rrr_be16toh(frame->data_size) + sizeof(*frame) - 1,
			frame->flags_and_type,
			rrr_be32toh(frame->connect_handle)
	);

	if (RRR_DEBUGLEVEL_6) {
		__rrr_udpstream_frame_packed_dump(frame);
	}

	if (read_session->rx_buf_wpos != RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame)) {
		RRR_MSG_0("Size mismatch in __rrr_udpstream_read_callback, packet was invalid\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	const rrr_biglength data_size = RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame);
	if (data_size > 0) {
		if (rrr_crc32cmp (frame->data, data_size, RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame)) != 0) {
			RRR_MSG_0("Data CRC32 mismatch for data in __rrr_udpstream_read_callback\n");
			if (RRR_DEBUGLEVEL_2) {
				__rrr_udpstream_frame_packed_dump(frame);
			}
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
	}

	if ((ret = __rrr_udpstream_handle_received_frame (
			data,
			frame,
			addr,
			addr_len
	)) != 0) {
		RRR_MSG_0("Error while pushing received frame to buffer in __rrr_udpstream_read_callback\n");
		goto out;
	}

	out:
	rrr_free(read_session->rx_buf_ptr);
	read_session->rx_buf_ptr = NULL;
	// This return value causes bugtrap in read framework. Application
	// should check for connection problems with the connection check
	// function regularly to catch errors.
	ret &= ~(RRR_UDPSTREAM_NOT_READY);
	return ret;
}

struct ack_list_node {
	RRR_LL_NODE(struct ack_list_node);
	uint32_t frame_id_from;
	uint32_t frame_id_to;
	const struct rrr_udpstream_frame *last_frame;
};

struct ack_list {
	RRR_LL_HEAD(struct ack_list_node);
};

struct rrr_udpstream_process_receive_buffer_callback_data {
	struct rrr_udpstream *data;
	struct rrr_udpstream_stream *stream;

	uint32_t accumulated_data_size;
	struct rrr_udpstream_frame *first_deliver_node;
	struct rrr_udpstream_frame *last_deliver_node;
};

static int __rrr_udpstream_process_receive_buffer_callback (
		void **joined_data,
		void *allocation_handle,
		void *arg
) {
	void *write_pos = *joined_data;
	struct rrr_udpstream_process_receive_buffer_callback_data *callback_data = arg;
	struct rrr_udpstream *data = callback_data->data;

	int ret = 0;

	// Read from the first undelivered node up to boundary to get a full original message
	RRR_LL_ITERATE_BEGIN_AT(&stream->receive_buffer, struct rrr_udpstream_frame, callback_data->first_deliver_node, 0);
		if (node->data != NULL && node->data_size > 0) {
			memcpy (write_pos, node->data, node->data_size);
			write_pos += node->data_size;
		}

		if (node == callback_data->last_deliver_node) {
			RRR_LL_ITERATE_LAST();

			RRR_DBG_3("UDP-stream DELIVER %u-%u %" PRIu64 "\n",
					callback_data->stream->stream_id, node->frame_id, node->application_data);

			if ((size_t) write_pos - (size_t) *joined_data != callback_data->accumulated_data_size) {
				RRR_BUG("Joined data size mismatch in __rrr_udpstream_process_receive_buffer\n");
			}

			if (data->upstream_validator_callback) {
				rrr_biglength target_size = 0;

				if ((ret = data->upstream_validator_callback (
						&target_size,
						*joined_data,
						callback_data->accumulated_data_size,
						data->upstream_allocator_callback_arg
				)) != 0) {
					RRR_MSG_0("Header validation failed of message in UDP-stream %u, data will be lost\n",
							callback_data->stream->stream_id);
					ret = 0;
					goto loop_bottom_clenaup;
				}

				if (target_size != callback_data->accumulated_data_size) {
					RRR_MSG_0("Stream error or size mismatch of received packed in UDP-stream %u, data will be lost\n",
							callback_data->stream->stream_id);
					goto loop_bottom_clenaup;
				}
			}

			struct rrr_udpstream_receive_data receive_callback_data = {
					allocation_handle,
					callback_data->accumulated_data_size,
					callback_data->stream->connect_handle,
					callback_data->stream->stream_id,
					node->application_data,
					node->source_addr,
					node->source_addr_len
			};

			// This function must always take care of or free memory in callback_data->data
			if (data->upstream_final_callback (joined_data, &receive_callback_data, data->upstream_final_callback_arg) != 0) {
				RRR_MSG_0("Error from callback in __rrr_udpstream_process_receive_buffer, data might have been lost\n");
				ret = 1;
				goto out;
			}

			loop_bottom_clenaup:
			callback_data->accumulated_data_size = 0;
			callback_data->first_deliver_node = NULL;
		}

		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&callback_data->stream->receive_buffer, __rrr_udpstream_frame_destroy(node));

	out:
	return ret;
}
/* Not currently used. ASD framework has allocator function.
int rrr_udpstream_default_allocator (
		uint32_t size,
		int (*callback)(void **joined_data, void *allocation_handle, void *udpstream_callback_arg),
		void *udpstream_callback_arg,
		void *arg
) {
	(void)(arg);

	int ret = 0;

	void *joined_data = NULL;

	if ((joined_data = malloc(size)) == NULL) {
		RRR_MSG_0("Could not allocate memory for joined data in __rrr_udpstream_process_receive_buffer\n");
		ret = 1;
		goto out;
	}

	ret = callback(&joined_data, NULL, udpstream_callback_arg);

	if (*joined_data != NULL) {
		free(*joined_data);
	}

	out:
	return ret;
}
*/
static int __rrr_udpstream_process_receive_buffer (
		int *receive_complete,
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream
) {
	int ret = 0;

	struct ack_list ack_list = {0};

	uint32_t last_ack_id = 0;
	uint32_t first_ack_id = 0;

	uint32_t accumulated_data_size = 0;
	uint32_t accumulated_frame_count = 0;
	struct rrr_udpstream_frame *first_deliver_node = NULL;
	struct rrr_udpstream_frame *last_deliver_node = NULL;

	int window_size_adjust = 0;

	window_size_adjust += stream->window_size_regulation_from_application;
	stream->window_size_regulation_from_application = 0;

	/*
	 * Whenever this function is called, ACKs will be generated for frames currently in the buffer.
	 * This will cause duplicate ACKs to be sent repeatedly if there are any holes which cause the
	 * deliver loop not to deliver and destroy frames. Duplicate ACKs in turn cause missing data to
	 * be re-sent.
	 */
	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		uint32_t ack_id_from_tmp = 0;
		uint32_t ack_id_to_tmp = 0;
		struct ack_list_node *ack_node = NULL;

		if (first_ack_id == 0) {
			first_ack_id = node->frame_id;
			if ( stream->receive_buffer.frame_id_prev_boundary_pos != 0 &&
			     node->frame_id > stream->receive_buffer.frame_id_prev_boundary_pos &&
			     node->frame_id - stream->receive_buffer.frame_id_prev_boundary_pos > 1
			) {
				// Some frames are missing out, send ACK of last delivered frame
				ack_id_from_tmp = stream->receive_buffer.frame_id_prev_boundary_pos;
				ack_id_to_tmp = stream->receive_buffer.frame_id_prev_boundary_pos;

				RRR_DBG_3("UDP-stream TX ACK %u-%u-%u (%u is first after hole A)\n",
						stream->stream_id, ack_id_from_tmp, ack_id_to_tmp, node->frame_id);

				window_size_adjust -= 2;

				goto add_ack;
			}
		}

		if ( last_ack_id != 0 &&
		     node->frame_id > last_ack_id &&
		     node->frame_id - last_ack_id > 1
		) {
			ack_id_from_tmp = first_ack_id;
			ack_id_to_tmp = last_ack_id;

			RRR_DBG_3("UDP-stream TX ACK %u-%u-%u (%u is first after hole B)\n",
					stream->stream_id, ack_id_from_tmp, ack_id_to_tmp, node->frame_id);

			first_ack_id = node->frame_id;

			window_size_adjust -= 2;

			goto add_ack;
		}

		if (RRR_LL_LAST(&stream->receive_buffer) == node) {
			ack_id_from_tmp = first_ack_id;
			ack_id_to_tmp = node->frame_id;

			window_size_adjust += 1;

			// It is a fairly common situation that the last frame in the buffer is not a boundary.
			// Prevent unnecessary ACKs to be sent with a grace function.
			if (--(node->ack_grace) <= 0) {
				node->ack_grace = 50;
				RRR_DBG_3("UDP-stream TX ACK %u-%u-%u (%u is last in buffer)\n",
						stream->stream_id, ack_id_from_tmp, ack_id_to_tmp, node->frame_id);
				goto add_ack;
			}
		}

		goto no_add_ack;
		add_ack:
			ack_node = rrr_allocate(sizeof(*ack_node));
			if (ack_node == NULL) {
				RRR_MSG_0("Could not allocate ACK node in __rrr_udpstream_process_receive_buffer\n");
				ret = 1;
				goto out;
			}
			ack_node->frame_id_from = ack_id_from_tmp;
			ack_node->frame_id_to = ack_id_to_tmp;
			ack_node->last_frame = node;
			RRR_LL_APPEND(&ack_list, ack_node);
			ack_node = NULL;
		no_add_ack:
			last_ack_id = node->frame_id;
	RRR_LL_ITERATE_END();

	/*
	 * Send ACKs pushed to list in previous loop
	 */
	RRR_LL_ITERATE_BEGIN(&ack_list, struct ack_list_node);
		const struct sockaddr *use_addr = stream->remote_addr;
		socklen_t use_sockaddr_len = stream->remote_addr_len;

		// XXX : Do we need this NULL check? All frames should have a remote address set

		if (use_addr == NULL) {
			use_addr = node->last_frame->source_addr;
			use_sockaddr_len = node->last_frame->source_addr_len;
		}

		__rrr_udpstream_regulate_window_size(stream, window_size_adjust);

		if (__rrr_udpstream_send_frame_ack (
				data,
				use_addr,
				use_sockaddr_len,
				stream->stream_id,
				node->frame_id_from,
				node->frame_id_to,
				(window_size_adjust != 0 ? stream->window_size_to_remote : 0),
				1
		) != 0) {
			RRR_MSG_0("Error while sending UDP-stream ACK in __rrr_udpstream_process_receive_buffer\n");
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	/*
	 * Iterate receive buffer, deliver messages in sequence and destroy delivered frames
	 */

	deliver_again:

	if (!data->upstream_final_receive_possible_callback(data->upstream_final_receive_possible_callback_arg)) {
		goto out;
	}

	accumulated_data_size = 0;
	accumulated_frame_count = 0;
	first_deliver_node = NULL;
	last_deliver_node = NULL;

	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		if (node->frame_id > stream->receive_buffer.frame_id_prev_boundary_pos) {
			if (node->frame_id - stream->receive_buffer.frame_id_prev_boundary_pos > 1 + accumulated_frame_count) {
				RRR_DBG_3("UDP-stream stream-id %u frame-id %u hole in the buffer detected, cannot deliver frames yet\n",
						stream->stream_id, node->frame_id);
				// Hole in the buffer
				RRR_LL_ITERATE_BREAK();
			}
		}
		else {
			if (accumulated_data_size != 0) {
				RRR_BUG("Data accumulation started with already delivered frames in __rrr_udpstream_process_receive_buffer\n");
			}
			RRR_DBG_3("udpstream stream-id %u frame-id %u set destroy as already delivered\n",
					stream->stream_id, node->frame_id);
			// Already delivered
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_NEXT();
		}

		if (first_deliver_node == NULL) {
			first_deliver_node = node;
		}

		accumulated_frame_count += 1;
		accumulated_data_size += node->data_size;

		if (RRR_UDPSTREAM_FRAME_IS_BOUNDARY(node)) {
			last_deliver_node = node;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->receive_buffer, __rrr_udpstream_frame_destroy(node));

	if (last_deliver_node == NULL || first_deliver_node == NULL) {
		goto out;
	}

	/*
	 * Deliver message if boundary was found
	 */

	if (first_deliver_node != RRR_LL_FIRST(&stream->receive_buffer)) {
		RRR_BUG("First delivery node was not first in buffer in __rrr_udpstream_process_receive_buffer\n");
	}

	stream->receive_buffer.frame_id_prev_boundary_pos = last_deliver_node->frame_id;

	struct rrr_udpstream_process_receive_buffer_callback_data callback_data = {
			data,
			stream,
			accumulated_data_size,
			first_deliver_node,
			last_deliver_node
	};

	if ((ret = data->upstream_allocator_callback (
			accumulated_data_size,
			stream->remote_addr,
			stream->remote_addr_len,
			__rrr_udpstream_process_receive_buffer_callback,
			&callback_data,
			data->upstream_allocator_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from allocator in __rrr_udpstream_process_receive_buffer\n");
		goto out;
	}

	goto deliver_again;

	out:
	RRR_LL_DESTROY(&ack_list, struct ack_list_node, rrr_free(node));
	*receive_complete = RRR_LL_COUNT(&stream->receive_buffer) == 0;
	return ret;
}

// This function will merge received frames back into the original messages. If the messages
// themselves contain length information and CRC32, this should be checked in the
// callback_validator-function. A length MUST be returned from this function. If it is not
// possible to extract the message length from the data, a dummy function may be provided
// which simply writes the data_size parameter into target_size.
//
// The callback function receives the actual message. It MUST ALWAYS take care of the memory
// in the data pointer of the receive_data struct, also if there are errors. The actual struct
// must not be freed, it is allocated on the stack.
//
// ACK messages are also sent from this function and window size regulation is performed.
static int __rrr_udpstream_process_receive_buffers (
		int *receive_complete,
		struct rrr_udpstream *data
) {
	int ret = 0;

	*receive_complete = 1;

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		int receive_complete_tmp = 1;
		if ((ret = __rrr_udpstream_process_receive_buffer (
				&receive_complete_tmp,
				data,
				node
		)) != 0) {
			RRR_MSG_0("Destroying UDP-stream with ID %u following error condition\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
			ret = 0;
		}
		if (!receive_complete_tmp) {
			*receive_complete = 0;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));

	return ret;
}

static int __rrr_udpstream_maintain (
		struct rrr_udpstream *data
) {
	int ret = 0;

	uint64_t time_now = rrr_time_get_64();

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		uint64_t diff = time_now - node->last_seen;

		if (diff > RRR_UDPSTREAM_CONNECTION_TIMEOUT_MS * 1000) {
			RRR_DBG_3("UDP-stream connection with connect handle %" PRIu32 " stream ID %" PRIu16 " timed out, removing.\n",
					node->connect_handle, node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
		}

		if (node->destroy_on_empty_buffers) {
			if (RRR_LL_COUNT(&node->send_buffer) == 0 && RRR_LL_COUNT(&node->receive_buffer) == 0) {
				RRR_DBG_3("UDP-stream connection with connect handle %" PRIu32 " stream ID %" PRIu16 " scheduled destroy and buffers are not empty, removing.\n",
						node->connect_handle, node->stream_id);

				RRR_LL_ITERATE_SET_DESTROY();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, 0; __rrr_udpstream_stream_send_reset(data, node); __rrr_udpstream_stream_destroy(node));

	return ret;
}

static int __rrr_udpstream_send_loop (
		int *sending_complete,
		int *sent_count_return,
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream
) {
	uint64_t time_now = rrr_time_get_64();

	*sent_count_return = 0;
	*sending_complete = 1;

	int ret = 0;

	int sent_count = 0;
	int64_t missing_ack_count = 0;
	RRR_LL_ITERATE_BEGIN(&stream->send_buffer, struct rrr_udpstream_frame);
		int do_send = 0;

		if (node->frame_id == 0) {
			RRR_BUG("Frame ID was 0 in __rrr_udpstream_send_loop\n");
		}

		if (node->last_send_time == 0) {
			if (++missing_ack_count < stream->window_size_from_remote) {
				do_send = 1;
				RRR_DBG_3("UDP-stream TX %u-%u WS %" PRIu32 " UNACK %i\n",
						stream->stream_id, node->frame_id, stream->window_size_from_remote, node->unacknowledged_count);
			}
		}
		else if (time_now - node->last_send_time > RRR_UDPSTREAM_RESEND_INTERVAL_FRAME_MS * 1000 ||
				node->unacknowledged_count >= RRR_UDPSTREAM_RESEND_UNACKNOWLEDGED_LIMIT
		) {
			RRR_DBG_3("UDP-stream TX %u-%u DUP WS %" PRIu32 " UNACK %i\n",
					stream->stream_id, node->frame_id, stream->window_size_from_remote, node->unacknowledged_count);
			do_send = 1;
		}
		else {
			missing_ack_count++;
		}

		if (do_send != 0) {
			if ((ret = __rrr_udpstream_send_and_update_frame(data, stream, node)) != 0) {
				RRR_MSG_0("Could not send frame in __rrr_udpstream_send_loop\n");
				goto out;
			}

			if (++sent_count >= RRR_UDPSTREAM_BURST_LIMIT_SEND) {
				*sending_complete = 0;
				RRR_LL_ITERATE_LAST();
			}
		}
	RRR_LL_ITERATE_END();

	*sent_count_return = sent_count;

	out:
	return ret;
}

// Send out buffered messages from outbound buffer
static int __rrr_udpstream_do_send_tasks (
		int *sending_complete,
		int *send_count,
		struct rrr_udpstream *data
) {
	int ret = 0;

	*send_count = 0;
	*sending_complete = 1;

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		int count = 0;
		int sending_complete_tmp = 0;

		if ((ret = __rrr_udpstream_send_loop(&sending_complete_tmp, &count, data, node)) != 0) {
			goto out;
		}

		*send_count += count;
		if (!sending_complete_tmp) {
			*sending_complete = 0;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_udpstream_stream_exists (
		struct rrr_udpstream *data,
		uint16_t stream_id
) {
	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_stream_id(data, stream_id);
	if (stream == NULL) {
		return 0;
	}
	return 1;
}

int rrr_udpstream_connection_check_address_equal (
		struct rrr_udpstream *data,
		uint32_t connect_handle,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(data, connect_handle);
	if (stream == NULL) {
		ret = 0;
		goto out;
	}

	if (stream->remote_addr_len == addr_len && memcmp(stream->remote_addr, addr, addr_len) == 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_udpstream_connection_check (
		struct rrr_udpstream *data,
		uint32_t connect_handle
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_SOFT_ERR;
		goto out;
	}

	if (stream->stream_id == 0) {
		RRR_DBG_3("UDP-stream %u not ready yet\n", stream->stream_id);
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	if (stream->send_buffer.frame_id_counter >= stream->send_buffer.frame_id_max) {
		RRR_DBG_3("UDP-stream %u IDs exhausted\n", stream->stream_id);
		stream->destroy_on_empty_buffers = 1;
		ret = RRR_UDPSTREAM_SOFT_ERR;
		goto out;
	}

	out:
	return ret;
}

// Application may decrease or increase window size to decrease or
// increase throughput. The new window size is sent later when some ACK
// packets are sent. Multiple calls to this function will cause window
// the size changes to be summed together.
int rrr_udpstream_regulate_window_size (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		int window_size_change
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_SOFT_ERR;
		goto out;
	}
	if (stream->stream_id == 0) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	stream->window_size_regulation_from_application += window_size_change;

	RRR_DBG_3("UDP-stream WS REQ %u change %i\n", stream->stream_id, window_size_change);

	out:
	return ret;
}

// Send a control frame immediately, by-passing buffer
int rrr_udpstream_send_control_frame (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		uint64_t application_data
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_SOFT_ERR;
		goto out;
	}

	if (stream->stream_id == 0) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	struct rrr_udpstream_frame frame = {0};

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_CONTROL;
	frame.stream_id = stream->stream_id;
	frame.application_data = application_data;

	if ((ret = __rrr_udpstream_send_frame (udpstream_data, stream, &frame)) != 0) {
		RRR_MSG_0("Could not send control frame in rrr_udpstream_send_control_frame for stream with connect handle %u\n",
				connect_handle);
		goto out;
	}

	out:
	return ret;
}

// Put messages into outbound buffer
int rrr_udpstream_queue_outbound_data (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		const void *data,
		rrr_biglength data_size,
		uint64_t application_data
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_SOFT_ERR;
		goto out;
	}

	if (stream->stream_id == 0) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	if (RRR_LL_COUNT(&stream->send_buffer) >= RRR_UDPSTREAM_BUFFER_LIMIT) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	if (stream->send_buffer.frame_id_counter + ((data_size / RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) + 1) > stream->send_buffer.frame_id_max) {
		RRR_DBG_3("UDP-stream frame IDs exhausted for stream-id %u\n", stream->stream_id);
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	const void *pos = data;
	struct rrr_udpstream_frame *new_frame = NULL;
	while (data_size > 0) {
		uint16_t chunk_size = (data_size > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT ? RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT : (uint16_t) data_size);
		new_frame = NULL;
		if ((ret = __rrr_udpstream_frame_new_from_data(&new_frame, pos, chunk_size)) != 0) {
			RRR_MSG_0("Could not allocate frame in rrr_udpstream_queue_outbound_data\n");
			ret = RRR_UDPSTREAM_HARD_ERR;
			goto out;
		}

		new_frame->flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_DATA;
		new_frame->frame_id = ++(stream->send_buffer.frame_id_counter);
		new_frame->application_data = application_data;

		RRR_LL_APPEND(&stream->send_buffer, new_frame);

		pos += chunk_size;
		data_size -= chunk_size;
	}

	// Set boundary flag on last frame
	if (new_frame != NULL) {
		new_frame->flags_and_type |= (RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY << 4);
	}

	if (!EVENT_PENDING(udpstream_data->event_send)) {
		EVENT_ADD(udpstream_data->event_send);
	}

	out:
	return ret;
}

void rrr_udpstream_close (
		struct rrr_udpstream *data
) {
	if (data->clients != NULL) {
		rrr_socket_client_collection_destroy(data->clients);
		data->clients = NULL;
	}

	// In case socket client collection has not already closed the FD
	rrr_ip_network_cleanup(&data->ip);

	__rrr_udpstream_stream_collection_clear(&data->streams);
	rrr_event_collection_clear(&data->events);
}

static int __rrr_udpstream_bind (
		struct rrr_ip_data *ip_data,
		uint16_t local_port,
		int do_ipv6
) {

	ip_data->port = local_port;

	if (rrr_ip_network_start_udp (ip_data, do_ipv6) != 0) {
		return 1;
	}

	return 0;
}

static void __rrr_udpstream_event_send (
		int fd,
		short flags,
		void *arg
) {
	struct rrr_udpstream *data = arg;

	(void)(fd);
	(void)(flags);

	int sending_complete = 0;
	int send_count_dummy = 0;

	if (__rrr_udpstream_do_send_tasks (
			&sending_complete,
			&send_count_dummy,
			data
	) != 0) {
		rrr_event_dispatch_break(data->queue);
	}

	if (sending_complete) {
		EVENT_REMOVE(data->event_send);
	}
}

static void __rrr_udpstream_event_deliver (
		int fd,
		short flags,
		void *arg
) {
	struct rrr_udpstream *data = arg;

	(void)(fd);
	(void)(flags);

	int reading_complete = 0;

	// TODO : Check upstram ready for delivery

	if (__rrr_udpstream_process_receive_buffers (
		&reading_complete,
		data
	) != 0) {
		rrr_event_dispatch_break(data->queue);
	}

	if (reading_complete) {
		EVENT_REMOVE(data->event_deliver);
	}
}

static void __rrr_udpstream_event_periodic (
		int fd,
		short flags,
		void *arg
) {
	struct rrr_udpstream *data = arg;

	(void)(fd);
	(void)(flags);

	// Send any unacknowledged messages
/*

	int sending_complete_dummy;
	int send_count_dummy;
if (__rrr_udpstream_do_send_tasks (&sending_complete_dummy, &send_count_dummy, data) != 0) {
		rrr_event_dispatch_break(data->queue);
	}*/

	// Check connection timeouts
	if (__rrr_udpstream_maintain(data) != 0) {
		rrr_event_dispatch_break(data->queue);
	}
}

static int __rrr_udpstream_events_create (
		struct rrr_udpstream *data
) {
	int ret = 0;

	if ((ret = rrr_event_collection_push_periodic (
			&data->event_deliver,
			&data->events,
			__rrr_udpstream_event_deliver,
			data,
			10 * 1000 // 10 ms
	)) != 0) {
		goto out_err;
	}

	if ((ret = rrr_event_collection_push_periodic (
			&data->event_send,
			&data->events,
			__rrr_udpstream_event_send,
			data,
			10 * 1000 // 10 ms
	)) != 0) {
		goto out_err;
	}

	if ((ret = rrr_event_collection_push_periodic (
			&data->event_periodic,
			&data->events,
			__rrr_udpstream_event_periodic,
			data,
			1000 * RRR_UDPSTREAM_RESEND_INTERVAL_FRAME_MS / 4
	)) != 0) {
		goto out_err;
	}

	EVENT_ADD(data->event_periodic);

	if ((ret = rrr_socket_client_collection_connected_fd_push (
			data->clients,
			data->ip.fd,
			RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT
	)) != 0) {
		RRR_MSG_0("Failed to push FD to client collection in __rrr_udpstream_events_create\n");
		goto out;
	}

	goto out;
	out_err:
		rrr_event_collection_clear(&data->events);
	out:
		return ret;
}

int rrr_udpstream_bind_v6_priority (
		struct rrr_udpstream *data,
		uint16_t local_port
) {
	int ret = 0;

	if (data->ip.fd != 0) {
		RRR_BUG("rrr_udpstream_bind called with non-zero fd, bind already complete\n");
	}

	int ret_4 = 0, ret_6 = 0;

	ret_6 = __rrr_udpstream_bind(&data->ip, local_port, 1);
	if (ret_6 != 0) {
		data->ip.fd = 0;
		ret_4 = __rrr_udpstream_bind(&data->ip, local_port, 0);
	}

	if (ret_4 != 0 && ret_6 != 0) {
		RRR_MSG_0("Listening failed on both IPv4 and IPv6 in udpstream on port %u\n", local_port);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_udpstream_events_create(data)) != 0) {
		RRR_MSG_0("Failed to create events in rrr_udpstream_bind_v6_priority\n");
		goto out_unbind;
	}

	if (ret_6 == 0) {
		RRR_DBG_1("udpstream bind on port %u IPv6 (possibly dual-stack)\n", local_port);
	}
	else {
		RRR_DBG_1("udpstream bind on port %u IPv4\n", local_port);
	}

	goto out;
	out_unbind:
		rrr_ip_network_cleanup(&data->ip);
	out:
		return ret;
}

int rrr_udpstream_bind_v4_only (
		struct rrr_udpstream *data,
		uint16_t local_port
) {
	int ret = 0;

	if (data->ip.fd != 0) {
		RRR_BUG("rrr_udpstream_bind called with non-zero fd, bind already complete\n");
	}

	if (__rrr_udpstream_bind(&data->ip, local_port, 0) != 0) {
		RRR_MSG_0("Listening failed on IPv4 in udpstream on port %u\n", local_port);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_udpstream_events_create(data)) != 0) {
		RRR_MSG_0("Failed to create events in rrr_udpstream_bind_v4_only\n");
		goto out_unbind;
	}

	RRR_DBG_1("udpstream bind on port %u IPv4 only\n", local_port);

	goto out;
	out_unbind:
		rrr_ip_network_cleanup(&data->ip);
	out:
		return ret;
}

int rrr_udpstream_connect_raw (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen
) {
	int ret = 0;

	if (data->ip.fd == 0) {
		RRR_BUG("FD was 0 in rrr_udpstream_connect_raw, must bind first\n");
	}

	if ((ret = __rrr_udpstream_send_connect(connect_handle, data, addr, socklen)) != 0) {
		RRR_MSG_0("Could not send connect packet in rrr_udpstream_connect_raw\n");
		goto out;
	}

	out:
	return ret;
}

int rrr_udpstream_connect (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const char *remote_host,
		const char *remote_port
) {
	int ret = 0;

	if (data->ip.fd == 0) {
		RRR_BUG("FD was 0 in rrr_udpstream_connect, must bind first\n");
	}

	struct addrinfo hints;
	struct addrinfo *result;

	memset (&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;

	int s = getaddrinfo(remote_host, remote_port, &hints, &result);
	if (s != 0) {
		RRR_MSG_0("Failed to get address of '%s' in udpstream: %s\n", remote_host, gai_strerror(s));
		ret = 1;
		goto out;
	}

	struct addrinfo *rp;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (RRR_DEBUGLEVEL_1) {
			char buf[128];
			rrr_ip_to_str(buf, sizeof(buf), result->ai_addr, result->ai_addrlen);
			RRR_MSG_1("UDP-stream connection attempt to %s\n", buf);
		}
		if ((ret = rrr_udpstream_connect_raw(connect_handle, data, result->ai_addr, result->ai_addrlen)) != 0) {
			RRR_DBG_1("UDP-stream failed to send connect packet, return was %i\n", ret);
		}
		else {
			break;
		}
	}

	// Let last return value propagate

	if (ret != 0) {
		RRR_MSG_0("Could not send connect packet in udpstream, all address suggestions failed\n");
	}

	freeaddrinfo(result);

	out:
	return ret;
}

void rrr_udpstream_dump_stats (
	struct rrr_udpstream *data
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		RRR_DBG(" - Stream %i: recv buf %i delivered id pos %u, send buf %i id pos %u window size f/t %" PRIu32 "/%" PRIu32 "\n",
				node->stream_id,
				RRR_LL_COUNT(&node->receive_buffer),
				node->receive_buffer.frame_id_prev_boundary_pos,
				RRR_LL_COUNT(&node->send_buffer),
				node->send_buffer.frame_id_counter,
				node->window_size_from_remote,
				node->window_size_to_remote
		);
	RRR_LL_ITERATE_END();
}

void rrr_udpstream_clear (
		struct rrr_udpstream *data
) {
	rrr_udpstream_close(data);
	RRR_FREE_IF_NOT_NULL(data->send_buffer);
}

int rrr_udpstream_init (
		struct rrr_udpstream *data,
		struct rrr_event_queue *queue,
		int flags,
		int (*upstream_control_frame_callback)(uint32_t connect_handle, uint64_t application_data, void *arg),
		void *upstream_control_frame_callback_arg,
		int (*upstream_allocator_callback) (RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS),
		void *upstream_allocator_callback_arg,
		int (*upstream_validator_callback)(RRR_UDPSTREAM_VALIDATOR_CALLBACK_ARGS),
		void *upstream_validator_callback_arg,
		int (*upstream_final_receive_possible_callback)(RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_POSSIBLE_ARGS),
		void *upstream_final_receive_possible_callback_arg,
		int (*upstream_final_callback)(RRR_UDPSTREAM_FINAL_RECEIVE_CALLBACK_ARGS),
		void *upstream_final_callback_arg
) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->flags = flags;

	flags &= ~(RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS|RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP|RRR_UDPSTREAM_FLAGS_FIXED_CONNECT_HANDLE);
	if (flags != 0) {
		RRR_BUG("Invalid flags %u in rrr_udpstream_init\n", flags);
	}

	rrr_event_collection_init(&data->events, queue);
	__rrr_udpstream_stream_collection_init(&data->streams);

	if ((ret = rrr_socket_client_collection_new (&data->clients, queue, "udpstream")) != 0) {
		RRR_MSG_0("Failed to create client collection in rrr_udpstream_init\n");
		goto out;
	}

	rrr_socket_client_collection_event_setup_raw (
			data->clients,
			NULL,
			NULL,
			data,
			8192,
			RRR_SOCKET_READ_METHOD_RECVFROM,
			__rrr_udpstream_set_read_flags_callback,
			NULL,
			__rrr_udpstream_read_get_target_size,
			NULL,
			__rrr_udpstream_read_get_target_size_error,
			NULL,
			__rrr_udpstream_read_callback,
			data
	);

	rrr_socket_client_collection_fd_close_notify_setup (
			data->clients,
			__rrr_udpstream_fd_close_callback,
			data
	);

	data->queue = queue;
	data->upstream_control_frame_callback = upstream_control_frame_callback;
	data->upstream_control_frame_callback_arg = upstream_control_frame_callback_arg;
	data->upstream_allocator_callback = upstream_allocator_callback;
	data->upstream_allocator_callback_arg = upstream_allocator_callback_arg;
	data->upstream_validator_callback = upstream_validator_callback;
	data->upstream_validator_callback_arg = upstream_validator_callback_arg;
	data->upstream_final_receive_possible_callback = upstream_final_receive_possible_callback,
	data->upstream_final_receive_possible_callback_arg = upstream_final_receive_possible_callback_arg,
	data->upstream_final_callback = upstream_final_callback;
	data->upstream_final_callback_arg = upstream_final_callback_arg;

	out:
	return ret;
}
