/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include <read.h>

#include "../global.h"
#include "udpstream.h"
#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "linked_list.h"
#include "vl_time.h"
#include "crc32.h"
#include "random.h"

static int __rrr_udpstream_frame_destroy(struct rrr_udpstream_frame *frame) {
	RRR_FREE_IF_NOT_NULL(frame->data);
	RRR_FREE_IF_NOT_NULL(frame->source_addr);
	free(frame);
	return 0;
}

static int __rrr_udpstream_frame_new_from_data (
		struct rrr_udpstream_frame **target,
		const void *data,
		uint16_t data_size
) {
	int ret = 0;

	*target = NULL;

	struct rrr_udpstream_frame *res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_udpstream_frame_new_from_data A\n");
		ret = 1;
		goto out;
	}
	memset(res, '\0', sizeof(*res));

	if (data_size > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) {
		RRR_BUG("Data size was exceeds maximum in __rrr_udpstream_frame_new_from_data\n");
	}

	if (data_size > 0) {
		res->data = malloc(data_size);
		if (res->data == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_udpstream_frame_new_from_data B\n");
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
		if ((result->source_addr = malloc(addr_len)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for address in __rrr_udpstream_frame_new_from_packed\n");
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
	free(stream);
	return 0;
}

static int __rrr_udpstream_stream_new(struct rrr_udpstream_stream **target) {
	*target = NULL;

	struct rrr_udpstream_stream *res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_udpstream_stream_new\n");
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

static void __rrr_udpstream_stream_invalidate(struct rrr_udpstream_stream *stream) {
	stream->send_buffer.frame_id_max = 0;
	stream->invalidated = 1; // Prevents stream find-functions from returning this stream
}

static void __rrr_udpstream_stream_collection_clear(struct rrr_udpstream_stream_collection *collection) {
	RRR_LL_DESTROY(collection, struct rrr_udpstream_stream, __rrr_udpstream_stream_destroy(node));
}

static void __rrr_udpstream_stream_collection_init(struct rrr_udpstream_stream_collection *collection) {
	memset (collection, '\0', sizeof(*collection));
}

void rrr_udpstream_clear (
		struct rrr_udpstream *data
) {
	rrr_read_session_collection_clear(&data->read_sessions);
	__rrr_udpstream_stream_collection_clear(&data->streams);
	pthread_mutex_destroy(&data->lock);
	RRR_FREE_IF_NOT_NULL(data->send_buffer);
}

int rrr_udpstream_init (
		struct rrr_udpstream *data,
		int flags
) {
	memset (data, '\0', sizeof(*data));
	data->flags = flags;
	flags &= ~(RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS|RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP|RRR_UDPSTREAM_FLAGS_FIXED_CONNECT_HANDLE);
	if (flags != 0) {
		RRR_BUG("Invalid flags %u in rrr_udpstream_init\n", flags);
	}
	__rrr_udpstream_stream_collection_init(&data->streams);
	rrr_read_session_collection_init(&data->read_sessions);
	pthread_mutex_init(&data->lock, 0);
	return 0;
}

void rrr_udpstream_set_flags (
		struct rrr_udpstream *data,
		int flags
) {
	pthread_mutex_lock(&data->lock);
	data->flags = flags;
	pthread_mutex_unlock(&data->lock);
}

static int __rrr_udpstream_checksum_and_send_packed_frame (
		struct rrr_udpstream *udpstream_data,
		const struct sockaddr *addr,
		socklen_t addrlen,
		struct rrr_udpstream_frame_packed *frame,
		void *data,
		uint16_t data_size,
		int copies
) {
	int ret = 0;

	// TODO : Move allocation to init function
	if (udpstream_data->send_buffer == NULL) {
		udpstream_data->send_buffer = malloc(RRR_UDPSTREAM_MESSAGE_SIZE_MAX);
		if (udpstream_data->send_buffer == NULL) {
			RRR_MSG_ERR("Could not allocate send buffer in __rrr_udpstream_checksum_and_send_packed_frame\n");
			ret = 1;
			goto out;
		}
		udpstream_data->send_buffer_size = RRR_UDPSTREAM_MESSAGE_SIZE_MAX;
	}

	if (data_size > udpstream_data->send_buffer_size) {
		RRR_BUG("data size too big in __rrr_udpstream_checksum_and_send_packed_frame\n");
	}

	if (addr == NULL) {
		RRR_BUG("addr was NULL in __rrr_udpstream_checksum_and_send_packed_frame\n");
	}

	// A packed frame created locally has the payload stored separately
	if (data_size > 0) {
		frame->data_crc32 = htobe32(crc32buf((char *) data, data_size));
		frame->data_size = htobe16(data_size);
	}

	char *crc32_start_pos = ((char *) frame) + sizeof(frame->header_crc32);
	ssize_t crc32_size = sizeof(*frame) - sizeof(frame->header_crc32) - 1;

	frame->header_crc32 = htobe32(crc32buf(crc32_start_pos, crc32_size));

	RRR_DBG_3("UDP-stream TX packed crc32: %" PRIu32 " size: %u flags_type: %u connect_handle/frame_id/window_size: %u stream: %u\n",
			frame->header_crc32, be16toh(frame->data_size), frame->flags_and_type, be32toh(frame->connect_handle), be16toh(frame->stream_id));

	memcpy(udpstream_data->send_buffer, frame, sizeof(*frame) - 1);
	memcpy(udpstream_data->send_buffer + sizeof(*frame) - 1, data, data_size);

	while (copies--) {
#ifdef RRR_UDPSTREAM_PACKET_LOSS_DEBUG_PERCENT
		if (rand() % 100 <= RRR_UDPSTREAM_PACKET_LOSS_DEBUG_PERCENT) {
			RRR_DBG_3("UDP-stream TX forgot to send packet :-(\n");
			continue;
		}
#endif
		int err;
		if ((ret = rrr_ip_send(&err, udpstream_data->ip.fd, addr, addrlen, udpstream_data->send_buffer, sizeof(*frame) - 1 + data_size)) != 0) {
			RRR_MSG_ERR("Could not send packed frame header in __rrr_udpstream_send_packed_frame\n");
			ret = 1;
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
	new_stream->remote_addr = malloc(new_stream->remote_addr_len);
	if (new_stream->remote_addr == NULL) {
		RRR_MSG_ERR("Could not allocate memory for address in __rrr_udpstream_send_connect\n");
		__rrr_udpstream_stream_destroy(new_stream);
		new_stream = NULL;
		goto out;
	}
	memcpy(new_stream->remote_addr, addr, new_stream->remote_addr_len);

	RRR_LL_PUSH(&data->streams, new_stream);

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

	RRR_DBG_3("UDP-stream RX ACK %u-%u-%u DUP %i\n",
			stream_id, ack_id_first, ack_id_last, copies);

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_FRAME_ACK;
	frame.stream_id = htobe16(stream_id);
	frame.ack_data.ack_id_first = htobe32(ack_id_first);
	frame.ack_data.ack_id_last = htobe32(ack_id_last);

	if (window_size != 0) {
		frame.flags_and_type |= (RRR_UDPSTREAM_FRAME_FLAGS_WINDOW_SIZE << 4);
		frame.window_size = htobe32(window_size);
	}

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, copies);
}

static int __rrr_udpstream_send_reset (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t frame_id
) {
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_RESET;
	frame.stream_id = htobe16(stream_id);

	// If frame ID is zero, remote should perform a hard reset which implies creating a
	// new connection and sending any data in send buffers again
	frame.frame_id = htobe32(frame_id);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, 3);
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
	frame.stream_id = htobe16(stream_id);
	frame.connect_handle = htobe32(connect_handle);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0, 3);
}

static uint32_t __rrr_udpstream_allocate_connect_handle (
		struct rrr_udpstream *data
) {
	uint32_t ret = rrr_rand();
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
			RRR_MSG_ERR("Could not allocate connect handle in __rrr_udpstream_send_connect\n");
			ret = 1;
			goto out;
		}
	}

	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags_and_type = RRR_UDPSTREAM_FRAME_TYPE_CONNECT;
	frame.connect_handle = htobe32(connect_handle);

	struct rrr_udpstream_stream *stream = NULL;
	if ((stream = __rrr_udpstream_create_and_add_stream(data, addr, addr_len)) == NULL) {
		RRR_MSG_ERR("Could not add stream to collection in __rrr_udpstream_send_connect\n");
		ret = 1;
		goto out;
	}

	stream->connect_handle = connect_handle;

	if (__rrr_udpstream_checksum_and_send_packed_frame(data, stream->remote_addr, stream->remote_addr_len, &frame, NULL, 0, 3) != 0) {
		RRR_MSG_ERR("Could not send CONNECT packet in __rrr_udpstream_send_connect\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_2("Sent CONNECT with handle %" PRIu32 "\n", connect_handle);

	*connect_handle_result = connect_handle;

	out:
	return ret;
}

static void __rrr_udpstream_frame_packed_dump (
		const struct rrr_udpstream_frame_packed *frame
) {
	RRR_DBG ("-- UDP-stream packed frame size %lu\n", RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame));
	RRR_DBG ("Header CRC32 : %" PRIu32 "\n", RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame));
	RRR_DBG ("Data CRC32   : %" PRIu32 "\n", RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame));
	RRR_DBG ("Flags        : %u\n", RRR_UDPSTREAM_FRAME_FLAGS(frame));
	RRR_DBG ("Type	        : %u\n", RRR_UDPSTREAM_FRAME_TYPE(frame));
	RRR_DBG ("Version      : %u\n", RRR_UDPSTREAM_FRAME_PACKED_VERSION(frame));
	RRR_DBG ("Stream-ID    : %u\n", RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(frame));
	RRR_DBG ("Frame-ID     : %u\n", RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(frame));

	RRR_DBG("-- 0x");
	for (size_t i = 0; i < RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame); i++) {
		char c = ((char *)frame)[i];
		if (c < 0x10) {
			RRR_DBG("0");
		}
		RRR_DBG("%x", c);
	}
	RRR_DBG("\n------------\n");
}

static int __rrr_udpstream_frame_packed_validate (
		const struct rrr_udpstream_frame_packed *frame
) {
	uint32_t header_crc32 = RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame);

//	printf ("packed crc32 receive: %" PRIu32 "\n", frame->header_crc32);
//	printf ("packed crc32 receive bswapped: %" PRIu32 "\n", header_crc32);

	char *crc32_start_pos = ((char *) frame) + sizeof(frame->header_crc32);
	ssize_t crc32_size = sizeof(*frame) - sizeof(frame->header_crc32) - 1;

	if (crc32cmp(crc32_start_pos, crc32_size, header_crc32) != 0) {
		RRR_MSG_ERR("Header CRC32 mismatch in __rrr_udpstream_frame_pack_validate\n");
		if (RRR_DEBUGLEVEL_2) {
			__rrr_udpstream_frame_packed_dump(frame);
		}
		return 1;
	}

	return 0;
}

static int __rrr_udpstream_read_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	int ret = RRR_SOCKET_OK;

	(void)(arg);

	struct rrr_udpstream_frame_packed *frame = (struct rrr_udpstream_frame_packed *) read_session->rx_buf_ptr;

	if (read_session->rx_buf_wpos < (ssize_t) sizeof (struct rrr_udpstream_frame_packed) - 1) {
		ret = RRR_SOCKET_READ_INCOMPLETE;
		goto out;
	}

	if (__rrr_udpstream_frame_packed_validate(frame) != 0) {
		RRR_MSG_ERR("Could not validate received frame in __rrr_udpstream_read_get_target_size\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

//	printf ("Data size: %u\n", frame->data_size);
	ssize_t total_size = RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame);

	if (RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame) > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) {
		RRR_MSG_ERR("UDP-stream received data size exceeded maximum (%li > %i)\n", total_size, RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session->target_size = total_size;

	out:
	return ret;
}
static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_connect_handle (
		struct rrr_udpstream *data,
		uint32_t connect_handle
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle && node->invalidated == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_connect_handle_and_addr (
		struct rrr_udpstream *data,
		uint32_t connect_handle,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle &&
			node->remote_addr_len == addr_len &&
			memcmp(node->remote_addr, addr, addr_len) == 0 &&
			node->invalidated == 0
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
		if (node->stream_id == stream_id && node->invalidated == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
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
			if ((stream->remote_addr = malloc(sizeof(*(stream->remote_addr)))) == NULL) {
				RRR_MSG_ERR("Could not allocate memory in __rrr_udpstream_update_stream_remote\n");
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
		RRR_DBG_3("Received UDP-stream CONNECT packet with non-zero payload, dropping it\n");
		goto out;
	}

	stream = __rrr_udpstream_find_stream_by_connect_handle_and_addr(data, frame->connect_handle, src_addr, addr_len);
	if (stream != NULL && stream->stream_id == 0) {
		// We are expecting CONNECT response
		if (stream->remote_addr_len != addr_len || memcmp(stream->remote_addr, src_addr, addr_len) != 0) {
			RRR_MSG_ERR("Received CONNECT response from unexpected remote host\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		if (frame->stream_id == 0) {
			RRR_MSG_ERR("Received zero stream ID in CONNECT response in __rrr_udpstream_handle_received_connect, connection was rejected\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		struct rrr_udpstream_stream *stream_test = __rrr_udpstream_find_stream_by_stream_id(data, frame->stream_id);
		if (stream_test != NULL) {
			RRR_DBG_2("Stream ID collision for connect with handle %u, connection must be closed\n", frame->connect_handle);
			__rrr_udpstream_stream_invalidate(stream);
			goto out;
		}

		stream->stream_id = frame->stream_id;

		RRR_DBG_2("Outbound UDP-stream connection established with stream id %u connect handle was %u\n",
				stream->stream_id, frame->connect_handle);
	}
	else if (stream != NULL && stream->stream_id != 0) {
		// Already connected
		RRR_DBG_2("Incoming UDP-stream duplicate CONNECT (response)\n");
		goto out;
	}
	else {
		uint16_t stream_id = 0;

		if ((data->flags & RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS) == 0) {
			RRR_MSG_ERR("Received CONNECT packet with handle %u in __rrr_udpstream_handle_received_connect, but we are neither expecting CONNECT response nor accepting connections\n",
					RRR_UDPSTREAM_FRAME_PACKED_CONNECT_HANDLE(frame));
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		if ((data->flags & RRR_UDPSTREAM_FLAGS_DISALLOW_IP_SWAP) != 0) {
			stream = __rrr_udpstream_find_stream_by_connect_handle_and_addr(data, frame->connect_handle, src_addr, addr_len);
		}
		else {
			if ((stream = __rrr_udpstream_find_stream_by_connect_handle(data, frame->connect_handle)) != NULL) {
				if (__rrr_udpstream_update_stream_remote(stream, src_addr, addr_len) != 0) {
					RRR_MSG_ERR("Could not update stream remote in __rrr_udpstream_handle_received_connect\n");
					ret = RRR_SOCKET_HARD_ERROR;
					goto out;
				}
			}
		}

		if (stream != NULL) {
			// Already connected, send new response
			RRR_DBG_2("Incoming UDP-stream duplicate CONNECT\n");
			stream_id = stream->stream_id;
			goto send_response;
		}

		// If stream id is zero, we cannot accept more connections and the connection is rejected
		stream_id = __rrr_udpstream_allocate_stream_id(data);
		if (stream_id > 0) {
			if ((stream = __rrr_udpstream_create_and_add_stream(data, src_addr, addr_len)) == NULL) {
				RRR_MSG_ERR("Could not push new connection to buffer collections in __rrr_udpstream_handle_received_connect\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}

			// We do not store the address of the remote client. The receive function callback
			// receives the currently used sender address for every message.
			stream->stream_id = stream_id;
			stream->connect_handle = frame->connect_handle;

			RRR_DBG_2("Incoming UDP-stream connection established with stream id %u connect handle %u\n",
					stream_id, stream->connect_handle);
		}
		else {
			// This is not considered an error
			RRR_DBG_2("Incoming UDP-stream connection rejected\n");
			goto send_response;
		}

		send_response:
		RRR_DBG_2("Sending UDP-stream CONNECT response stream id %u connect handle %u\n",
				stream_id, stream->connect_handle);
		if (__rrr_udpstream_send_connect_response(data, src_addr, addr_len, stream_id, frame->connect_handle) != 0) {
			RRR_MSG_ERR("Could not send connect response in __rrr_udpstream_handle_received_connect\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_udpstream_handle_received_reset (
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame
) {
	int ret = 0;

	RRR_DBG_3("UDP-stream RX RST %u\n", new_frame->stream_id);

	if (new_frame->frame_id == 0) {
		RRR_DBG_3("Performing hard reset for stream ID %u\n", new_frame->stream_id);

		stream->receive_buffer.frame_id_max = stream->receive_buffer.frame_id_counter;
		stream->send_buffer.frame_id_max = stream->send_buffer.frame_id_counter;
		stream->hard_reset_received = 1;

		goto out;
	}
	else {
		// Soft reset, continue until received last frame id. Do not send any more frames.
		stream->receive_buffer.frame_id_max = new_frame->frame_id;
		stream->send_buffer.frame_id_max = stream->send_buffer.frame_id_counter;
	}

	out:
	return ret;
}

static int __rrr_udpstream_handle_received_frame_ack (
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame
) {
	int ret = 0;

	RRR_DBG_3("UDP-stream RX ACK %u-%u-%u\n",
			new_frame->stream_id, new_frame->ack_data.ack_id_first, new_frame->ack_data.ack_id_last);

	RRR_LL_ITERATE_BEGIN(&stream->send_buffer, struct rrr_udpstream_frame);
		if (node->frame_id >= new_frame->ack_data.ack_id_first && node->frame_id <= new_frame->ack_data.ack_id_last) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else {
			node->unacknowledged_count++;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->send_buffer, __rrr_udpstream_frame_destroy(node));

	return ret;
}

static int __rrr_udpstream_handle_received_frame_control (
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame,
		int (*control_frame_listener)(uint32_t connect_handle, uint64_t application_data, void *arg),
		void *control_frame_listener_arg
) {
	int ret = 0;

	RRR_DBG_3("UDP-stream RX CTRL %u-%" PRIu64 "\n",
			new_frame->stream_id, new_frame->application_data);

	if ((ret = control_frame_listener (
			stream->connect_handle,
			new_frame->application_data,
			control_frame_listener_arg
	)) != 0) {
		RRR_MSG_ERR("Error from control frame listener in __rrr_udpstream_handle_received_frame_control\n");
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

	stream->window_size_to_remote = tmp;

	return 0;
}

static int __rrr_udpstream_handle_received_frame (
		struct rrr_udpstream *data,
		const struct rrr_udpstream_frame_packed *frame,
		const struct sockaddr *src_addr,
		socklen_t addr_len,
		int (*control_frame_listener)(uint32_t connect_handle, uint64_t application_data, void *arg),
		void *control_frame_listener_arg
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream_frame *new_frame = NULL;

	RRR_DBG_3("UDP-stream RX %u-%u crc32: %" PRIu32 " S: %u F/T: %u CH: %u\n",
			be16toh(frame->stream_id),
			be32toh(frame->frame_id),
			frame->header_crc32,
			be16toh(frame->data_size),
			frame->flags_and_type, be32toh(frame->connect_handle)
	);

	if (__rrr_udpstream_frame_new_from_packed(&new_frame, frame, src_addr, addr_len) != 0) {
		RRR_MSG_ERR("Could not allocate internal frame in __rrr_udpstream_handle_received_frame\n");
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_CONNECT(new_frame)) {
		ret = __rrr_udpstream_handle_received_connect(data, new_frame, src_addr, addr_len);
		goto out;
	}

	if (new_frame->stream_id == 0) {
		RRR_DBG_2("Unknown packet with type/flags %u and zero stream id in __rrr_udpstream_handle_received_frame\n",
				new_frame->flags_and_type);
		goto out;
	}

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_stream_id(data, new_frame->stream_id);

	if (stream == NULL) {
		// Check that unknown packet is not a reset, if not we would keep sending resets back and forward
		if (!RRR_UDPSTREAM_FRAME_IS_RESET(frame)) {
			RRR_DBG_2("Received UDP-stream packet with unknown stream ID %u, sending hard reset\n", new_frame->stream_id);
			if (__rrr_udpstream_send_reset(data, src_addr, addr_len, new_frame->stream_id, 0) != 0) {
				RRR_MSG_ERR("Could not send UDP-stream hard reset in __rrr_udpstream_handle_received_frame\n");
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
			RRR_MSG_ERR("Could not update remote stream address in __rrr_udpstream_handle_received_frame\n");
			goto out;
		}
	}

	if (RRR_UDPSTREAM_FRAME_IS_RESET(new_frame)) {
		ret = __rrr_udpstream_handle_received_reset(stream, new_frame);
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
		ret = __rrr_udpstream_handle_received_frame_ack(stream, new_frame);
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_CONTROL(frame)) {
		ret = __rrr_udpstream_handle_received_frame_control (
				stream,
				new_frame,
				control_frame_listener,
				control_frame_listener_arg
		);
		goto out;
	}

	if (new_frame->frame_id == 0) {
		RRR_DBG_2("Received data frame with flags %u and zero frame id in __rrr_udpstream_handle_received_frame_control\n",
				new_frame->flags_and_type);
		goto out;
	}
/*
	VL_DEBUG_MSG_3("UDP-stream packet with data for stream ID %u frame id %u boundary %i flags %i type %i\n",
			new_frame->stream_id,
			new_frame->frame_id,
			RRR_UDPSTREAM_FRAME_IS_BOUNDARY(new_frame),
			RRR_UDPSTREAM_FRAME_FLAGS(new_frame),
			RRR_UDPSTREAM_FRAME_TYPE(frame)
	);
*/
	if (stream->receive_buffer.frame_id_counter == 0 && new_frame->frame_id != 1) {
		// First frame must be ID 1, this to be able to filter out "old data" from lost streams
		// which might be retained if we are offline for a bit. If this happens, we must also
		// reset the whole stream and the sender must connect again and obtain a new ID.

		RRR_DBG_2("udpstream id %u dropping frame ID %u as we expect first frame id 1\n",
				new_frame->stream_id, new_frame->frame_id);

		if (__rrr_udpstream_send_reset(data, src_addr, addr_len, new_frame->stream_id, 0) != 0) {
			RRR_MSG_ERR("Could not send UDP-stream hard reset in __rrr_udpstream_handle_received_frame\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		__rrr_udpstream_stream_invalidate(stream);

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
//			VL_DEBUG_MSG_2("udpstream stream-id %u frame id %u insert in receive buffer before %u\n",
//					stream->stream_id, new_frame->frame_id, node->frame_id);
			RRR_LL_ITERATE_INSERT(&stream->receive_buffer, new_frame);
			new_frame = NULL;
			goto out;
		}
		if (node->frame_id < frame_id_max) {
			RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
				RRR_MSG_ERR("udpstream stream-id %u frame id %u dump recv buffer\n",
						stream->stream_id, node->frame_id);
			RRR_LL_ITERATE_END();
			RRR_BUG("Order error in receive buffer in __rrr_udpstream_handle_received_frame\n");
		}
		frame_id_max = node->frame_id;
	RRR_LL_ITERATE_END();

	out_append:
//		VL_DEBUG_MSG_2("udpstream stream-id %u frame id %u append to receive buffer\n",
//				stream->stream_id, new_frame->frame_id);
		RRR_LL_APPEND(&stream->receive_buffer, new_frame);
		new_frame = NULL;

	out:
		if (new_frame != NULL) {
			__rrr_udpstream_frame_destroy(new_frame);
		}
		return ret;
}

struct rrr_udpstream_read_callback_data {
	struct rrr_udpstream *data;
	int receive_count;
	int (*control_frame_listener)(uint32_t connect_handle, uint64_t application_data, void *arg);
	void *control_frame_listener_arg;
};

static int __rrr_udpstream_read_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream_read_callback_data *callback_data = arg;
	struct rrr_udpstream *data = callback_data->data;
	struct rrr_udpstream_frame_packed *frame = (struct rrr_udpstream_frame_packed *) read_session->rx_buf_ptr;

	callback_data->receive_count++;

	if (read_session->rx_buf_wpos != (ssize_t) RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame)) {
		RRR_MSG_ERR("Size mismatch in __rrr_udpstream_read_callback, packet was invalid\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	ssize_t data_size = RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame);
	if (data_size > 0) {
		if (crc32cmp (frame->data, data_size, RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame)) != 0) {
			RRR_MSG_ERR("CRC32 mismatch for data in __rrr_udpstream_read_callback\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
	}

	if ((ret = __rrr_udpstream_handle_received_frame (
			data,
			frame,
			&read_session->src_addr,
			read_session->src_addr_len,
			callback_data->control_frame_listener,
			callback_data->control_frame_listener_arg
	)) != 0) {
		RRR_MSG_ERR("Error while pushing received frame to buffer in __rrr_udpstream_read_callback\n");
		goto out;
	}

	out:
	free(read_session->rx_buf_ptr);
	read_session->rx_buf_ptr = NULL;
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
	struct rrr_udpstream_stream *stream;
	int (*validator_callback)(ssize_t *target_size, void *data, ssize_t data_size, void *arg);
	void *callback_validator_arg;
	int (*receive_callback)(void **joined_data, const struct rrr_udpstream_receive_data *receive_data, void *arg);
	void *receive_callback_arg;

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
	struct rrr_udpstream_process_receive_buffer_callback_data *data = arg;

	int ret = 0;

	// Read from the first undelivered node up to boundary to get a full original message
	RRR_LL_ITERATE_BEGIN_AT(&stream->receive_buffer, struct rrr_udpstream_frame, data->first_deliver_node, 0);
		if (node->data != NULL && node->data_size > 0) {
			memcpy (write_pos, node->data, node->data_size);
			write_pos += node->data_size;
		}

		if (node == data->last_deliver_node) {
			RRR_LL_ITERATE_LAST();

			RRR_DBG_3("UDP-stream DELIVER %u-%u %" PRIu64 "\n",
					data->stream->stream_id, node->frame_id, node->application_data);

			if (write_pos - *joined_data != data->accumulated_data_size) {
				RRR_BUG("Joined data size mismatch in __rrr_udpstream_process_receive_buffer\n");
			}

			if (data->validator_callback != NULL) {
				ssize_t target_size = 0;

				if ((ret = data->validator_callback (
						&target_size,
						*joined_data,
						data->accumulated_data_size,
						data->callback_validator_arg
				)) != 0) {
					RRR_MSG_ERR("Header validation failed of message in UDP-stream %u, data will be lost\n",
							data->stream->stream_id);
					ret = 0;
					goto loop_bottom_clenaup;
				}

				if (target_size != data->accumulated_data_size) {
					RRR_MSG_ERR("Stream error or size mismatch of received packed in UDP-stream %u, data will be lost\n",
							data->stream->stream_id);
					goto loop_bottom_clenaup;
				}
			}

			if (data->receive_callback != NULL) {
				struct rrr_udpstream_receive_data callback_data = {
						allocation_handle,
						data->accumulated_data_size,
						data->stream->connect_handle,
						data->stream->stream_id,
						node->application_data,
						node->source_addr,
						node->source_addr_len
				};

				// This function must always take care of or free memory in callback_data->data
				if (data->receive_callback (joined_data, &callback_data, data->receive_callback_arg) != 0) {
					RRR_MSG_ERR("Error from callback in __rrr_udpstream_process_receive_buffer, data might have been lost\n");
					ret = 1;
					goto out;
				}
			}

			loop_bottom_clenaup:
			data->accumulated_data_size = 0;
			data->first_deliver_node = NULL;
		}

		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->stream->receive_buffer, __rrr_udpstream_frame_destroy(node));

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
		RRR_MSG_ERR("Could not allocate memory for joined data in __rrr_udpstream_process_receive_buffer\n");
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
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		int (*allocator_callback) (
				uint32_t size,
				int (*receive_callback)(void **joined_data, void *allocation_handle, void *udpstream_callback_arg),
				void *udpstream_callback_arg,
				void *arg
		),
		void *allocator_callback_arg,
		int (*validator_callback)(ssize_t *target_size, void *data, ssize_t data_size, void *arg),
		void *validator_callback_arg,
		int (*final_callback)(void **joined_data, const struct rrr_udpstream_receive_data *receive_data, void *arg),
		void *final_callback_arg
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
			if (stream->receive_buffer.frame_id_prev_boundary_pos != 0 &&
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

		if (last_ack_id != 0 && node->frame_id - last_ack_id > 1) {
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
			ack_node = malloc(sizeof(*ack_node));
			if (ack_node == NULL) {
				RRR_MSG_ERR("Could not allocate ACK node in __rrr_udpstream_process_receive_buffer\n");
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
			RRR_MSG_ERR("Error while sending UDP-stream ACK in __rrr_udpstream_process_receive_buffer\n");
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	/*
	 * Iterate receive buffer, deliver messages in sequence and destroy delivered frames
	 */

	deliver_again:

	accumulated_data_size = 0;
	accumulated_frame_count = 0;
	first_deliver_node = NULL;
	last_deliver_node = NULL;

	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		if (node->frame_id > stream->receive_buffer.frame_id_prev_boundary_pos) {
			if (node->frame_id - stream->receive_buffer.frame_id_prev_boundary_pos > 1 + accumulated_frame_count) {
				RRR_DBG_2("UDP-stream stream-id %u frame-id %u hole in the buffer detected, cannot deliver frames yet\n",
						stream->stream_id, node->frame_id);
				// Hole in the buffer
				RRR_LL_ITERATE_BREAK();
			}
		}
		else {
			if (accumulated_data_size != 0) {
				RRR_BUG("Data accumulation started with already delivered frames in __rrr_udpstream_process_receive_buffer\n");
			}
			RRR_DBG_2("udpstream stream-id %u frame-id %u set destroy as already delivered\n",
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
			stream,
			validator_callback,
			validator_callback_arg,
			final_callback,
			final_callback_arg,
			accumulated_data_size,
			first_deliver_node,
			last_deliver_node
	};

	if ((ret = allocator_callback (
			accumulated_data_size,
			__rrr_udpstream_process_receive_buffer_callback,
			&callback_data,
			allocator_callback_arg
	)) != 0) {
		RRR_MSG_ERR("Error from allocator in __rrr_udpstream_process_receive_buffer\n");
		goto out;
	}

	goto deliver_again;

	out:
	RRR_LL_DESTROY(&ack_list, struct ack_list_node, free(node));
	return ret;
}

// Read messages from inbound buffer. The receive callback must always take care of
// memory in receive_data->data or free it, also upon errors
int rrr_udpstream_do_process_receive_buffers (
		struct rrr_udpstream *data,
		int (*allocator_callback) (
				uint32_t size,
				int (*receive_callback)(void **joined_data, void *allocation_handle, void *udpstream_callback_arg),
				void *udpstream_callback_arg,
				void *arg
		),
		void *allocator_callback_arg,
		int (*validator_callback)(ssize_t *target_size, void *data, ssize_t data_size, void *arg),
		void *validator_callback_arg,
		int (*receive_callback)(void **joined_data, const struct rrr_udpstream_receive_data *receive_data, void *arg),
		void *receive_callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if ((ret = __rrr_udpstream_process_receive_buffer (
				data,
				node,
				allocator_callback,
				allocator_callback_arg,
				validator_callback,
				validator_callback_arg,
				receive_callback,
				receive_callback_arg
		)) != 0) {
			RRR_MSG_ERR("Destroying UDP-stream with ID %u following error condition\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
			ret = 0;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));

	pthread_mutex_unlock(&data->lock);
	return ret;
}

static int __rrr_udpstream_maintain (
		struct rrr_udpstream *data
) {
	int ret = 0;

	uint64_t time_now = rrr_time_get_64();

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		uint64_t diff = time_now - node->last_seen;

		if (diff > RRR_UDPSTREAM_CONNECTION_TIMEOUT_MS * 1000 && node->invalidated == 0) {
			RRR_DBG_2("UDP-stream connection with id %u timed out, invalidating\n", node->stream_id);
			__rrr_udpstream_stream_invalidate(node);
		}
		else if (diff > RRR_UDPSTREAM_CONNECTION_INVALID_TIMEOUT_MS * 1000) {
			RRR_DBG_2("UDP-stream connection with id %u timed out after being invalid\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->hard_reset_received != 0) {
			RRR_DBG_2("UDP-stream connection with id %u removing after hard reset\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));

	return ret;
}

// Do all reading and store messages into the buffer. Control messages are
// not buffered, but delivered directly to the application layer through
// the receive_callback function.
int rrr_udpstream_do_read_tasks (
		struct rrr_udpstream *data,
		int (*control_frame_listener)(uint32_t connect_handle, uint64_t application_data, void *arg),
		void *control_frame_listener_arg
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	if ((ret = __rrr_udpstream_maintain(data)) != 0) {
		RRR_MSG_ERR("Error while maintaining streams in rrr_udpstream_do_read_tasks\n");
		goto out;
	}

	struct rrr_udpstream_read_callback_data callback_data = {
			data,
			0,
			control_frame_listener,
			control_frame_listener_arg
	};

	int errors = 0;
	do {
		if ((ret = rrr_socket_read_message_default (
				&data->read_sessions,
				data->ip.fd,
				1024,
				1024,
				RRR_READ_F_NO_SLEEPING,
				RRR_SOCKET_READ_METHOD_RECVFROM,
				__rrr_udpstream_read_get_target_size,
				data,
				__rrr_udpstream_read_callback,
				&callback_data
		)) != 0) {
			if (ret == RRR_SOCKET_READ_INCOMPLETE) {
				ret = 0;
				goto out;
			}
			else if (ret == RRR_SOCKET_SOFT_ERROR) {
				// Don't stop reading despite of clients sending bad data
				errors++;
				ret = 0;
			}
			else {
				RRR_MSG_ERR("Error while reading from socket in rrr_udpstream_read, return was %i\n", ret);
				ret = 1;
				goto out;
			}
		}
	} while (
			callback_data.receive_count + errors > 0 &&
			callback_data.receive_count + errors < RRR_UDPSTREAM_BURST_LIMIT_RECEIVE
	);

	RRR_DBG_3 ("UDP-stream RECV cnt: %i, err cnt: %i\n", callback_data.receive_count, errors);

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

static int __rrr_udpstream_send_frame_to_remote (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *frame
) {
	struct rrr_udpstream_frame_packed frame_packed = {0};

	frame_packed.version = RRR_UDPSTREAM_VERSION;
	frame_packed.frame_id = htobe32(frame->frame_id);
	frame_packed.flags_and_type = frame->flags_and_type;
	frame_packed.stream_id = htobe16(stream->stream_id);
	frame_packed.application_data = htobe64(frame->application_data);

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

static int __rrr_udpstream_send_loop (
		int *sent_count_return,
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream
) {
	uint64_t time_now = rrr_time_get_64();

	*sent_count_return = 0;

	int ret = 0;

	int sent_count = 0;
	int64_t missing_ack_count = 0;
	int64_t resend_count = 0;
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
			resend_count++;
		}
		else {
			missing_ack_count++;
		}

		if (do_send != 0) {
			if ((ret = __rrr_udpstream_send_frame_to_remote(data, stream, node)) != 0) {
				RRR_MSG_ERR("Could not send frame in __rrr_udpstream_send_loop\n");
				ret = 1;
				goto out;
			}
			node->unacknowledged_count = 0;
			node->last_send_time = rrr_time_get_64();
			sent_count++;
			if (sent_count >= RRR_UDPSTREAM_BURST_LIMIT_SEND) {
				RRR_LL_ITERATE_LAST();
			}
		}
	RRR_LL_ITERATE_END();

//	VL_DEBUG_MSG_2("udpstream stream-id %u missing ACK count %i window size %i\n",
//			stream->stream_id, missing_ack_count, stream->window_size);

	*sent_count_return = sent_count;

	out:
	return ret;
}

// Send out buffered messages from outbound buffer
int rrr_udpstream_do_send_tasks (
		int *send_count,
		struct rrr_udpstream *data
) {
	int ret = 0;

	*send_count = 0;

	pthread_mutex_lock(&data->lock);

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		int count = 0;
		if ((ret = __rrr_udpstream_send_loop(&count, data, node)) != 0) {
			goto out;
		}
		*send_count += count;
	RRR_LL_ITERATE_END();

	out:
	pthread_mutex_unlock(&data->lock);
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

	pthread_mutex_lock(&data->lock);

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
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connection_check (
		struct rrr_udpstream *data,
		uint32_t connect_handle
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_UNKNOWN_CONNECT_ID;
		goto out;
	}

	if (stream->stream_id == 0) {
//		VL_DEBUG_MSG_2("Check connection stream id %u connect handle %u: Not ready\n",
//			stream->stream_id, stream->connect_handle);
		ret = RRR_UDPSTREAM_NOT_READY;
	}

	if (stream->send_buffer.frame_id_counter >= stream->send_buffer.frame_id_max) {
		ret = RRR_UDPSTREAM_RESET;
	}

	out:
	pthread_mutex_unlock(&data->lock);
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

	pthread_mutex_lock(&udpstream_data->lock);

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_UNKNOWN_CONNECT_ID;
		goto out;
	}
	if (stream->stream_id == 0) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	stream->window_size_regulation_from_application += window_size_change;

	RRR_DBG_3("UDP-stream WS REQ %u change %i\n", stream->stream_id, window_size_change);

	out:
	pthread_mutex_unlock(&udpstream_data->lock);
	return ret;
}

// Send a control frame immediately, by-passing buffer
int rrr_udpstream_send_control_frame (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		uint64_t application_data
) {
	int ret = 0;

	pthread_mutex_lock(&udpstream_data->lock);

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_UNKNOWN_CONNECT_ID;
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

	if ((ret = __rrr_udpstream_send_frame_to_remote (udpstream_data, stream, &frame)) != 0) {
		RRR_MSG_ERR("Could not send control frame in rrr_udpstream_send_control_frame for stream with connect handle %u\n",
				connect_handle);
		goto out;
	}

	out:
	pthread_mutex_unlock(&udpstream_data->lock);
	return ret;
}

// Put messages into outbound buffer
int rrr_udpstream_queue_outbound_data (
		struct rrr_udpstream *udpstream_data,
		uint32_t connect_handle,
		const void *data,
		ssize_t data_size,
		uint64_t application_data
) {
	int ret = 0;

	pthread_mutex_lock(&udpstream_data->lock);

	struct rrr_udpstream_stream *stream = __rrr_udpstream_find_stream_by_connect_handle(udpstream_data, connect_handle);
	if (stream == NULL) {
		ret = RRR_UDPSTREAM_UNKNOWN_CONNECT_ID;
		goto out;
	}

	if (stream->stream_id == 0) {
		ret = RRR_UDPSTREAM_NOT_READY;
		goto out;
	}

	if (RRR_LL_COUNT(&stream->send_buffer) >= RRR_UDPSTREAM_BUFFER_LIMIT) {
//		VL_DEBUG_MSG_3("Buffer is full with %i items for udpstream stream-id %u\n",
//				RRR_LL_COUNT(&stream->send_buffer), stream->stream_id);
		ret = RRR_UDPSTREAM_BUFFER_FULL;
		goto out;
	}

	if (stream->send_buffer.frame_id_counter + ((data_size / RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT) + 1) > stream->send_buffer.frame_id_max) {
		RRR_DBG_2("UDP-stream frame IDs exhausted for stream-id %u\n", stream->stream_id);
		ret = RRR_UDPSTREAM_IDS_EXHAUSTED;
		goto out;
	}

//	if (stream->send_buffer.frame_id_counter > RRR_UDPSTREAM_FRAME_ID_MAX) {
//		VL_BUG("Frame IDs exhausted in __rrr_udpstream_send_loop\n");
//	}

	const void *pos = data;
	struct rrr_udpstream_frame *new_frame = NULL;
	while (data_size > 0) {
		uint16_t chunk_size = (data_size > RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT ? RRR_UDPSTREAM_FRAME_DATA_SIZE_LIMIT : data_size);
		new_frame = NULL;
		if ((ret = __rrr_udpstream_frame_new_from_data(&new_frame, pos, chunk_size)) != 0) {
			RRR_MSG_ERR("Could not allocate frame in rrr_udpstream_queue_outbound_data\n");
			ret = RRR_UDPSTREAM_ERR;
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

	out:
	pthread_mutex_unlock(&udpstream_data->lock);
	return ret;
}

void rrr_udpstream_close (
		struct rrr_udpstream *data
) {
	pthread_mutex_lock(&data->lock);
	rrr_ip_network_cleanup(&data->ip);
	pthread_mutex_unlock(&data->lock);
}

int rrr_udpstream_bind (
		struct rrr_udpstream *data,
		unsigned int local_port
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	if (data->ip.fd != 0) {
		RRR_BUG("rrr_udpstream_bind called with non-zero fd, bind already complete\n");
	}

	data->ip.port = local_port;

	if (rrr_ip_network_start_udp_ipv4 (&data->ip) != 0) {
		RRR_MSG_ERR("Could not start IP in rrr_udpstream_bind\n");
		ret = 1;
		goto out;
	}

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connect_raw (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	if (data->ip.fd == 0) {
		RRR_BUG("FD was 0 in rrr_udpstream_connect_raw, must bind first\n");
	}

	if ((ret = __rrr_udpstream_send_connect(connect_handle, data, addr, socklen)) != 0) {
		RRR_MSG_ERR("Could not send connect packet in rrr_udpstream_connect_raw\n");
		goto out;
	}

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connect (
		uint32_t *connect_handle,
		struct rrr_udpstream *data,
		const char *remote_host,
		const char *remote_port
) {
	int ret = 0;
	struct addrinfo *res = NULL;

	if (data->ip.fd == 0) {
		RRR_BUG("FD was 0 in rrr_udpstream_connect, must bind first\n");
	}

	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(remote_host, remote_port, &hints, &res);
	if (ret != 0) {
		RRR_MSG_ERR ("Could not get address info of server %s port %s in rrr_udpstream_connect: %s\n",
				remote_host, remote_port, gai_strerror(ret));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_udpstream_connect_raw(connect_handle, data, res->ai_addr, res->ai_addrlen)) != 0) {
		RRR_MSG_ERR("Could not send connect packet in rrr_udpstream_connect\n");
		goto out;
	}

	out:
	if (res != NULL) {
		freeaddrinfo(res);
	}
	pthread_mutex_unlock(&data->lock);
	return ret;
}

void rrr_udpstream_dump_stats (
	struct rrr_udpstream *data
) {
	pthread_mutex_lock(&data->lock);

	RRR_DBG("UDP-stream streams: %i, read sessions: %i\n",
			RRR_LL_COUNT(&data->streams), RRR_LL_COUNT(&data->read_sessions));

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		RRR_DBG(" - Stream %i: recv buf %i delivered id pos %u, send buf %i id pos %u window size f/t %" PRIu32 "/%" PRIu32 " invalid %i\n",
				node->stream_id,
				RRR_LL_COUNT(&node->receive_buffer),
				node->receive_buffer.frame_id_prev_boundary_pos,
				RRR_LL_COUNT(&node->send_buffer),
				node->send_buffer.frame_id_counter,
				node->window_size_from_remote,
				node->window_size_to_remote,
				node->invalidated
		);
	RRR_LL_ITERATE_END();

	pthread_mutex_unlock(&data->lock);
}
