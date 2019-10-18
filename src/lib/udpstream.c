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

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>

#include "../global.h"
#include "udpstream.h"
#include "rrr_socket.h"
#include "rrr_socket_read.h"
#include "linked_list.h"
#include "vl_time.h"
#include "crc32.h"

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
		VL_MSG_ERR("Could not allocate memory in __rrr_udpstream_frame_new_from_data A\n");
		ret = 1;
		goto out;
	}
	memset(res, '\0', sizeof(*res));

	if (data_size > RRR_UDPSTREAM_FRAME_SIZE_MAX) {
		VL_BUG("Data size was exceeds maximum in __rrr_udpstream_frame_new_from_data\n");
	}

	if (data_size > 0) {
		res->data = malloc(data_size);
		if (res->data == NULL) {
			VL_MSG_ERR("Could not allocate memory in __rrr_udpstream_frame_new_from_data B\n");
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
			VL_MSG_ERR("Could not allocate memory for address in __rrr_udpstream_frame_new_from_packed\n");
			ret = 1;
			goto out;
		}
		memcpy(result->source_addr, addr, addr_len);
	}

	result->source_addr_len = addr_len;
	result->flags = RRR_UDPSTREAM_FRAME_FLAGS(template);
	result->frame_id = RRR_UDPSTREAM_FRAME_PACKED_FRAME_ID(template);
	result->stream_id = RRR_UDPSTREAM_FRAME_PACKED_STREAM_ID(template);

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
	target->frame_id_max = RRR_UDPSTREAM_FRAME_ID_MAX;
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
		VL_MSG_ERR("Could not allocate memory in __rrr_udpstream_stream_new\n");
		return 1;
	}
	memset(res, '\0', sizeof(*res));

	__rrr_udpstream_frame_buffer_init(&res->receive_buffer);
	__rrr_udpstream_frame_buffer_init(&res->send_buffer);

	res->last_seen = time_get_64();

	*target = res;

	return 0;
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
	rrr_socket_read_session_collection_clear(&data->read_sessions);
	__rrr_udpstream_stream_collection_clear(&data->streams);
	pthread_mutex_destroy(&data->lock);
}

void rrr_udpstream_init (
		struct rrr_udpstream *data,
		int flags
) {
	memset (data, '\0', sizeof(*data));
	data->flags = flags;
	__rrr_udpstream_stream_collection_init(&data->streams);
	rrr_socket_read_session_collection_init(&data->read_sessions);
	pthread_mutex_init(&data->lock, 0);
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
		uint16_t data_size
) {
	int ret = 0;

	if (addr == NULL) {
		VL_BUG("addr was NULL in __rrr_udpstream_checksum_and_send_packed_frame\n");
	}

	// A packed frame created locally has the payload stored separately
	if (data_size > 0) {
		frame->data_crc32 = htobe32(crc32buf((char *) data, data_size));
		frame->data_size = htobe16(data_size);
	}

	char *crc32_start_pos = ((char *) frame) + sizeof(frame->header_crc32);
	ssize_t crc32_size = sizeof(*frame) - sizeof(frame->header_crc32) - 1;

	frame->header_crc32 = htobe32(crc32buf(crc32_start_pos, crc32_size));

//	printf ("packed crc32: %" PRIu32 " size: %u\n", frame->header_crc32, be16toh(frame->data_size));

	if ((ret = ip_send_raw(udpstream_data->ip.fd, addr, addrlen, frame, sizeof(*frame) - 1)) != 0) {
		VL_MSG_ERR("Could not send packed frame header in __rrr_udpstream_send_packed_frame\n");
		ret = 1;
		goto out;
	}

	if (data_size > 0) {
		if ((ret = ip_send_raw(udpstream_data->ip.fd, addr, addrlen, data, data_size)) != 0) {
			VL_MSG_ERR("Could not send packed frame payload in __rrr_udpstream_send_packed_frame\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static struct rrr_udpstream_stream *__rrr_udpstream_create_and_add_stream (
		struct rrr_udpstream *data
) {
	struct rrr_udpstream_stream *new_stream = NULL;

	if (__rrr_udpstream_stream_new(&new_stream) != 0) {
		return NULL;
	}

	RRR_LL_PUSH(&data->streams, new_stream);

	return new_stream;
}

static uint16_t __rrr_udpstream_allocate_stream_id (
		struct rrr_udpstream *data
) {
	uint16_t ret = 0;

	for (int retries = 0xffff; retries > 0; retries--) {
		if (data->next_stream_id == 0) {
			data->next_stream_id++;
		}

		int collission = 0;
		RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
			if (node->stream_id == data->next_stream_id) {
				collission = 1;
				RRR_LL_ITERATE_BREAK();
			}
		RRR_LL_ITERATE_END(&data->streams);
		if (collission == 0) {
			ret = data->next_stream_id;
			break;
		}

		data->next_stream_id++;
	}

	data->next_stream_id++;
	return ret;
}

static int __rrr_udpstream_send_ack (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t frame_id
) {
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags = RRR_UDPSTREAM_FRAME_FLAGS_ACK;
	frame.stream_id = htobe16(stream_id);
	frame.frame_id = htobe16(frame_id);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0);
}

static int __rrr_udpstream_send_reset (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint32_t frame_id
) {
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags = RRR_UDPSTREAM_FRAME_FLAGS_RESET;
	frame.stream_id = htobe16(stream_id);

	// If frame ID is zero, remote should perform a hard reset which implies creating a
	// new connection and sending any data in send buffers again
	frame.frame_id = htobe16(frame_id);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0);
}

static uint16_t __rrr_udpstream_allocate_connect_handle (
		struct rrr_udpstream *data
) {
	for (int retries = 0xffff; retries > 0; retries--) {
		uint16_t ret = (uint16_t) rand();
		int collission = 0;
		RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
			if (node->connect_handle == ret) {
				collission = 1;
				RRR_LL_ITERATE_BREAK();
			}
		RRR_LL_ITERATE_END(&data->streams);
		if (collission == 0) {
			return ret;
		}
	}

	return 0;
}

static int __rrr_udpstream_send_connect_response (
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t socklen,
		uint16_t stream_id,
		uint16_t connect_handle
) {
	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags = RRR_UDPSTREAM_FRAME_FLAGS_CONNECT;
	frame.stream_id = htobe16(stream_id);
	frame.connect_handle = htobe16(connect_handle);

	return __rrr_udpstream_checksum_and_send_packed_frame(data, addr, socklen, &frame, NULL, 0);
}

static int __rrr_udpstream_send_connect (
		uint16_t *connect_handle_result,
		struct rrr_udpstream *data,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	*connect_handle_result = 0;

	uint16_t connect_handle = __rrr_udpstream_allocate_connect_handle(data);
	if (connect_handle == 0) {
		VL_MSG_ERR("Could not allocate connect handle in __rrr_udpstream_send_connect\n");
		ret = 1;
		goto out;
	}

	struct rrr_udpstream_frame_packed frame = {0};

	frame.flags = RRR_UDPSTREAM_FRAME_FLAGS_CONNECT;
	frame.connect_handle = htobe16(connect_handle);

	struct rrr_udpstream_stream *stream = NULL;
	if ((stream = __rrr_udpstream_create_and_add_stream(data)) == NULL) {
		VL_MSG_ERR("Could not add stream to collection in __rrr_udpstream_send_connect\n");
		ret = 1;
		goto out;
	}

	stream->connect_handle = connect_handle;
	stream->remote_addr_len = addr_len;
	stream->remote_addr = malloc(stream->remote_addr_len);
	if (stream->remote_addr == NULL) {
		VL_MSG_ERR("Could not allocate memory for address in __rrr_udpstream_send_connect\n");
	}
	memcpy(stream->remote_addr, addr, stream->remote_addr_len);

	if (__rrr_udpstream_checksum_and_send_packed_frame(data, stream->remote_addr, stream->remote_addr_len, &frame, NULL, 0) != 0) {
		VL_MSG_ERR("Could not send CONNECT packet in __rrr_udpstream_send_connect\n");
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_2("Sent CONNECT with handle %" PRIu16 "\n", connect_handle);

	*connect_handle_result = connect_handle;

	out:
	return ret;
}

static int __rrr_udpstream_frame_packed_validate (
		struct rrr_udpstream_frame_packed *frame
) {
	uint32_t header_crc32 = RRR_UDPSTREAM_FRAME_PACKED_HEADER_CRC32(frame);

//	printf ("packed crc32 receive: %" PRIu32 "\n", frame->header_crc32);
//	printf ("packed crc32 receive bswapped: %" PRIu32 "\n", header_crc32);

	char *crc32_start_pos = ((char *) frame) + sizeof(frame->header_crc32);
	ssize_t crc32_size = sizeof(*frame) - sizeof(frame->header_crc32) - 1;

	if (crc32cmp(crc32_start_pos, crc32_size, header_crc32) != 0) {
		VL_MSG_ERR("CRC32 mismatch in __rrr_udpstream_frame_pack_validate\n");
		return 1;
	}

	return 0;
}

static int __rrr_udpstream_read_get_target_size (
		struct rrr_socket_read_session *read_session,
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
		VL_MSG_ERR("Could not validate received frame in __rrr_udpstream_read_get_target_size\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

//	printf ("Data size: %u\n", frame->data_size);
	ssize_t total_size = RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame);

	if (total_size > RRR_UDPSTREAM_FRAME_SIZE_MAX) {
		VL_MSG_ERR("UDP-stream received frame size exceeded maximum (%li > %i)\n", total_size, RRR_UDPSTREAM_FRAME_SIZE_MAX);
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	read_session->target_size = total_size;

	out:
	return ret;
}

static struct rrr_udpstream_stream *__rrr_udpstream_find_stream_by_connect_handle (
		struct rrr_udpstream *data,
		uint16_t connect_handle
) {
	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if (node->connect_handle == connect_handle) {
			return node;
		}
	RRR_LL_ITERATE_END(&data->streams);
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
	RRR_LL_ITERATE_END(&data->streams);
	return NULL;
}

static int __rrr_udpstream_handle_received_connect (
		struct rrr_udpstream *data,
		struct rrr_udpstream_frame *new_frame,
		const struct sockaddr *src_addr,
		socklen_t addr_len
) {
	int ret = 0;

	struct rrr_udpstream_stream *stream = NULL;

	if (new_frame->data_size != 0) {
		VL_DEBUG_MSG_3("Received UDP-stream CONNECT packet with non-zero payload\n");
		goto out;
	}
	stream = __rrr_udpstream_find_stream_by_connect_handle(data, new_frame->connect_handle);
	if (stream != NULL && stream->stream_id == 0) {
		// We are expecting CONNECT response
		if (stream->remote_addr_len != addr_len || memcmp(stream->remote_addr, src_addr, addr_len) != 0) {
			VL_MSG_ERR("Received CONNECT response from unexpected remote host\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		if (new_frame->stream_id == 0) {
			VL_MSG_ERR("Received zero stream ID in CONNECT response in __rrr_udpstream_handle_received_connect, connection was rejected\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		stream->stream_id = new_frame->stream_id;

		VL_DEBUG_MSG_2("Outbound UDP-stream connection established with stream id %u connect handle was %u\n",
				stream->stream_id, new_frame->connect_handle);
	}
	else {
		if ((data->flags & RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS) == 0) {
			VL_MSG_ERR("Received CONNECT packet in __rrr_udpstream_handle_received_frame, but we are not expecting CONNECT response nor accepting connections\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		// If stream id is zero, we cannot accept more connections and the connection is rejected
		uint16_t stream_id = __rrr_udpstream_allocate_stream_id(data);
		if (stream_id > 0) {
			if ((stream = __rrr_udpstream_create_and_add_stream(data)) == NULL) {
				VL_MSG_ERR("Could not push new connection to buffer collections in __rrr_udpstream_handle_received_connect\n");
				ret = RRR_SOCKET_HARD_ERROR;
				goto out;
			}

			// We do not store the address of the remote client. The receive function callback
			// receives the currently used sender address for every message.
			stream->stream_id = stream_id;
			stream->connect_handle = new_frame->connect_handle;

			VL_DEBUG_MSG_2("Incoming UDP-stream connection established with stream id %u\n", stream_id);
		}
		else {
			// This is not considered an error
			VL_DEBUG_MSG_2("Incoming UDP-stream connection rejected\n");
		}

		if (__rrr_udpstream_send_connect_response(data, src_addr, addr_len, stream_id, new_frame->connect_handle) != 0) {
			VL_MSG_ERR("Could not send connect response in __rrr_udpstream_handle_received_connect\n");
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

	VL_DEBUG_MSG_3("Received UDP-stream packet with RESET for stream ID %u\n", new_frame->stream_id);

	if (new_frame->frame_id == 0) {
		VL_DEBUG_MSG_3("Performing hard reset for stream ID %u\n", new_frame->stream_id);

		stream->receive_buffer.frame_id_max = stream->receive_buffer.frame_id_counter;
		stream->send_buffer.frame_id_max = stream->send_buffer.frame_id_counter;
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

static int __rrr_udpstream_handle_received_ack (
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *new_frame
) {
	int ret = 0;

	VL_DEBUG_MSG_3("Received UDP-stream packet with ACK for stream ID %u frame %u\n",
			new_frame->stream_id, new_frame->frame_id);

	RRR_LL_ITERATE_BEGIN(&stream->send_buffer, struct rrr_udpstream_frame);
		if (node->frame_id <= new_frame->frame_id) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else {
			node->unacknowledged_count++;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->send_buffer, __rrr_udpstream_frame_destroy(node));

	return ret;
}

static int __rrr_udpstream_handle_received_frame (
		struct rrr_udpstream *data,
		const struct rrr_udpstream_frame_packed *frame,
		const struct sockaddr *src_addr,
		socklen_t addr_len
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream_frame *new_frame = NULL;

	if (__rrr_udpstream_frame_new_from_packed(&new_frame, frame, src_addr, addr_len) != 0) {
		VL_MSG_ERR("Could not allocate internal frame in __rrr_udpstream_handle_received_frame\n");
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_CONNECT(new_frame)) {
		ret = __rrr_udpstream_handle_received_connect(data, new_frame, src_addr, addr_len);
		goto out;
	}

	if (new_frame->stream_id == 0) {
		VL_DEBUG_MSG_3("Unknown packet with flags %u and zero stream id in __rrr_udpstream_handle_received_frame\n", new_frame->flags);
		goto out;
	}

	struct rrr_udpstream_stream *stream = NULL;
	if ((stream = __rrr_udpstream_find_stream_by_stream_id(data, new_frame->stream_id)) == NULL) {
		VL_DEBUG_MSG_3("Received UDP-stream packet with unknown stream ID %u, sending hard reset\n", new_frame->stream_id);
		if (__rrr_udpstream_send_reset(data, src_addr, addr_len, new_frame->stream_id, 0) != 0) {
			VL_MSG_ERR("Could not send UDP-stream hard reset in __rrr_udpstream_handle_received_frame\n");
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}
		goto out;
	}

	stream->last_seen = time_get_64();

	if (RRR_UDPSTREAM_FRAME_IS_RESET(frame)) {
		ret = __rrr_udpstream_handle_received_reset(stream, new_frame);
		goto out;
	}

	if (new_frame->frame_id == 0) {
		VL_DEBUG_MSG_3("Unknown packet with flags %u and zero frame id in __rrr_udpstream_handle_received_frame\n", new_frame->flags);
		goto out;
	}

	if (RRR_UDPSTREAM_FRAME_IS_ACK(frame)) {
		ret = __rrr_udpstream_handle_received_ack(stream, new_frame);
		goto out;
	}

	VL_DEBUG_MSG_3("Received UDP-stream packet with data for stream ID %u frame id %u\n",
			new_frame->stream_id, new_frame->frame_id);

	if (stream->receive_buffer.frame_id_counter == 0) {
		stream->receive_buffer.frame_id_counter = 1;
	}

	if (new_frame->frame_id == stream->receive_buffer.frame_id_counter) {
		stream->receive_buffer.frame_id_counter++;
		goto out_append;
	}
	else if (new_frame->frame_id <= stream->receive_buffer.frame_id_ack_pos) {
		// Already received
		goto out;
	}

	uint32_t frame_id_max = 0;
	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		if (node->frame_id == new_frame->frame_id) {
			// Already received
			goto out;
		}
		if (node->frame_id > new_frame->frame_id) {
			RRR_LL_ITERATE_INSERT(&stream->receive_buffer, new_frame);
			new_frame = NULL;
			goto out;
		}
		if (node->frame_id < frame_id_max) {
			VL_BUG("Order error in receive buffer in __rrr_udpstream_handle_received_frame\n");
		}
		frame_id_max = node->frame_id;
	RRR_LL_ITERATE_END(&stream->receive_buffer);

	out_append:
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
};

static int __rrr_udpstream_read_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	int ret = RRR_SOCKET_OK;

	struct rrr_udpstream_read_callback_data *callback_data = arg;
	struct rrr_udpstream *data = callback_data->data;
	struct rrr_udpstream_frame_packed *frame = (struct rrr_udpstream_frame_packed *) read_session->rx_buf_ptr;

	callback_data->receive_count++;

	if (read_session->rx_buf_wpos != (ssize_t) RRR_UDPSTREAM_FRAME_PACKED_TOTAL_SIZE(frame)) {
		VL_MSG_ERR("Size mismatch in __rrr_udpstream_read_callback, packet was invalid\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	ssize_t data_size = RRR_UDPSTREAM_FRAME_PACKED_DATA_SIZE(frame);
	if (data_size > 0) {
		if (crc32cmp (frame->data, data_size, RRR_UDPSTREAM_FRAME_PACKED_DATA_CRC32(frame)) != 0) {
			VL_MSG_ERR("CRC32 mismatch for data in __rrr_udpstream_read_callback\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
	}

	if ((ret = __rrr_udpstream_handle_received_frame (
			data,
			frame,
			&read_session->src_addr,
			read_session->src_addr_len
	)) != 0) {
		VL_MSG_ERR("Error while pushing received frame to buffer in __rrr_udpstream_read_callback\n");
		goto out;
	}

	out:
	free(read_session->rx_buf_ptr);
	read_session->rx_buf_ptr = NULL;
	return ret;
}

static int __rrr_udpstream_process_receive_buffer (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		int (*callback_validator)(ssize_t *target_size, void *data, ssize_t data_size, void *arg),
		void *callback_validator_arg,
		int (*callback)(struct rrr_udpstream_receive_data *receive_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	void *joined_data = NULL;

	struct sockaddr *ack_addr = NULL;
	socklen_t ack_addr_len = 0;

	uint16_t prev_frame_id = 0;
	uint32_t accumulated_data_size = 0;
	RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
		if (prev_frame_id != 0 && node->frame_id - prev_frame_id > 1) {
			// Hole in the buffer, send ACK for packets up to this point
			RRR_LL_ITERATE_BREAK();
		}

		accumulated_data_size += node->data_size;
		if (RRR_UDPSTREAM_FRAME_IS_BOUNDARY(node)) {
			struct rrr_udpstream_frame *last_node = node;

			RRR_FREE_IF_NOT_NULL(joined_data);
			if ((joined_data = malloc(accumulated_data_size)) == NULL) {
				VL_MSG_ERR("Could not allocate memory for joined data in __rrr_udpstream_process_receive_buffer\n");
				ret = 1;
				goto out;
			}

			void *write_pos = joined_data;
			// Read from the beginning and up to boundary to get a full original message
			RRR_LL_ITERATE_BEGIN(&stream->receive_buffer, struct rrr_udpstream_frame);
				if (node->data != NULL && node->data_size > 0) {
					memcpy (write_pos, node->data, node->data_size);
					write_pos += node->data_size;
				}
				if (node == last_node) {
					// Don't destroy node in this loop, will break wrapping loop
					RRR_LL_ITERATE_LAST();
				}
				else {
					RRR_LL_ITERATE_SET_DESTROY();
				}
			RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->receive_buffer, __rrr_udpstream_frame_destroy(node));

			if (write_pos - joined_data != accumulated_data_size) {
				VL_BUG("Joined data size mismatch in __rrr_udpstream_process_receive_buffer\n");
			}

			ssize_t target_size = 0;
			if ((ret = callback_validator (
					&target_size,
					joined_data,
					accumulated_data_size,
					callback_validator_arg
			)) != 0) {
				VL_MSG_ERR("Header validation failed of message in UDP-stream %u, data will be lost\n", stream->stream_id);
				ret = 0;
			}
			else {
				if (target_size != accumulated_data_size) {
					VL_MSG_ERR("Stream error or size mismatch of received packed in UDP-stream %u, data will be lost\n", stream->stream_id);
				}
				else {
					// This function must always take care of or free memory
					struct rrr_udpstream_receive_data callback_data = {
							joined_data,
							accumulated_data_size,
							stream->connect_handle,
							node->source_addr,
							node->source_addr_len
					};
					if (callback (&callback_data, callback_arg) != 0) {
						VL_MSG_ERR("Error from callback in __rrr_udpstream_process_receive_buffer, data might have been lost\n");
						ret = 1;
						// Do not goto out, we should destroy the current node and set data pointer to NULL
						RRR_LL_ITERATE_LAST();
					}
					joined_data = NULL;
				}
			}

			if (ack_addr == NULL || ack_addr_len != node->source_addr_len || memcmp(ack_addr, node->source_addr, ack_addr_len) != 0) {
				RRR_FREE_IF_NOT_NULL(ack_addr);
				ack_addr_len = node->source_addr_len;
				if ((ack_addr = malloc(ack_addr_len)) == NULL) {
					VL_MSG_ERR("Could not allocate memory for ACK address in __rrr_udpstream_process_receive_buffer\n");
					ret = 1;
					goto out;
				}
				memcpy(ack_addr, node->source_addr, ack_addr_len);
			}

			accumulated_data_size = 0;

			RRR_LL_ITERATE_SET_DESTROY();
		}

		prev_frame_id = node->frame_id;
	RRR_LL_ITERATE_END_CHECK_DESTROY(&stream->receive_buffer, __rrr_udpstream_frame_destroy(node));

	if (prev_frame_id > 0 && prev_frame_id) {
		const struct sockaddr *use_addr = stream->remote_addr;
		socklen_t use_sockaddr_len = stream->remote_addr_len;

		if (use_addr == NULL) {
			use_addr = ack_addr;
			use_sockaddr_len = ack_addr_len;
		}

		if (__rrr_udpstream_send_ack(data, use_addr, use_sockaddr_len, stream->stream_id, prev_frame_id) != 0) {
			VL_MSG_ERR("Error while sending UDP-stream ACK in __rrr_udpstream_process_receive_buffer\n");
			ret = 1;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(ack_addr);
	RRR_FREE_IF_NOT_NULL(joined_data);
	return ret;
}

int rrr_udpstream_do_process_receive_buffers (
		struct rrr_udpstream *data,
		int (*callback_validator)(ssize_t *target_size, void *data, ssize_t data_size, void *arg),
		void *callback_validator_arg,
		int (*callback)(struct rrr_udpstream_receive_data *receive_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if ((ret = __rrr_udpstream_process_receive_buffer (
				data,
				node,
				callback_validator,
				callback_validator_arg,
				callback,
				callback_arg
		)) != 0) {
			VL_MSG_ERR("Destroying UDP-stream with ID %u following error condition\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
			ret = 0;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));

	pthread_mutex_unlock(&data->lock);
	return ret;
}

static void __rrr_udpstream_maintain (
		struct rrr_udpstream *data
) {
	uint64_t time_now = time_get_64();

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		uint64_t diff = time_now - node->last_seen;
		if (diff > RRR_UDPSTREAM_TIMEOUT_MS * 1000) {
			VL_DEBUG_MSG_3("UDP-stream connection with id %u timed out\n", node->stream_id);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->streams, __rrr_udpstream_stream_destroy(node));
}

int rrr_udpstream_do_read_tasks (
		struct rrr_udpstream *data
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	__rrr_udpstream_maintain(data);

	struct rrr_udpstream_read_callback_data callback_data = {
			data,
			0
	};

	int errors = 0;
	do {
		if ((ret = rrr_socket_read_message (
				&data->read_sessions,
				data->ip.fd,
				1024,
				1024,
				RRR_SOCKET_READ_NO_SLEEPING | RRR_SOCKET_READ_METHOD_RECVFROM,
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
				VL_MSG_ERR("Error while reading from socket in rrr_udpstream_read, return was %i\n", ret);
				ret = 1;
				goto out;
			}
		}
	} while (callback_data.receive_count + errors > 0 && callback_data.receive_count + errors < RRR_UDPSTREAM_BURST_RECEIVE_MAX);

	VL_DEBUG_MSG_3 ("Receive count: %i, Error count: %i\n", callback_data.receive_count, errors);

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

static int __rrr_udpstream_send_frame_to_server (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream,
		struct rrr_udpstream_frame *frame
) {
	struct rrr_udpstream_frame_packed frame_packed = {0};

	frame_packed.version = RRR_UDPSTREAM_VERSION;
	frame_packed.frame_id = htobe16(frame->frame_id);
	frame_packed.flags = frame->flags;
	frame_packed.stream_id = htobe16(stream->stream_id);

	return __rrr_udpstream_checksum_and_send_packed_frame (
			data,
			stream->remote_addr,
			stream->remote_addr_len,
			&frame_packed,
			frame->data,
			frame->data_size
	);
}

static int __rrr_udpstream_send_loop (
		struct rrr_udpstream *data,
		struct rrr_udpstream_stream *stream
) {
	uint64_t time_now = time_get_64();

	int ret = 0;

	int old_frames_found = 0;
	RRR_LL_ITERATE_BEGIN(&stream->send_buffer, struct rrr_udpstream_frame);
		int do_send = 0;

		if (node->frame_id == 0) {
			VL_BUG("Frame ID was 0 in __rrr_udpstream_send_loop\n");
		}

		if (node->last_send_time == 0) {
			if (old_frames_found == 0) {
				do_send = 1;
			}
		}
		else if (time_now - node->last_send_time > RRR_UDPSTREAM_RESEND_INTERVAL_MS * 1000 ||
				node->unacknowledged_count >= RRR_UDPSTREAM_UNACKNOWLEDGED_LIMIT
		) {
			old_frames_found = 1;
			do_send = 1;
		}

		if (do_send != 0) {
			if ((ret = __rrr_udpstream_send_frame_to_server(data, stream, node)) != 0) {
				VL_MSG_ERR("Could not send frame in __rrr_udpstream_send_loop\n");
				ret = 1;
				goto out;
			}
			node->unacknowledged_count = 0;
			node->last_send_time = time_get_64();
		}
	RRR_LL_ITERATE_END(&stream->send_buffer);

	out:
	return ret;
}

int rrr_udpstream_do_send_tasks (
		struct rrr_udpstream *data
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	RRR_LL_ITERATE_BEGIN(&data->streams, struct rrr_udpstream_stream);
		if ((ret = __rrr_udpstream_send_loop(data, node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END(&data->streams);

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connection_check (
		struct rrr_udpstream *data,
		uint16_t connect_handle
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

int rrr_udpstream_queue_outbound_data (
		struct rrr_udpstream *udpstream_data,
		uint16_t connect_handle,
		const void *data,
		ssize_t data_size
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

	stream->last_seen = time_get_64();

	if (RRR_LL_COUNT(&stream->send_buffer) > RRR_UDPSTREAM_BUFFER_MAX) {
//		VL_DEBUG_MSG_2("Buffer is full for udpstream stream-id %u\n", stream->stream_id);
		ret = RRR_UDPSTREAM_BUFFER_FULL;
		goto out;
	}

	if (stream->send_buffer.frame_id_counter + ((data_size / RRR_UDPSTREAM_FRAME_SIZE_MAX) + 1) > stream->send_buffer.frame_id_max) {
		VL_DEBUG_MSG_2("Frame IDs exhausted for udpstream stream-id %u\n", stream->stream_id);
		ret = RRR_UDPSTREAM_FRAME_ID_MAX;
		goto out;
	}

	if (stream->send_buffer.frame_id_counter > RRR_UDPSTREAM_FRAME_ID_MAX) {
		VL_BUG("Frame IDs exhausted in __rrr_udpstream_send_loop\n");
	}

	const void *pos = data;
	struct rrr_udpstream_frame *new_frame = NULL;
	while (data_size > 0) {
		uint16_t chunk_size = (data_size > RRR_UDPSTREAM_FRAME_SIZE_MAX ? RRR_UDPSTREAM_FRAME_SIZE_MAX : data_size);
		new_frame = NULL;
		if ((ret = __rrr_udpstream_frame_new_from_data(&new_frame, pos, chunk_size)) != 0) {
			VL_MSG_ERR("Could not allocate frame in rrr_udpstream_send\n");
			ret = RRR_UDPSTREAM_ERR;
			goto out;
		}

		new_frame->frame_id = ++(stream->send_buffer.frame_id_counter);

		RRR_LL_APPEND(&stream->send_buffer, new_frame);

		pos += chunk_size;
		data_size -= chunk_size;
	}

	// Set boundary flag on last frame
	if (new_frame != NULL) {
		new_frame->flags |= RRR_UDPSTREAM_FRAME_FLAGS_BOUNDARY;
	}

	out:
	pthread_mutex_unlock(&udpstream_data->lock);
	return ret;
}

void rrr_udpstream_close (
		struct rrr_udpstream *data
) {
	pthread_mutex_lock(&data->lock);
	ip_network_cleanup(&data->ip);
	pthread_mutex_unlock(&data->lock);
}

int rrr_udpstream_bind (
		struct rrr_udpstream *data,
		unsigned int local_port
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	if (data->ip.fd != 0) {
		VL_BUG("rrr_udpstream_bind called with non-zero fd, bind already complete\n");
	}

	data->ip.port = local_port;

	if (ip_network_start_udp_ipv4 (&data->ip) != 0) {
		VL_MSG_ERR("Could not start IP in rrr_udpstream_connect\n");
		ret = 1;
		goto out;
	}

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connect_raw (
		uint16_t *connect_handle,
		struct rrr_udpstream *data,
		struct sockaddr *addr,
		socklen_t socklen
) {
	int ret = 0;

	pthread_mutex_lock(&data->lock);

	if (data->ip.fd == 0) {
		VL_BUG("FD was 0 in rrr_udpstream_connect_raw, must bind first\n");
	}

	if ((ret = __rrr_udpstream_send_connect(connect_handle, data, addr, socklen)) != 0) {
		VL_MSG_ERR("Could not send connect packet in rrr_udpstream_connect_raw\n");
		goto out;
	}

	out:
	pthread_mutex_unlock(&data->lock);
	return ret;
}

int rrr_udpstream_connect (
		uint16_t *connect_handle,
		struct rrr_udpstream *data,
		const char *remote_host,
		const char *remote_port
) {
	int ret = 0;
	struct addrinfo *res = NULL;

	if (data->ip.fd == 0) {
		VL_BUG("FD was 0 in rrr_udpstream_connect, must bind first\n");
	}

	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(remote_host, remote_port, &hints, &res);
	if (ret != 0) {
		VL_MSG_ERR ("Could not get address info of server %s port %s in rrr_udpstream_connect: %s\n",
				remote_host, remote_port, gai_strerror(ret));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_udpstream_connect_raw(connect_handle, data, res->ai_addr, res->ai_addrlen)) != 0) {
		VL_MSG_ERR("Could not send connect packet in rrr_udpstream_connect\n");
		goto out;
	}

	out:
	if (res != NULL) {
		freeaddrinfo(res);
	}
	pthread_mutex_unlock(&data->lock);
	return ret;
}
