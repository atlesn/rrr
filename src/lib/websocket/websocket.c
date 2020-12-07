/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include <limits.h>
#include <stdint.h>

#include "../log.h"
#include "websocket.h"
#include "../net_transport/net_transport.h"
#include "../util/rrr_endian.h"
#include "../read_constants.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/base64.h"
#include "../util/rrr_time.h"
#include "../random.h"
#include "../helpers/nullsafe_str.h"
#include "../type.h"

static void __rrr_websocket_frame_destroy (
		struct rrr_websocket_frame *frame
) {
	RRR_FREE_IF_NOT_NULL(frame->payload);
	free(frame);
}

void rrr_websocket_state_set_client_mode (
		struct rrr_websocket_state *ws_state
) {
	ws_state->do_mask_outgoing_frames = 1;
}

void rrr_websocket_state_clear_receive (
		struct rrr_websocket_state *ws_state
) {
	rrr_nullsafe_str_destroy_if_not_null(&ws_state->receive_state.fragment_buffer_nullsafe);
	memset(&ws_state->receive_state, '\0', sizeof(ws_state->receive_state));
}

void rrr_websocket_state_clear_all (
		struct rrr_websocket_state *ws_state
) {
	rrr_websocket_state_clear_receive(ws_state);
	RRR_LL_DESTROY(&ws_state->send_queue, struct rrr_websocket_frame, __rrr_websocket_frame_destroy(node));
	memset(ws_state, '\0', sizeof(*ws_state));
}

int rrr_websocket_state_get_key_base64 (
		char **target,
		struct rrr_websocket_state *ws_state
) {
	int ret = 0;

	*target = NULL;

	unsigned char *base64 = NULL;

	if (ws_state->websocket_key_64[0] == 0 && ws_state->websocket_key_64[1] == 0) {
		RRR_ASSERT(sizeof(rrr_rand) < sizeof(uint32_t),rrr_rand_is_at_least_4_bytes);
		for (int i = 0; i < 4; i++) {
			ws_state->websocket_key_32[i] = (uint32_t) rrr_rand();
		}
	}

	size_t out_len = 0;
	if ((base64 = rrr_base64_encode((const unsigned char *) ws_state->websocket_key_8, sizeof(ws_state->websocket_key_8), &out_len)) == NULL) {
		RRR_MSG_0("Failed to encode base64 in rrr_websocket_state_get_key_base64\n");
		ret = 1;
		goto out;
	}

	char *newline = strchr((char *) base64, '\n');
	if (newline) {
		*newline = '\0';
	}

	*target = (char *) base64;

	out:
	return ret;
}

int rrr_websocket_frame_enqueue (
		struct rrr_websocket_state *ws_state,
		uint8_t opcode,
		char **payload,
		uint64_t payload_len
) {
	int ret = 0;

	struct rrr_websocket_frame *frame;

	if ((frame = malloc(sizeof(*frame))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_websocket_frame_enqueue\n");
		ret = 1;
		goto out;
	}

	memset(frame, '\0', sizeof(*frame));

	frame->header.opcode = opcode;
	frame->header.mask = ws_state->do_mask_outgoing_frames;
	frame->header.payload_len = payload_len;

	if (payload != NULL && *payload != NULL) {
		frame->payload = *payload;
		*payload = NULL;
	}

	RRR_LL_PUSH(&ws_state->send_queue, frame);

	out:
	return ret;
}

int rrr_websocket_check_timeout (
		struct rrr_websocket_state *ws_state,
		int timeout_s
) {
	if (timeout_s == 0) {
		return 0;
	}

	if (ws_state->last_receive_time == 0) {
		ws_state->last_receive_time = rrr_time_get_64();
	}

	uint64_t timeout_limit = rrr_time_get_64() - timeout_s * 1000 * 1000;

	if (ws_state->last_receive_time > timeout_limit) {
		return 0;
	}

	return 1;
}

int rrr_websocket_enqueue_ping_if_needed (
		struct rrr_websocket_state *ws_state,
		int ping_interval_s
) {
	if (ping_interval_s == 0) {
		return 0;
	}

	if (ws_state->last_ping_time == 0) {
		ws_state->last_ping_time = rrr_time_get_64();
		return 0;
	}

	uint64_t ping_limit = rrr_time_get_64() - ping_interval_s * 1000 * 1000;

	if (ws_state->last_ping_time > ping_limit || ws_state->waiting_for_pong) {
		return 0;
	}

	ws_state->last_ping_time = rrr_time_get_64();
	ws_state->waiting_for_pong = 1;

	return rrr_websocket_frame_enqueue (
			ws_state,
			RRR_WEBSOCKET_OPCODE_PING,
			NULL,
			0
	);
}

static void __rrr_websocket_payload_mask_unmask (
		uint8_t *payload,
		ssize_t payload_size,
		uint32_t masking_key_h
) {
	union {
		uint32_t key_32;
		uint8_t key_8[4];
	} key;
	key.key_32 = rrr_htobe32(masking_key_h);

	for (ssize_t i = 0; i < payload_size; i++) {
		payload[i] = payload[i] ^ key.key_8[i % 4];
	}
}

static int __rrr_websocket_transport_ctx_frame_send (
		struct rrr_net_transport_handle *handle,
		struct rrr_websocket_frame *frame
) {
	int ret = 0;

	RRR_DBG_3("Websocket %i send frame opcode %i size %" PRIu64 "\n",
			handle->handle, frame->header.opcode, frame->header.payload_len);

	uint8_t header[32]; // Make sure it's big enough when new stuff is added
	memset(header, '\0', sizeof(header));

	{
		uint8_t pos = 0;

		header[pos] = frame->header.opcode;
		header[pos] |= 0x80; // FIN
		pos++;

		uint8_t mask_flag_shifted = (frame->header.mask ? 1 << 7 : 0);

		if (frame->header.payload_len < 126) {
			header[pos] = mask_flag_shifted | frame->header.payload_len;
			pos++;
		}
		else if (frame->header.payload_len <= 65535) {
			header[pos] = mask_flag_shifted | 126;
			pos++;
			uint16_t tmp = rrr_htobe16(frame->header.payload_len);
			memcpy (header + pos, &tmp, sizeof(tmp));
			pos += sizeof(tmp);
		}
		else {
			header[pos] = mask_flag_shifted | 127;
			pos++;
			uint64_t tmp = rrr_htobe64(frame->header.payload_len);
			memcpy (header + pos, &tmp, sizeof(tmp));
			pos += sizeof(tmp);
		}

		if (frame->header.mask) {
			frame->header.masking_key = (uint32_t) rrr_rand();
			uint32_t masking_key_be = rrr_htobe32(frame->header.masking_key);
			memcpy (header + pos, &masking_key_be, sizeof(masking_key_be));
			pos += sizeof(masking_key_be);
		}

		if (pos > sizeof(header)) {
			RRR_BUG("BUG: pos exceeds header size in __rrr_websocket_transport_ctx_send_frame\n");
		}

		if ((ret = rrr_net_transport_ctx_send_blocking(handle, header, pos)) != 0) {
			RRR_DBG_1("Failed to send websocket header for handle %i\n", handle->handle);
			goto out;
		}
	}

	if (frame->header.payload_len > 0) {
		if (frame->header.mask) {
			__rrr_websocket_payload_mask_unmask((uint8_t *) frame->payload, frame->header.payload_len, frame->header.masking_key);
		}

		if ((ret = rrr_net_transport_ctx_send_blocking(handle, frame->payload, frame->header.payload_len)) != 0) {
			RRR_DBG_1("Failed to send websocket payload for handle %i\n", handle->handle);
			goto out;
		}
	}

	out:
	return ret;
}

struct rrr_websocket_callback_data {
	struct rrr_websocket_state *ws_state;
	int (*callback)(RRR_WEBSOCKET_FRAME_CALLBACK_ARGS);
	void *callback_arg;
};
/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	 */

#define CHECK_LENGTH()																\
	do {if (read_session->rx_buf_wpos < (rrr_slength) header_new.header_len) {		\
		ret = RRR_READ_INCOMPLETE; goto out;										\
	}} while (0)

int __rrr_websocket_get_target_size (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_websocket_callback_data *callback_data = arg;

	int ret = RRR_READ_OK;

	struct rrr_websocket_header header_new = {0};

	header_new.header_len = 2;
	CHECK_LENGTH();

	uint16_t flags = rrr_be16toh(*((uint16_t *) read_session->rx_buf_ptr));
	const uint8_t payload_len = flags & 0x7f;
	flags >>= 7;
	header_new.mask = flags & 1;
	flags >>= 1;
	header_new.opcode = flags & 0xf;
	flags >>= 4;
	header_new.rsv3 = flags & 1;
	flags >>= 1;
	header_new.rsv2 = flags & 1;
	flags >>= 1;
	header_new.rsv1 = flags & 1;
	flags >>= 1;
	header_new.fin = flags & 1;

	if (payload_len == 126) {
		const char *pos = read_session->rx_buf_ptr + header_new.header_len;
		header_new.header_len += 2;
		CHECK_LENGTH();
		header_new.payload_len = rrr_be16toh(*((uint16_t *) pos));
	}
	else if (payload_len == 127) {
		const char *pos = read_session->rx_buf_ptr + header_new.header_len;
		header_new.header_len += 8;
		CHECK_LENGTH();
		header_new.payload_len = rrr_be64toh(*((uint64_t *) pos));
	}
	else {
		header_new.payload_len = payload_len;
	}

	if (header_new.mask) {
		const char *pos = read_session->rx_buf_ptr + header_new.header_len;
		header_new.header_len += 4;
		CHECK_LENGTH();
		header_new.masking_key = rrr_be32toh(*((uint32_t *) pos));
	}

	rrr_biglength target_len = header_new.header_len + header_new.payload_len;

	if (target_len > (rrr_biglength) SSIZE_MAX) {
		RRR_MSG_0("Total specified length og websocket frame was too big (%" PRIrrrbl ">%li)\n",
				target_len, SSIZE_MAX);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	callback_data->ws_state->last_receive_time = rrr_time_get_64();
	callback_data->ws_state->receive_state.header = header_new;
	read_session->target_size = target_len;
	read_session->read_complete_method = RRR_READ_COMPLETE_METHOD_TARGET_LENGTH;

	out:
	return ret;
}

int __rrr_websocket_receive_callback_final_step (
		struct rrr_websocket_state *ws_state,
		const struct rrr_nullsafe_str *payload,
		int (*final_callback)(RRR_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	RRR_DBG_3("Websocket receive frame type %u size %" PRIrrr_nullsafe_len "\n",
			ws_state->last_receive_opcode, rrr_nullsafe_str_len(payload));

	// last_receive time is updated in get_target_size function

	switch (ws_state->last_receive_opcode) {
		case RRR_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
			ret = RRR_READ_EOF;
			goto out;
		case RRR_WEBSOCKET_OPCODE_PING:
			ret = rrr_websocket_frame_enqueue (
					ws_state,
					RRR_WEBSOCKET_OPCODE_PONG,
					NULL,
					0
			);
			break;
		case RRR_WEBSOCKET_OPCODE_PONG:
			ws_state->waiting_for_pong = 0;
			break;
		default:
			ret = final_callback (
					ws_state->last_receive_opcode,
					payload,
					final_callback_arg
			);
			break;
	};

	out:
	return ret;
}

static int __rrr_websocket_receive_callback_fragmentation_step_nullsafe_callback (
		const struct rrr_nullsafe_str *payload,
		void *arg
) {
	struct rrr_websocket_callback_data *callback_data = arg;
	return __rrr_websocket_receive_callback_final_step (
			callback_data->ws_state,
			payload,
			callback_data->callback,
			callback_data->callback_arg
	);
}

static int __rrr_websocket_receive_callback_fragmentation_step (
		struct rrr_websocket_callback_data *callback_data,
		uint8_t fin,
		char *payload,
		ssize_t payload_size
) {
	struct rrr_websocket_state *ws_state = callback_data->ws_state;

	int ret = 0;

	if (!ws_state->last_receive_opcode) {
		RRR_MSG_0("Missing opcode in first websocket frame fragment\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	// Shortcut for single frames
	if (ws_state->receive_state.fragment_buffer_nullsafe == NULL && fin) {
		ret = rrr_nullsafe_str_with_tmp_str_do (
				payload,
				payload_size,
				__rrr_websocket_receive_callback_fragmentation_step_nullsafe_callback,
				callback_data
		);
		goto out;
	}

	if (ws_state->receive_state.fragment_buffer_nullsafe == NULL) {
		if ((ret = rrr_nullsafe_str_new_or_replace_empty(&ws_state->receive_state.fragment_buffer_nullsafe)) != 0) {
			goto out;
		}
	}

	if ((ret = rrr_nullsafe_str_append_raw(ws_state->receive_state.fragment_buffer_nullsafe, payload, payload_size)) != 0) {
		RRR_MSG_0("Fragment size overflow for websocket connection, total size of fragments too large or allocation failure, return was %i\n", ret);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (fin) {
		ret = rrr_nullsafe_str_with_str_do (
				ws_state->receive_state.fragment_buffer_nullsafe,
				__rrr_websocket_receive_callback_fragmentation_step_nullsafe_callback,
				callback_data
		);
		goto out;
	}

	goto out_no_clear;
	out:
		rrr_websocket_state_clear_receive(ws_state);
	out_no_clear:
		return ret;
}

int __rrr_websocket_receive_callback_interpret_step (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_websocket_callback_data *callback_data = arg;
	struct rrr_websocket_state *ws_state = callback_data->ws_state;

	int ret = RRR_READ_OK;

	uint8_t *payload = (uint8_t *) read_session->rx_buf_ptr + ws_state->receive_state.header.header_len;
	const ssize_t payload_len = read_session->rx_buf_wpos - ws_state->receive_state.header.header_len;

	if (ws_state->receive_state.header.mask) {
		__rrr_websocket_payload_mask_unmask(payload, payload_len, ws_state->receive_state.header.masking_key);
	}

	// Save these in case header is reset
	const unsigned short int fin = ws_state->receive_state.header.fin;
	const uint8_t opcode = ws_state->receive_state.header.opcode;

	// Zero opcode means CONTINUATION frame
	if (opcode) {
		// First non-fin frame has opcode, start new fragmented frame and reset header
		rrr_websocket_state_clear_receive(ws_state);

		switch (opcode) {
			case RRR_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
			case RRR_WEBSOCKET_OPCODE_PING:
			case RRR_WEBSOCKET_OPCODE_PONG:
				if (payload_len > 125) {
					RRR_MSG_0("Received websocket control packet of type %u with payload longer than 125 bytes, this is an error.\n", opcode);
					ret = RRR_READ_SOFT_ERROR;
					goto out;
				}
				if (!fin) {
					RRR_MSG_0("Received websocket control packet of type %u with FIN flag left unset, this is an error.\n", opcode);
					ret = RRR_READ_SOFT_ERROR;
					goto out;
				}
				break;
			case RRR_WEBSOCKET_OPCODE_TEXT:
			case RRR_WEBSOCKET_OPCODE_BINARY:
				break;
			default:
				RRR_MSG_0("Received unknown websocket packet of type %u\n", opcode);
				ret = RRR_READ_SOFT_ERROR;
				goto out;
		};

		if (!fin && opcode != RRR_WEBSOCKET_OPCODE_TEXT && opcode != RRR_WEBSOCKET_OPCODE_BINARY) {
			RRR_MSG_0("Received fragmented websocket frame of type %i which is not allowed, only TEXT and BINARY may be fragmented\n", opcode);
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}

		ws_state->last_receive_opcode = opcode;
	}

	ret = __rrr_websocket_receive_callback_fragmentation_step (
			callback_data,
			fin,
			(char *) payload,
			payload_len
	);

	out:
	return ret;
}

int rrr_websocket_transport_ctx_read_frames (
		struct rrr_net_transport_handle *handle,
		struct rrr_websocket_state *ws_state,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max_size,
		int (*callback)(RRR_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *callback_arg
) {
	struct rrr_websocket_callback_data callback_data = {
			ws_state,
			callback,
			callback_arg
	};

	return rrr_net_transport_ctx_read_message (
			handle,
			read_attempts,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			__rrr_websocket_get_target_size,
			&callback_data,
			__rrr_websocket_receive_callback_interpret_step,
			&callback_data
	);
}

int rrr_websocket_transport_ctx_send_frames (
	struct rrr_net_transport_handle *handle,
	struct rrr_websocket_state *ws_state
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&ws_state->send_queue, struct rrr_websocket_frame);
		if ((ret = __rrr_websocket_transport_ctx_frame_send(handle, node)) != 0) {
			goto out;
		}
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&ws_state->send_queue, 0; __rrr_websocket_frame_destroy(node));

	out:
	return ret;
}

