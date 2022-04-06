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

#ifndef RRR_WEBSOCKET_H
#define RRR_WEBSOCKET_H

#include "../rrr_types.h"
#include "../util/linked_list.h"

// RFC6455

#define RRR_WEBSOCKET_OPCODE_CONTINUATION		0
#define RRR_WEBSOCKET_OPCODE_TEXT				1
#define RRR_WEBSOCKET_OPCODE_BINARY				2
#define RRR_WEBSOCKET_OPCODE_CONNECTION_CLOSE	8
#define RRR_WEBSOCKET_OPCODE_PING				9
#define RRR_WEBSOCKET_OPCODE_PONG				10

#define RRR_WEBSOCKET_FRAME_CALLBACK_ARGS \
	uint8_t opcode, const struct rrr_nullsafe_str *payload, void *arg

struct rrr_nullsafe_str;
struct rrr_net_transport_handle;

struct rrr_websocket_header {
	uint8_t fin;
	uint8_t rsv1;
	uint8_t rsv2;
	uint8_t rsv3;
	uint8_t opcode;
	uint8_t mask;
	uint8_t header_len;
	uint64_t payload_len;
	union {
		uint32_t masking_key;
		uint8_t masking_key_bytes[4];
	};
};

struct rrr_websocket_frame {
	RRR_LL_NODE(struct rrr_websocket_frame);
	struct rrr_websocket_header header;
	char *payload;
};

struct rrr_websocket_frame_collection {
	RRR_LL_HEAD(struct rrr_websocket_frame);
};

struct rrr_websocket_state_receive {
	struct rrr_websocket_header header;
	struct rrr_nullsafe_str *fragment_buffer_nullsafe;
};

struct rrr_websocket_state {
	struct rrr_websocket_state_receive receive_state;
	uint8_t last_receive_opcode;
	uint64_t last_receive_time;
	uint64_t last_ping_time;
	uint8_t last_enqueued_pcode;
	int waiting_for_pong;
	int do_mask_outgoing_frames;
	struct rrr_websocket_frame_collection send_queue;

	// Used when client creates request
	union {
		uint8_t websocket_key_8[16];
		uint64_t websocket_key_32[4];
		uint64_t websocket_key_64[2];
	};
};

void rrr_websocket_state_set_client_mode (
		struct rrr_websocket_state *ws_state
);
void rrr_websocket_state_clear_receive (
		struct rrr_websocket_state *ws_state
);
void rrr_websocket_state_clear_all (
		struct rrr_websocket_state *ws_state
);
int rrr_websocket_state_get_key_base64 (
		char **target,
		struct rrr_websocket_state *ws_state
);
int rrr_websocket_frame_enqueue (
		struct rrr_websocket_state *ws_state,
		uint8_t opcode,
		char **payload,
		uint64_t payload_len
);
int rrr_websocket_check_timeout (
		struct rrr_websocket_state *ws_state,
		rrr_length timeout_s
);
int rrr_websocket_enqueue_ping_if_needed (
		struct rrr_websocket_state *ws_state,
		rrr_length ping_interval_s
);
int rrr_websocket_transport_ctx_read_frames (
		struct rrr_net_transport_handle *handle,
		struct rrr_websocket_state *ws_state,
		rrr_biglength read_step_initial,
		rrr_biglength read_step_max_size,
		rrr_biglength read_max_size,
		uint64_t ratelimit_interval_us,
		rrr_biglength ratelimit_max_bytes,
		int (*callback)(RRR_WEBSOCKET_FRAME_CALLBACK_ARGS),
		void *callback_arg
);
int rrr_websocket_transport_ctx_send_frames (
	struct rrr_net_transport_handle *handle,
	struct rrr_websocket_state *ws_state
);

#endif /* RRR_WEBSOCKET_H */
