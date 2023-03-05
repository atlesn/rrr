/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include <assert.h>
#include <string.h>

#include "hdlc.h"

#include "../parse.h"

static const char RRR_HDLC_BYTE_FRAME  = 0x7e;
static const char RRR_HDLC_BYTE_ESCAPE = 0x7d;
static const char RRR_HDLC_BYTE_XOR    = 0x20;

#define MUST_ESCAPE(c) ((c) == RRR_HDLC_BYTE_FRAME || (c) == RRR_HDLC_BYTE_ESCAPE)

void rrr_hdlc_parse_state_init (
		struct rrr_hdlc_parse_state *state,
		struct rrr_parse_pos *parse_pos
) {
	state->parse_pos = parse_pos;
	state->parse_flag = RRR_HDLC_PARSE_STATE_IDLE;
	state->result_wpos = 0;
}

static int __rrr_hdlc_parse_frame_done_verify_size (
		struct rrr_hdlc_parse_state *state
) {
	if (RRR_HDLC_DATA_SIZE(state) == 0) {
		RRR_MSG_0("Parsed HDLC frame was zero bytes (0x7e 0x7e sequence), this is an error.\n");
		return RRR_HDLC_SOFT_ERROR;
	}
	return RRR_HDLC_OK;
}

#define PUSH(c)                                                \
    do {if (state->result_wpos == sizeof(state->result) - 1) { \
        return RRR_HDLC_SOFT_ERROR;                            \
    }                                                          \
    state->result[state->result_wpos++] = c;                   \
    } while (0)

int rrr_hdlc_parse_frame (
		struct rrr_hdlc_parse_state *state
) {
	while (!RRR_PARSE_CHECK_EOF(state->parse_pos)) {
		switch (state->parse_flag) {
			case RRR_HDLC_PARSE_STATE_IDLE:
				if (rrr_parse_quick_match_or_skip(state->parse_pos, RRR_HDLC_BYTE_FRAME) == 0) {
					state->parse_flag = RRR_HDLC_PARSE_STATE_FRAME;
				}
				break;
			case RRR_HDLC_PARSE_STATE_FRAME:
				if (rrr_parse_quick_match(state->parse_pos, RRR_HDLC_BYTE_ESCAPE) == 0) {
					state->parse_flag = RRR_HDLC_PARSE_STATE_ESCAPE;
					break;
				}
				if (rrr_parse_quick_match(state->parse_pos, RRR_HDLC_BYTE_FRAME) == 0) {
					state->parse_flag = RRR_HDLC_PARSE_STATE_DONE;
					return __rrr_hdlc_parse_frame_done_verify_size(state);
				}
				PUSH(rrr_parse_quick_byte(state->parse_pos));
				break;
			case RRR_HDLC_PARSE_STATE_ESCAPE:
				PUSH(rrr_parse_quick_byte(state->parse_pos) ^ RRR_HDLC_BYTE_XOR);
				state->parse_flag = RRR_HDLC_PARSE_STATE_FRAME;
				break;
			case RRR_HDLC_PARSE_STATE_DONE:
				return __rrr_hdlc_parse_frame_done_verify_size(state);
			default:
				assert(0);
		};
	}

	return RRR_HDLC_INCOMPLETE;
}

int rrr_hdlc_get_export_length (
		rrr_length *result,
		const char *data,
		rrr_length data_size
) {
	rrr_biglength result_tmp = 0;

	*result = 0;

	for (rrr_length i = 0; i < data_size; i++) {
		result_tmp += MUST_ESCAPE(*(data + i)) ? 2 : 1;
	}

	result_tmp += 2;

	if (result_tmp > RRR_HDLC_MAX) {
		RRR_MSG_0("HDLC export length would exceed maximum value (%" PRIrrrbl ">%i)\n", result_tmp, RRR_HDLC_MAX);
		return 1;
	}

	*result = rrr_length_from_biglength_bug_const(result_tmp);

	return 0;
}

/* Buffer must be allocated with a size of at least the one obtained from rrr_hdlc_get_export_length */
void rrr_hdlc_export_frame (
		char *target,
		rrr_length *written_bytes,
		const char *data,
		rrr_length data_size
) {
	rrr_length pos = 0;

	target[pos++] = RRR_HDLC_BYTE_FRAME;

	for (rrr_length i = 0; i < data_size; i++) {
		if (MUST_ESCAPE(data[i])) {
			target[pos++] = RRR_HDLC_BYTE_ESCAPE;
			target[pos++] = data[i] ^ RRR_HDLC_BYTE_XOR;
		}
		else {
			target[pos++] = data[i];
		}
	}

	target[pos++] = RRR_HDLC_BYTE_FRAME;

	*written_bytes = pos;
}
