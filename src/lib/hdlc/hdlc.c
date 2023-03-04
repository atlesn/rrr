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

void rrr_hdlc_parse_state_init (
		struct rrr_hdlc_parse_state *state,
		struct rrr_parse_pos *parse_pos
) {
	state->parse_pos = parse_pos;
	state->parse_flag = RRR_HDLC_PARSE_STATE_IDLE;
	state->result_wpos = 0;
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
					return RRR_HDLC_OK;
				}
				PUSH(rrr_parse_quick_byte(state->parse_pos));
				break;
			case RRR_HDLC_PARSE_STATE_ESCAPE:
				PUSH(rrr_parse_quick_byte(state->parse_pos) ^ RRR_HDLC_BYTE_XOR);
				break;
			case RRR_HDLC_PARSE_STATE_DONE:
				return RRR_HDLC_OK;
			default:
				assert(0);
		};
	}

	return RRR_HDLC_INCOMPLETE;
}
