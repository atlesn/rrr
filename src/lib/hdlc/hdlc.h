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

#ifndef RRR_HDLC_H
#define RRR_HDLC_H

#include "../read_constants.h"
#include "../rrr_types.h"

#define RRR_HDLC_OK           RRR_READ_OK
#define RRR_HDLC_INCOMPLETE   RRR_READ_INCOMPLETE
#define RRR_HDLC_SOFT_ERROR   RRR_READ_SOFT_ERROR

enum rrr_hdlc_parse_flag {
	RRR_HDLC_PARSE_STATE_IDLE,
	RRR_HDLC_PARSE_STATE_FRAME,
	RRR_HDLC_PARSE_STATE_ESCAPE,
	RRR_HDLC_PARSE_STATE_DONE
};

struct rrr_hdlc_parse_state {
	struct rrr_parse_pos *parse_pos;
	rrr_length result_wpos;
	enum rrr_hdlc_parse_flag parse_flag;
	char result[4096];
};

#define RRR_HDLC_DATA(s)       ((s)->result)
#define RRR_HDLC_DATA_SIZE(s)  ((s)->result_wpos)
#define RRR_HDLC_MAX(s)        (sizeof((s)->result))

void rrr_hdlc_parse_state_init (
		struct rrr_hdlc_parse_state *state,
		struct rrr_parse_pos *parse_pos
);

int rrr_hdlc_parse_frame (
		struct rrr_hdlc_parse_state *state
);

#endif /* RRR_HDLC_H */
