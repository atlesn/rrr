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

#ifndef RRR_PARSE_H
#define RRR_PARSE_H

#include "rrr_types.h"

// In RRR, a NAME may have letters, numbers, underscore and dash. On the other
// hand, a TAG may have letters, numbers and underscore (but not dash).

#define RRR_PARSE_MATCH_SPACE_TAB (1<<0)
#define RRR_PARSE_MATCH_COMMAS    (1<<1)
#define RRR_PARSE_MATCH_LETTERS   (1<<2)
#define RRR_PARSE_MATCH_HEX       (1<<3)
#define RRR_PARSE_MATCH_NUMBERS   (1<<4)
#define RRR_PARSE_MATCH_NEWLINES  (1<<5)
#define RRR_PARSE_MATCH_NULL      (1<<6)
#define RRR_PARSE_MATCH_END       (1<<7)
#define RRR_PARSE_MATCH_DASH      (1<<8)
#define RRR_PARSE_MATCH_CONTROL   (1<<9)
#define RRR_PARSE_MATCH_NAME      (RRR_PARSE_MATCH_LETTERS|RRR_PARSE_MATCH_NUMBERS|RRR_PARSE_MATCH_DASH)
#define RRR_PARSE_MATCH_TAG       (RRR_PARSE_MATCH_LETTERS|RRR_PARSE_MATCH_NUMBERS)

#define RRR_PARSE_CHECK_EOF(_pos)		\
	((_pos)->pos >= (_pos)->size)

#define RRR_PARSE_MATCH_C_SPACE_TAB(c)	\
	((c) == ' ' || (c) == '\t')
#define RRR_PARSE_MATCH_C_NEWLINES(c)	\
	((c) == '\r' || (c) == '\n')
#define RRR_PARSE_MATCH_C_COMMAS(c)		\
	((c) == ',' || (c) == ';')
#define RRR_PARSE_MATCH_C_DASH(c)		\
	((c) == '-')
#define RRR_PARSE_MATCH_C_LETTER(c) 	\
	(	((c) >= 'a' && (c) <= 'z') ||	\
		((c) >= 'A' && (c) <= 'Z') ||	\
		((c) == '_'))
#define RRR_PARSE_MATCH_C_HEX(c) 		\
	(	((c) >= 'a' && (c) <= 'f') ||	\
		((c) >= 'A' && (c) <= 'F') ||	\
		((c) >= '0' && (c) <= '9'))
#define RRR_PARSE_MATCH_C_NUMBER(c) 	\
	((c) >= '0' && (c) <= '9')
#define RRR_PARSE_MATCH_C_NULL(c) 		\
	((c) == '\0')
#define RRR_PARSE_MATCH_C_CONTROL(c)	\
	((c) <= 0x1f)
#define RRR_PARSE_MATCH_C_TAG(c)	\
	(RRR_PARSE_MATCH_C_LETTER(c) || RRR_PARSE_MATCH_C_NUMBER(c))

struct rrr_parse_pos {
	const char *data;
	rrr_length pos;
	rrr_length size;
	rrr_length line;
	rrr_length line_begin_pos;
};

void rrr_parse_pos_init (
		struct rrr_parse_pos *target,
		const char *data,
		rrr_length size
);
void rrr_parse_ignore_space_and_tab (
		struct rrr_parse_pos *pos
);
void rrr_parse_ignore_control_and_increment_line (
		struct rrr_parse_pos *pos
);
void rrr_parse_ignore_spaces_and_increment_line (
		struct rrr_parse_pos *pos
);
void rrr_parse_comment (
		struct rrr_parse_pos *pos
);
int rrr_parse_match_word_case (
		struct rrr_parse_pos *pos,
		const char *word
);
int rrr_parse_match_word (
		struct rrr_parse_pos *pos,
		const char *word
);
int rrr_parse_match_letters_simple (
		struct rrr_parse_pos *pos
);
rrr_length rrr_parse_match_letters_peek (
		const struct rrr_parse_pos *pos,
		rrr_length flags
);
void rrr_parse_match_letters (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end,
		rrr_length flags
);
void rrr_parse_match_until (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end,
		rrr_length flags
);
void rrr_parse_non_newline (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end
);
void rrr_parse_non_control (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end
);
int rrr_parse_str_extract (
		char **target,
		struct rrr_parse_pos *pos,
		const rrr_length begin,
		const rrr_length length
);
int rrr_parse_str_split (
		const char *str,
		char chr,
		rrr_length elements_max,
		int (*callback)(const char *elements[], rrr_length elements_count, void *arg),
		void *callback_arg
);
int rrr_parse_str_extract_until (
		char **result,
		rrr_length *result_length,
		const char *str,
		char end_char
);
int rrr_parse_str_extract_name (
		char **name,
		struct rrr_parse_pos *pos,
		char end_char
);
void rrr_parse_str_strip_newlines (
		char *str
);
void rrr_parse_str_trim (
		char *str
);

#endif /* RRR_PARSE_H */
