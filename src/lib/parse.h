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

#ifndef RRR_PARSE_H
#define RRR_PARSE_H

#define RRR_PARSE_MATCH_SPACE_TAB	(1<<0)
#define RRR_PARSE_MATCH_COMMAS		(1<<1)
#define RRR_PARSE_MATCH_LETTERS		(1<<2)
#define RRR_PARSE_MATCH_HEX			(1<<3)
#define RRR_PARSE_MATCH_NUMBERS		(1<<4)
#define RRR_PARSE_MATCH_NEWLINES	(1<<5)
#define RRR_PARSE_MATCH_NULL		(1<<6)
#define RRR_PARSE_MATCH_END			(1<<7)

#define RRR_PARSE_CHECK_EOF(_pos)		\
	((_pos)->pos >= (_pos)->size)

#define RRR_PARSE_MATCH_C_SPACE_TAB(c)	\
	((c) == ' ' || (c) == '\t')
#define RRR_PARSE_MATCH_C_NEWLINES(c)	\
	((c) == '\r' || (c) == '\n')
#define RRR_PARSE_MATCH_C_COMMAS(c)		\
	((c) == ',' || (c) == ';')
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

// XXX : Removed - for compatibility with condition expressions
// || ((c) == '-')

struct rrr_parse_pos {
	const char *data;
	int pos;
	int size;
	int line;
	int line_begin_pos;
};

void rrr_parse_pos_init (
		struct rrr_parse_pos *target,
		const char *data,
		int size
);
void rrr_parse_ignore_space_and_tab (struct rrr_parse_pos *pos);
void rrr_parse_ignore_spaces_and_increment_line (struct rrr_parse_pos *pos);
void rrr_parse_comment (struct rrr_parse_pos *pos);
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
void rrr_parse_match_letters (
		struct rrr_parse_pos *pos,
		int *start,
		int *end,
		int flags
);
void rrr_parse_match_until (
		struct rrr_parse_pos *pos,
		int *start,
		int *end,
		int flags
);
void rrr_parse_non_newline (
		struct rrr_parse_pos *pos,
		int *start,
		int *end
);
int rrr_parse_extract_string (
		char **target,
		struct rrr_parse_pos *pos,
		const int begin,
		const int length
);
int rrr_parse_str_split (
		const char *str,
		char chr,
		size_t elements_max,
		int (*callback)(const char *elements[], size_t elements_count, void *arg),
		void *callback_arg
);
int rrr_parse_str_extract_until (
		char **result,
		size_t *result_length,
		const char *str,
		char end_char
);
void rrr_parse_str_strip_newlines (
		char *str
);

#endif /* RRR_PARSE_H */
