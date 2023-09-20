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

#include "log.h"
#include "parse.h"
#include "allocator.h"
#include "util/macro_utils.h"
#include "helpers/string_builder.h"

void rrr_parse_pos_init (
		struct rrr_parse_pos *target,
		const char *data,
		rrr_length size
) {
	target->data = data;
	target->pos = 0;
	target->size = size;
	target->line = 1;
	target->line_begin_pos = 0;
}

static int __rrr_parse_is_space_or_tab (
		unsigned char c
) {
	return RRR_PARSE_MATCH_C_SPACE_TAB(c);
}

static int __rrr_parse_is_spaces (
		unsigned char c
) {
	return RRR_PARSE_MATCH_C_SPACE_TAB(c) || RRR_PARSE_MATCH_C_NEWLINES(c);
}

static int __rrr_parse_is_control (
		unsigned char c
) {
	return RRR_PARSE_MATCH_C_CONTROL(c);
}

static void __rrr_parse_ignore_and_increment_line (
		struct rrr_parse_pos *pos,
		int (*condition_cb)(unsigned char c)
) {
	if (pos->pos >= pos->size) {
		return;
	}

	unsigned char c = (unsigned char) pos->data[pos->pos];

	// If the given condition_cb does not match newlines, line counting
	// is not performed (parsing will stop at newlines).

	while (condition_cb(c) && pos->pos < pos->size) {
		unsigned char next = pos->pos + 1 < pos->size ? (unsigned char) pos->data[pos->pos + 1] : '\0';

		if (c == '\r' && next == '\n') {
			// Windows
			pos->pos++;
			pos->line++;
			pos->line_begin_pos = pos->pos + 1;
		}
		else if (c == '\n') {
			// UNIX
			pos->line++;
			pos->line_begin_pos = pos->pos + 1;
		}
		else if (c == '\r') {
			// MAC
			pos->line++;
			pos->line_begin_pos = pos->pos + 1;
		}

		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		c = (unsigned char) pos->data[pos->pos];
	}
}

void rrr_parse_ignore_space_and_tab (
		struct rrr_parse_pos *pos
) {
	__rrr_parse_ignore_and_increment_line(pos, __rrr_parse_is_space_or_tab);
}

void rrr_parse_ignore_control_and_increment_line (
		struct rrr_parse_pos *pos
) {
	__rrr_parse_ignore_and_increment_line(pos, __rrr_parse_is_control);
}

void rrr_parse_ignore_spaces_and_increment_line (
		struct rrr_parse_pos *pos
) {
	__rrr_parse_ignore_and_increment_line(pos, __rrr_parse_is_spaces);
}

void rrr_parse_comment (
		struct rrr_parse_pos *pos
) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

	while (c != '\r' && c != '\n' && pos->pos < pos->size) {
		pos->pos++;
		c = pos->data[pos->pos];
	}

	rrr_parse_ignore_spaces_and_increment_line(pos);
}

int rrr_parse_match_word_case (
		struct rrr_parse_pos *pos,
		const char *word
) {
	// Default result = not matching
	int ret = 0;

	const char *word_pos = word;
	rrr_length pos_orig = pos->pos;

	while (*word_pos != '\0' && pos->pos < pos->size) {
		char c = pos->data[pos->pos];
		char c_case = '\0';

		if (c >= 'a' && c <= 'z') {
			c_case = (char) (c - 32);
		}
		else if (c >= 'A' && c <= 'Z') {
			c_case = (char) (c + 32);
		}

		if (*word_pos != c && *word_pos != c_case) {
			break;
		}

		pos->pos++;
		word_pos++;
	}

	if (*word_pos == '\0') {
		ret = 1; // Matching
	}
	else {
		pos->pos = pos_orig; // Revert
	}

	return ret;
}

int rrr_parse_match_word (
		struct rrr_parse_pos *pos,
		const char *word
) {
	// Default result = not matching
	int ret = 0;

	const char *word_pos = word;
	rrr_length pos_orig = pos->pos;

	while (*word_pos != '\0' && pos->pos < pos->size) {
		char c = pos->data[pos->pos];

		if (*word_pos != c) {
			break;
		}

		pos->pos++;
		word_pos++;
	}

	if (*word_pos == '\0') {
		ret = 1; // Matching
	}
	else {
		pos->pos = pos_orig; // Revert
	}

	return ret;
}

int rrr_parse_match_letters_simple (
		struct rrr_parse_pos *pos
) {
	int ret = 0; // No letters matched

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		char letter = *(pos->data + pos->pos);
		if (!RRR_PARSE_MATCH_C_LETTER(letter)) {
			break;
		}
		ret = 1; // At least one letter matched
		pos->pos++;
	}

	return ret;
}

static int __rrr_parse_match_char (char c, rrr_length flags) {
	return (((flags & RRR_PARSE_MATCH_SPACE_TAB) && RRR_PARSE_MATCH_C_SPACE_TAB(c)) ||
	        ((flags & RRR_PARSE_MATCH_COMMAS) && RRR_PARSE_MATCH_C_COMMAS(c)) ||
	        ((flags & RRR_PARSE_MATCH_LETTERS) && RRR_PARSE_MATCH_C_LETTER(c)) ||
	        ((flags & RRR_PARSE_MATCH_HEX) && RRR_PARSE_MATCH_C_HEX(c)) ||
	        ((flags & RRR_PARSE_MATCH_NUMBERS) && RRR_PARSE_MATCH_C_NUMBER(c)) ||
	        ((flags & RRR_PARSE_MATCH_NEWLINES) && RRR_PARSE_MATCH_C_NEWLINES(c)) ||
	        ((flags & RRR_PARSE_MATCH_NULL) && RRR_PARSE_MATCH_C_NULL(c)) ||
	        ((flags & RRR_PARSE_MATCH_DASH) && RRR_PARSE_MATCH_C_DASH(c)) ||
	        ((flags & RRR_PARSE_MATCH_CONTROL) && RRR_PARSE_MATCH_C_CONTROL(c))
	);
}

rrr_length rrr_parse_match_letters_peek (
		const struct rrr_parse_pos *pos_orig,
		rrr_length flags
) {
	struct rrr_parse_pos pos_tmp = *pos_orig;

	char c;
	while (!RRR_PARSE_CHECK_EOF(&pos_tmp)) {
		c = pos_tmp.data[pos_tmp.pos];

		if (!__rrr_parse_match_char(c, flags)) {
			break;
		}

		rrr_length_inc_bug(&pos_tmp.pos);
	}

	return pos_tmp.pos - pos_orig->pos;
}

void rrr_parse_match_letters (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end,
		rrr_length flags
) {
	*start = pos->pos;
	*end = pos->pos;

	rrr_length_add_bug(&pos->pos, rrr_parse_match_letters_peek(pos, flags));

	*end = (rrr_slength) pos->pos - 1;
}

void rrr_parse_match_until (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end,
		rrr_length flags
) {
	*start = pos->pos;
	*end = pos->pos;

	rrr_length pos_orig = pos->pos;

	int found = 0;
	char c = pos->data[pos->pos];
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		if (__rrr_parse_match_char(c, flags)) {
			found = 1;
			break;
		}

		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			if (flags & RRR_PARSE_MATCH_END) {
				found = 1;
			}
			break;
		}
		c = pos->data[pos->pos];
	}

	if (found == 0) {
		// If end terminator was not found, we did not match. Revert.
		pos->pos = pos_orig;
	}

	*end = (rrr_slength) pos->pos - 1;
}

void rrr_parse_non_newline (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end
) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		if (c == '\r' || c == '\n') {
			break;
		}

		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = (rrr_slength) pos->pos - 1;
}

void rrr_parse_non_control (
		struct rrr_parse_pos *pos,
		rrr_length *start,
		rrr_slength *end
) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		if (RRR_PARSE_MATCH_C_CONTROL(c)) {
			break;
		}

		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = (rrr_slength) pos->pos - 1;
}

int rrr_parse_str_extract (
		char **target,
		struct rrr_parse_pos *pos,
		const rrr_length begin,
		const rrr_length length
) {
	*target = NULL;

	if (length == 0) {
		RRR_BUG("BUG: length was 0 in rrr_parse_str_extract\n");
	}

	char *bytes = rrr_allocate((size_t) length + 1);

	if (bytes == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_parse_str_extract\n");
		return 1;
	}

	memcpy(bytes, pos->data + begin, (size_t) length);

	bytes[length] = '\0';

	*target = bytes;

	return 0;
}

int rrr_parse_str_split (
		const char *str,
		char chr,
		rrr_length elements_max,
		int (*callback)(const char *elements[], rrr_length elements_count, void *arg),
		void *callback_arg
) {
	int ret = 0;

	rrr_length elements_count = 0;
	const char *elements[elements_max];

	char *tmp = NULL;

	for (size_t i = 0; i < elements_max; i++) {
		elements[i] = NULL;
	}

	if (*str == '\0') {
		goto do_callback;
	}

	if ((tmp = rrr_strdup(str)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_parse_str_split\n");
		ret = 1;
		goto out;
	}

	char *pos = tmp;
	const char *element = tmp;
	int zero_found = 0;
	while (!zero_found) {
		if (elements_count == elements_max) {
			RRR_MSG_0("Too many elements while splitting string (more than %" PRIrrrl ")\n", elements_max);
			ret = 1;
			goto out;
		}

		if (*pos == chr || *pos == '\0') {
			if (*pos == '\0') {
				zero_found = 1;
			}

			*pos = '\0';

			elements[elements_count] = element;

			if ((ret = rrr_length_inc_err(&elements_count)) != 0) {
				goto out;
			}

			element = pos + 1;
		}
		pos++;
	}

	do_callback:
	ret = callback(elements, elements_count, callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(tmp);
	return ret;
}

int rrr_parse_str_extract_until (
		char **result,
		rrr_length *result_length,
		const char *str,
		char end_char
) {
	*result = NULL;
	*result_length = 0;

	const char *pos = str;
	const char *end = strchr(str, end_char);

	if (end == NULL) {
		return 0;
	}

	rrr_length length = (rrr_length) (end - pos);

	char *match = rrr_allocate(length + 1);
	if (match == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_parse_str_extract_until\n");
		return 1;
	}

	memcpy(match, str, length);
	match[length] = '\0';

	*result = match;
	*result_length = length;

	return 0;
}

int rrr_parse_str_extract_name (
		char **name,
		struct rrr_parse_pos *pos,
		char end_char
) {
	int ret = 0;

	char *name_tmp = NULL;

	*name = NULL;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		goto out;
	}

	rrr_length start;
	rrr_slength end;

	rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_NAME);

	if (end < start) {
		goto out;
	}

	rrr_parse_ignore_spaces_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos) || *(pos->data + pos->pos) != end_char) {
		goto out_missing_end_char;
	}
	rrr_length_inc_bug(&pos->pos);

	rrr_length name_length = rrr_length_inc_bug_const(rrr_length_from_slength_sub_bug_const(end, start));
	if ((name_tmp = rrr_allocate(name_length + 1)) == NULL) {
		goto out_failed_alloc;
	}

	memcpy(name_tmp, pos->data + start, name_length);
	name_tmp[name_length] = '\0';

	*name = name_tmp;
	name_tmp = NULL;

	goto out;
	out_failed_alloc:
		RRR_MSG_0("Could not allocate memory for name in %s\n", __func__);
		ret = 1;
		goto out;
	out_missing_end_char:
		RRR_MSG_0("End character %c missing after name\n", end_char);
		ret = 1;
		goto out;
	out:
		RRR_FREE_IF_NOT_NULL(name_tmp);
		return ret;
}

void rrr_parse_str_strip_newlines (
		char *str
) {
	size_t skip_count = 0;
	size_t length = strlen(str);
	for (size_t i = 0; i < length; i++) {
		while (((skip_count + i) < length) && (*(str + i + skip_count) == '\r' || *(str + i + skip_count) == '\n')) {
			skip_count++;
		}

		if (skip_count + i >= length) {
			*(str + i) = '\0';
			return;
		}
		else {
			*(str + i) = *(str + i + skip_count);
		}
	}
}

void rrr_parse_str_trim (
		char *str
) {
	size_t length = strlen(str);
	for (char *pos = str + length -1; pos >= str; pos--) {
		if (*pos == ' ' || *pos == '\r' || *pos == '\n' || *pos == '\t') {
			*pos = '\0';
		}
		else {
			break;
		}
	}
}

void rrr_parse_make_location_message (
		char **result,
		const struct rrr_parse_pos *pos_orig
) {
	struct rrr_parse_pos pos = *pos_orig;

	rrr_length start;
	rrr_slength end;
	rrr_slength col_orig;
	rrr_slength col;
	rrr_slength line_length;
	char line_num_str[24];
	int line_num_chars;
	char *str_tmp;
	struct rrr_string_builder string_builder = {0};

	col_orig = pos.pos - pos.line_begin_pos;
	pos.pos = pos.line_begin_pos;

	rrr_parse_non_newline (&pos, &start, &end);

	line_num_chars = sprintf(line_num_str, "%" PRIrrrl "", pos.line);

	assert(end >= 0);

	if (rrr_parse_str_extract (
			&str_tmp,
			&pos,
			start,
			end
	) != 0) {
		RRR_BUG("Allocation failure in %s\n", __func__);
	}

	line_length = end - start;

	if (line_length > 128) {
		line_length = 128;
		end = start + line_length;
		str_tmp[end] = '\0';
	}

	if (col_orig > line_length) {
		col = line_length;
	}
	else {
		col = col_orig;
	}

	for (size_t i = 0; i < (size_t) line_length; i++) {
		if (str_tmp[i] == '\t')
			str_tmp[i] = ' ';
	}

	if (rrr_string_builder_append_format(&string_builder, "At line %" PRIrrrl " col %" PRIrrrsl "%s\n",
			pos.line, col_orig + 1, col != col_orig ? " (line preview is truncated at 128 chars)" : "") != 0) {
		RRR_BUG("Failed to format string in %s\n", __func__);
	}

	if (rrr_string_builder_append_format(&string_builder, "  %s | ", line_num_str) != 0) {
		RRR_BUG("Failed to format string in %s\n", __func__);
	}

	if (rrr_string_builder_append_raw(&string_builder, str_tmp, (rrr_biglength) line_length) != 0) {
		RRR_BUG("Failed to format string in %s\n", __func__);
	}

	if (rrr_string_builder_append(&string_builder, "\n") != 0) {
		RRR_BUG("Failed to format string in %s\n", __func__);
	}

	memset(line_num_str, ' ', line_num_chars);
	memset(str_tmp, ' ', (rrr_length) col);
	str_tmp[col] = '\0';

	if (rrr_string_builder_append_format(&string_builder, "  %s %s~-^-~ <= HERE\n", line_num_str, str_tmp) != 0) {
		RRR_BUG("Failed to format string in %s\n", __func__);
	}

	*result = rrr_string_builder_buffer_takeover(&string_builder);

	rrr_free(str_tmp);
}
