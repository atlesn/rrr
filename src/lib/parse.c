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

#include "log.h"
#include "parse.h"
#include "util/macro_utils.h"

void rrr_parse_pos_init (
		struct rrr_parse_pos *target,
		const char *data,
		int size
) {
	target->data = data;
	target->pos = 0;
	target->size = size;
	target->line = 1;
	target->line_begin_pos = 0;
}

void rrr_parse_ignore_space_and_tab (struct rrr_parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

	while ((c == ' ' || c == '\t') && pos->pos < pos->size) {
		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		c = pos->data[pos->pos];
	}
}

void rrr_parse_ignore_spaces_and_increment_line (struct rrr_parse_pos *pos) {
	if (pos->pos >= pos->size) {
		return;
	}

	char c = pos->data[pos->pos];

	while ((c == ' ' || c == '\t' || c == '\n' || c == '\r') && pos->pos < pos->size) {
		char next = pos->pos + 1 < pos->size ? pos->data[pos->pos + 1] : '\0';

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

		c = pos->data[pos->pos];
	}
}

void rrr_parse_comment (struct rrr_parse_pos *pos) {
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
	int pos_orig = pos->pos;

	while (*word_pos != '\0' && pos->pos < pos->size) {
		char c = pos->data[pos->pos];
		char c_case = '\0';

		if (c >= 'a' && c <= 'z') {
			c_case = c - 32;
		}
		else if (c >= 'A' && c <= 'Z') {
			c_case = c + 32;
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
	int pos_orig = pos->pos;

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

void rrr_parse_match_letters (
		struct rrr_parse_pos *pos,
		int *start,
		int *end,
		int flags
) {
	*start = pos->pos;
	*end = pos->pos;

	char c = pos->data[pos->pos];
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		if (	((flags & RRR_PARSE_MATCH_SPACE_TAB) && RRR_PARSE_MATCH_C_SPACE_TAB(c)) ||
				((flags & RRR_PARSE_MATCH_COMMAS) && RRR_PARSE_MATCH_C_COMMAS(c)) ||
				((flags & RRR_PARSE_MATCH_LETTERS) && RRR_PARSE_MATCH_C_LETTER(c)) ||
				((flags & RRR_PARSE_MATCH_HEX) && RRR_PARSE_MATCH_C_HEX(c)) ||
				((flags & RRR_PARSE_MATCH_NUMBERS) && RRR_PARSE_MATCH_C_NUMBER(c)) ||
				((flags & RRR_PARSE_MATCH_NEWLINES) && RRR_PARSE_MATCH_C_NEWLINES(c)) ||
				((flags & RRR_PARSE_MATCH_NULL) && RRR_PARSE_MATCH_C_NULL(c))
		) {
			// OK
		}
		else {
			break;
		}

		pos->pos++;
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
		c = pos->data[pos->pos];
	}

	*end = pos->pos - 1;
}

void rrr_parse_match_until (
		struct rrr_parse_pos *pos,
		int *start,
		int *end,
		int flags
) {
	*start = pos->pos;
	*end = pos->pos;

	int pos_orig = pos->pos;

	int found = 0;
	char c = pos->data[pos->pos];
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		if (	((flags & RRR_PARSE_MATCH_SPACE_TAB) && RRR_PARSE_MATCH_C_SPACE_TAB(c)) ||
				((flags & RRR_PARSE_MATCH_COMMAS) && RRR_PARSE_MATCH_C_COMMAS(c)) ||
				((flags & RRR_PARSE_MATCH_LETTERS) && RRR_PARSE_MATCH_C_LETTER(c)) ||
				((flags & RRR_PARSE_MATCH_HEX) && RRR_PARSE_MATCH_C_HEX(c)) ||
				((flags & RRR_PARSE_MATCH_NUMBERS) && RRR_PARSE_MATCH_C_NUMBER(c)) ||
				((flags & RRR_PARSE_MATCH_NEWLINES) && RRR_PARSE_MATCH_C_NEWLINES(c)) ||
				((flags & RRR_PARSE_MATCH_NULL) && RRR_PARSE_MATCH_C_NULL(c))
		) {
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

	*end = pos->pos - 1;
}

void rrr_parse_non_newline (
		struct rrr_parse_pos *pos,
		int *start,
		int *end
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

	*end = pos->pos - 1;
}

int rrr_parse_extract_string (
		char **target,
		struct rrr_parse_pos *pos,
		const int begin,
		const int length
) {
	*target = NULL;

	if (length == 0) {
		RRR_BUG("BUG: length was 0 in __rrr_config_extract_string\n");
	}

	char *bytes = malloc(length + 1);

	if (bytes == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_config_extract_string\n");
		return 1;
	}

	memcpy(bytes, pos->data + begin, length);

	bytes[length] = '\0';

	*target = bytes;

	return 0;
}

int rrr_parse_str_split (
		const char *str,
		char chr,
		size_t elements_max,
		int (*callback)(const char *elements[], size_t elements_count, void *arg),
		void *callback_arg
) {
	int ret = 0;

	size_t elements_count = 0;
	const char *elements[elements_max];

	char *tmp = NULL;

	for (size_t i = 0; i < elements_max; i++) {
		elements[i] = NULL;
	}

	if (*str == '\0') {
		goto do_callback;
	}

	if ((tmp = strdup(str)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_parse_str_split\n");
		ret = 1;
		goto out;
	}

	char *pos = tmp;
	const char *element = tmp;
	int zero_found = 0;
	while (!zero_found) {
//		printf ("Split pos %s\n", pos);

		if (elements_count == elements_max) {
			RRR_MSG_0("Too many elements while splitting string (more than %lu)\n", elements_max);
			ret = 1;
			goto out;
		}

		if (*pos == chr || *pos == '\0') {
			if (*pos == '\0') {
				zero_found = 1;
			}

			*pos = '\0';

			elements[elements_count++] = element;

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
		size_t *result_length,
		const char *str,
		char end_char
) {
	*result = NULL;
	*result_length = 0;

	const char *pos = str;
	const char *end = strchr(str, end_char);

	if (end == NULL) {
		return 1;
	}

	size_t length = end - pos;

	char *match = malloc(length + 1);
	if (match == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_parse_extract_until\n");
		return 1;
	}

	memcpy(match, str, length);
	match[length] = '\0';

	*result = match;
	*result_length = length;

	return 0;
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
