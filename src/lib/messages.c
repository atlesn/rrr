/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "messages.h"

int find_string(const char *str, unsigned long int size, const char *search, const char **result) {
	unsigned long int search_length = strlen(search);

	if (search_length > size) {
		fprintf (stderr, "Message was to short\n");
		return 1;
	}
	if (strncmp(str, search, search_length) != 0) {
		return 1;
	}
	*result = str + size + 1;
	return 0;
}

int find_number(const char *str, unsigned long int size, const char **end, uint64_t *result) {
	*end = memchr(str, ':', size);
	if (*end == NULL) {
		fprintf (stderr, "Missing delimeter in message while searching for number\n");
		return 1;
	}

	if (*end == str) {
		fprintf (stderr, "Missing number argument in message\n");
		return 1;
	}

	char tmp[MSG_TMP_SIZE];
	if (*end - str + 1 > MSG_TMP_SIZE) {
		fprintf (stderr, "Too long argument while searching for number in message\n");
		return 1;
	}

	strncpy(tmp, str, *end-str);
	tmp[*end-str] = '\0';

	char *endptr;
	*result = strtoull(tmp, &endptr, 10);
	if (*endptr != '\0') {
		fprintf (stderr, "Invalid characters in number argument of message\n");
		return 1;
	}

	*end = *end + 1;
	return 0;
}

int init_message (
	unsigned long int type,
	unsigned long int class,
	uint64_t timestamp_from,
	uint64_t timestamp_to,
	uint64_t data_numeric,
	const char *data,
	unsigned long int data_size,
	struct vl_message *result
) {
	memset(result, '\0', sizeof(*result));

	result->type = type;
	result->class = class;
	result->timestamp_from = timestamp_from;
	result->timestamp_to = timestamp_to;
	result->data_numeric = data_numeric;

	// Always have a \0 at the end
	if (data_size + 1 > MSG_DATA_MAX_LENGTH) {
		fprintf (stderr, "Message length was too long\n");
		return 1;
	}

	result->length = data_size;
	memcpy (result->data, data, data_size);

	return 0;
}

int parse_message(const char *msg, unsigned long int size, struct vl_message *result) {
	memset (result, '\0', sizeof(*result));
	const char *pos = msg;
	const char *end = msg + size;

	// {MSG|MSG_ACK|MSG_TAG}:{AVG|MAX|MIN|POINT|INFO}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_string(pos, end - pos, "MSG", &pos) == 0) {
		result->type = MSG_TYPE_MSG;
	}
	else if (find_string(pos, end - pos, "MSG_ACK", &pos) == 0) {
		result->type = MSG_TYPE_ACK;
	}
	else if (find_string(pos, end - pos, "MSG_TAG", &pos) == 0) {
		result->type = MSG_TYPE_TAG;
	}
	else {
		fprintf (stderr, "Unknown message type\n");
		return 1;
	}

	// {AVG|MAX|MIN|POINT|INFO}:{LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_string (pos, end - pos, "AVG", &pos) == 0) {
		result->class = MSG_CLASS_AVG;
	}
	else if (find_string (pos, end - pos, "MAX", &pos) == 0) {
		result->class = MSG_CLASS_MAX;
	}
	else if (find_string (pos, end - pos, "MIN", &pos) == 0) {
		result->class = MSG_CLASS_MIN;
	}
	else if (find_string (pos, end - pos, "AVG", &pos) == 0) {
		result->class = MSG_CLASS_AVG;
	}
	else if (find_string (pos, end - pos, "INFO", &pos) == 0) {
		result->class = MSG_CLASS_INFO;
	}
	else {
		fprintf (stderr, "Unknown message class\n");
		return 1;
	}

	// {LENGTH}:{TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_number(pos, end-pos, &pos, &result->length) != 0) {
		return 1;
	}

	// {TIMESTAMP_FROM}:{TIMESTAMP_TO}:{DATA}
	if (find_number(pos, end-pos, &pos, &result->timestamp_from) != 0) {
		return 1;
	}

	// {TIMESTAMP_TO}:{DATA}
	if (find_number(pos, end-pos, &pos, &result->timestamp_to) != 0) {
		return 1;
	}

	// {DATA}
	unsigned long int data_length = size - (pos - msg);
	if (data_length > MSG_DATA_MAX_LENGTH) {
		fprintf (stderr, "Message data size was too long\n");
		return 1;
	}
	if (result->length != data_length) {
		fprintf (stderr, "Message reported data length did not match actual length\n");
		return 1;
	}

	result->length = data_length;
	memcpy(result->data, pos, data_length);

	return 0;
}
