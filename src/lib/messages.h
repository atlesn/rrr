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

#ifndef VL_MESSAGES_H
#define VL_MESSAGES_H

#define MSG_TYPE_MSG 1
#define MSG_TYPE_ACK 2
#define MSG_TYPE_TAG 3

#define MSG_CLASS_POINT 1
#define MSG_CLASS_AVG 2
#define MSG_CLASS_MAX 3
#define MSG_CLASS_MIN 4
#define MSG_CLASS_INFO 10

#define MSG_DATA_MAX_LENGTH 256

#define MSG_TMP_SIZE 64

struct vl_message {
	unsigned long int type;
	unsigned long int class;
	uint64_t timestamp_from;
	uint64_t timestamp_to;
	unsigned long int length;
	char data[MSG_DATA_MAX_LENGTH];
};
int init_message (
		unsigned long int type,
		unsigned long int class,
		uint64_t timestamp_from,
		uint64_t timestamp_to,
		const char *data,
		unsigned long int data_size,
		struct vl_message *result
);
int parse_message(const char *msg, unsigned long int size, struct vl_message *result);

#endif
