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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "../lib/rrr_endian.h"
#include "../lib/messages_head.h"
#include "../lib/rrr_socket_msg_checksum.h"
#include "../lib/rrr_socket_msg_head.h"

/* Remember to disable compiler alignment */
struct test_data {
	char be4[4];
	char be3[3];
	int16_t be2;
	char be1;

	char sep1;

	char le4[4];
	char le3[3];
	int16_t le2;
	char le1;

	char sep2[2];

	char blob_a[8];
	char blob_b[8];

	struct rrr_message msg;
} __attribute__((packed));

void test_data_init (struct test_data *data) {
	data->be4[0] = 1;
	data->be4[2] = 2;

	data->be3[0] = 1;
	data->be3[1] = 2;

	data->be2 = htobe16(-33);

	data->be1 = 1;

	data->sep1 = ';';

// Put an incorrect number to check if test fails
	data->le4[1] = 2;
//	data->le4[1] = 5;
	data->le4[3] = 1;

	data->le3[1] = 2;
	data->le3[2] = 1;

	data->le2 = htole16(-33);

	data->le1 = 1;

	data->sep2[0] = '|';
	data->sep2[1] = '|';

	sprintf(data->blob_a, "abcdefg");
	sprintf(data->blob_b, "gfedcba");

	data->msg.msg_size = sizeof(struct rrr_message) - 1;
	data->msg.msg_type = RRR_SOCKET_MSG_TYPE_MESSAGE;
	data->msg.topic_length = 0;
	MSG_SET_TYPE(&data->msg, MSG_TYPE_MSG);
	MSG_SET_CLASS(&data->msg, MSG_CLASS_DATA);

	MSG_TO_BE(&data->msg);
	rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) &data->msg);
}

int main (int argc, char **argv) {
	int ret = 0;
	int fd = 0;

	if (argc != 2) {
		fprintf(stderr, "Output file argument missing to make_test_data\n");
		ret = 1;
		goto out;
	}

	struct test_data data = {0};
	test_data_init(&data);

	if ((fd = open(argv[1], O_CREAT|O_TRUNC|O_WRONLY, S_IRWXU)) <= 0) {
		fprintf (stderr, "Could not open output file '%s' for writing: %s\n",
				argv[1], strerror(errno));
		ret = 1;
		goto out;
	}

	if (write(fd, &data, sizeof(data)) != sizeof(data)) {
		fprintf (stderr, "Could not write to output file '%s': %s\n",
				argv[1], strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	if (fd > 0) {
		close(fd);
	}

	return ret;
}
