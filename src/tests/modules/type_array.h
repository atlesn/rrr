/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <inttypes.h>

struct vl_message;
struct instance_metadata_collection;

int test_type_array (
		struct vl_message **result_message_1,
		struct vl_message **result_message_2,
		struct instance_metadata_collection *instances,
		const char *input_name,
		const char *input_socket_name,
		const char *output_name_1,
		const char *output_name_2
);

int test_type_array_mysql_and_network (
		struct instance_metadata_collection *instances,
		const char *input_buffer_name,
		const char *tag_buffer_name,
		const char *mysql_name,
		const struct vl_message *message
);
