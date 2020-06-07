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

struct rrr_message;
struct instance_metadata_collection;

int test_averager (
		struct instance_metadata_collection *instances,
		const char *output_name_averager
);

int test_array (
		struct instance_metadata_collection *instances,
		const char *output_name
);

int test_anything (
		struct instance_metadata_collection *instances,
		const char *output_name
);

int test_type_array_mysql (
		struct instance_metadata_collection *instances,
		const char *tag_buffer_name
);
