/*

Voltage Logger

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

struct vl_thread_collection;
struct instance_metadata_collection;
struct rrr_config;
struct cmd_data;

int main_start_threads (
		struct vl_thread_collection **thread_collection,
		struct instance_metadata_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd
);
void main_threads_stop (struct vl_thread_collection *collection, struct instance_metadata_collection *instances);
int main_parse_cmd_arguments(struct cmd_data* cmd, int argc, const char* argv[]);
