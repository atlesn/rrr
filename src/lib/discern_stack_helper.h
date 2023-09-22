/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_DISCERN_STACK_HELPER_H
#define RRR_DISCERN_STACK_HELPER_H

struct rrr_msg_msg;

struct rrr_discern_stack_helper_callback_data {
	const struct rrr_msg_msg *msg;
};

int rrr_discern_stack_helper_topic_filter_resolve_cb (
		int *result,
		const char *topic_filter,
		void *arg
);

int rrr_discern_stack_helper_array_tag_resolve_cb (
		int *result,
		const char *array_tag,
		void *arg
);

#endif /* RRR_DISCERN_STACK_HELPER_H */
