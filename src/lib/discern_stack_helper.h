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

#include "rrr_types.h"
#include "discern_stack.h"

struct rrr_msg_msg;

struct rrr_discern_stack_helper_callback_data {
	const struct rrr_msg_msg *msg;
	int index_produced;
};

int rrr_discern_stack_helper_topic_filter_resolve_cb (RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS);
int rrr_discern_stack_helper_array_tag_resolve_cb (RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS);

#endif /* RRR_DISCERN_STACK_HELPER_H */
