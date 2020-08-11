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

#ifndef RRR_CONDITION_H
#define RRR_CONDITION_H

#include <sys/types.h>

#include "util/linked_list.h"

struct rrr_parse_pos;

struct rrr_condition_shunting_yard_carrier {
	RRR_LL_NODE(struct rrr_condition_shunting_yard_carrier);
	const struct rrr_condition_op *op;
	const char *value;
	size_t value_size;
};

struct rrr_condition_shunting_yard_stack {
	RRR_LL_HEAD(struct rrr_condition_shunting_yard_carrier);
};

struct rrr_condition_shunting_yard {
	RRR_LL_HEAD(struct rrr_condition_shunting_yard_carrier);
	struct rrr_condition_shunting_yard_stack op_stack;
};

struct rrr_condition {
	struct rrr_condition_shunting_yard shunting_yard;
};

void rrr_condition_clear (
		struct rrr_condition *target
);
void rrr_condition_dump (
		const struct rrr_condition *condition
);
int rrr_condition_parse (
		struct rrr_condition *target,
		struct rrr_parse_pos *pos
);

#endif /* RRR_CONDITION_H */
