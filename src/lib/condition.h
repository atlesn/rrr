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
#include <inttypes.h>

#include "read_constants.h"
#include "util/linked_list.h"

#define RRR_CONDITION_VALUE_MAX 64

#define RRR_CONDITION_OK			RRR_READ_OK
#define RRR_CONDITION_HARD_ERROR	RRR_READ_HARD_ERROR
#define RRR_CONDITION_SOFT_ERROR	RRR_READ_SOFT_ERROR

#define RRR_CONDITION_NAME_EVALUATE_CALLBACK_ARGS \
	uint64_t *result, int *is_signed, const char *name, void *arg

struct rrr_string_builder;
struct rrr_parse_pos;

struct rrr_condition_shunting_yard_carrier {
	RRR_LL_NODE(struct rrr_condition_shunting_yard_carrier);
	const struct rrr_condition_op *op;
	char value[RRR_CONDITION_VALUE_MAX];
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
int rrr_condition_clone (
		struct rrr_condition *target,
		const struct rrr_condition *source
);
void rrr_condition_dump (
		struct rrr_string_builder *string_builder,
		const struct rrr_condition *condition
);
int rrr_condition_interpret (
		struct rrr_condition *target,
		struct rrr_parse_pos *pos
);
int rrr_condition_interpret_raw (
		struct rrr_condition *target,
		const char *buf,
		size_t buf_length
);
int rrr_condition_iterate (
		const struct rrr_condition *condition,
		int (*callback)(const struct rrr_condition_op *op, const char *value, const char *tag, void *arg),
		void *callback_arg
);
int rrr_condition_evaluate (
		uint64_t *result,
		const struct rrr_condition *condition,
		int (*name_evaluate_callback)(RRR_CONDITION_NAME_EVALUATE_CALLBACK_ARGS),
		void *name_evaluate_callback_arg
);

#endif /* RRR_CONDITION_H */
