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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "condition.h"

#include "log.h"
#include "parse.h"
#include "read_constants.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

#define RRR_CONDITION_OK			RRR_READ_OK
#define RRR_CONDITION_HARD_ERROR	RRR_READ_HARD_ERROR
#define RRR_CONDITION_SOFT_ERROR	RRR_READ_SOFT_ERROR

#define RRR_CONDITION_OPERATOR_STACK_MAX 128

enum rrr_condition_priority {
	RRR_CONDITION_PRIORITY_NONE,
	RRR_CONDITION_PRIORITY_CMP,
	RRR_CONDITION_PRIORITY_EQUALITY,
	RRR_CONDITION_PRIORITY_BITWISE_AND,
	RRR_CONDITION_PRIORITY_AND,
	RRR_CONDITION_PRIORITY_OR
};

struct rrr_condition_op {
	char op[4];
	unsigned char prio;
};

// If operators have the same first character, the longest one
// must be above
static const struct rrr_condition_op operators[] = {
		{"(", RRR_CONDITION_PRIORITY_NONE},
		{")", RRR_CONDITION_PRIORITY_NONE},
		{"<=", RRR_CONDITION_PRIORITY_CMP},
		{">=", RRR_CONDITION_PRIORITY_CMP},
		{"<", RRR_CONDITION_PRIORITY_CMP},
		{">", RRR_CONDITION_PRIORITY_CMP},
		{"==", RRR_CONDITION_PRIORITY_EQUALITY},
		{"!=", RRR_CONDITION_PRIORITY_EQUALITY},
		{"&", RRR_CONDITION_PRIORITY_BITWISE_AND},
		{"AND", RRR_CONDITION_PRIORITY_AND},
		{"OR", RRR_CONDITION_PRIORITY_OR},
		{"", 0}
};

static const struct rrr_condition_op *operator_par_open = &operators[0];
static const struct rrr_condition_op *operator_par_close = &operators[1];

struct rrr_condition_shunting_yard_carrier *__rrr_condition_shunting_yard_carrier_new (
		const struct rrr_condition_op *op,
		const char *value,
		size_t value_size
) {
	struct rrr_condition_shunting_yard_carrier *result = malloc(sizeof(*result));
	if (result == NULL) {
		return NULL;
	}

	memset(result, '\0', sizeof(*result));

	result->op = op;
	result->value = value;
	result->value_size = value_size;

//	printf ("New carrier %p op %s value size %lu\n",
//			result, (op != NULL ? op->op : "(null)"), value_size);

	return result;
}

void __rrr_condition_shunting_yard_carrier_free_if_not_null (
		struct rrr_condition_shunting_yard_carrier *carrier
) {
	if (carrier == NULL) {
		return;
	}

//	printf ("Free carrier %p op %s value size %lu\n",
//			carrier, (carrier->op != NULL ? carrier->op->op : "(null)"), carrier->value_size);

	free(carrier);
}

static void __rrr_condition_shunting_yard_clear (
		struct rrr_condition_shunting_yard *shunting_yard
) {
	RRR_LL_DESTROY(shunting_yard, struct rrr_condition_shunting_yard_carrier, __rrr_condition_shunting_yard_carrier_free_if_not_null(node));
	RRR_LL_DESTROY(&shunting_yard->op_stack, struct rrr_condition_shunting_yard_carrier, __rrr_condition_shunting_yard_carrier_free_if_not_null(node));
}

void rrr_condition_clear (
		struct rrr_condition *target
) {
	__rrr_condition_shunting_yard_clear(&target->shunting_yard);
}

static const struct rrr_condition_op *__rrr_condition_parse_op (struct rrr_parse_pos *pos) {
	size_t i = 0;

	do {
		const struct rrr_condition_op *op = &operators[i];
		if (rrr_parse_match_word(pos, op->op)) {
			return op;
		}
	} while(*(operators[++i].op) != '\0');

	return NULL;
}

static int __rrr_condition_shunting_yard_finalize (
		struct rrr_condition_shunting_yard *shunting_yard
) {

	/* The closing ) should clear out the operator stack
	while (RRR_LL_COUNT(&shunting_yard->op_stack) > 0) {
		struct rrr_condition_shunting_yard_carrier *carrier = RRR_LL_SHIFT(&shunting_yard->op_stack);
		if (carrier->op == operator_par_open) {
			RRR_MSG_0("One or more end paranthesis ) missing in condition\n");
			free(carrier);
			return 1;
		}
		RRR_LL_APPEND(shunting_yard, carrier);
	}
	*/

	if (RRR_LL_COUNT(&shunting_yard->op_stack) != 0) {
		RRR_BUG("BUG: Operator stack was not empty in __rrr_condition_shunting_yard_finalize\n");
	}

	if (RRR_LL_COUNT(shunting_yard) > 0) {
		int op_count = 0;
		int value_count = 0;
		RRR_LL_ITERATE_BEGIN(shunting_yard, struct rrr_condition_shunting_yard_carrier);
			if (node->op) {
				op_count++;
			}
			else {
				value_count++;
			}
		RRR_LL_ITERATE_END();

		if (value_count - op_count != 1) {
			RRR_MSG_0("Too many operators in condition expression (%i too many)\n", op_count - value_count + 1);
			return 1;
		}
	}

	return 0;
}

static int __rrr_condition_shunting_yard_shunt_op (
		int *par_level,
		struct rrr_condition_shunting_yard *shunting_yard,
		const struct rrr_condition_op *op
) {
	int ret = RRR_CONDITION_OK;

	struct rrr_condition_shunting_yard_carrier *carrier_new = __rrr_condition_shunting_yard_carrier_new(op, NULL, 0);
	if (carrier_new == NULL) {
		RRR_MSG_0("Could not allocate memory for op carrier in __rrr_condition_shunting_yard_shunt_op\n");
		ret = RRR_CONDITION_HARD_ERROR;
		goto out;
	}

//	printf("Shunting operator %s\n", op->op);

	if (op == operator_par_open) {
		(*par_level)++;
		RRR_LL_UNSHIFT(&shunting_yard->op_stack, carrier_new);
//		printf("Pushed open par, stack length is %i\n", RRR_LL_COUNT(&shunting_yard->op_stack));
		carrier_new = NULL;
	}
	else if (op == operator_par_close) {
		(*par_level)--;
		if (*par_level < 0) {
			RRR_MSG_0("Too many end paranthesis ')' in condition\n");
			ret = RRR_CONDITION_SOFT_ERROR;
			goto out;
		}

		while (RRR_LL_COUNT(&shunting_yard->op_stack) > 0) {
			struct rrr_condition_shunting_yard_carrier *carrier = RRR_LL_SHIFT(&shunting_yard->op_stack);
//			printf("Checking op on stack %s\n", carrier->op->op);
			if (carrier->op == operator_par_open) {
//				printf("Found open par, free %p\n", carrier);
				__rrr_condition_shunting_yard_carrier_free_if_not_null(carrier);
				break;
			}
			RRR_LL_APPEND(shunting_yard, carrier);
		}
	}
	else if (RRR_LL_COUNT(&shunting_yard->op_stack) == 0) {
//		printf("Pushed op %s, stack length is %i\n", carrier_new->op->op, RRR_LL_COUNT(&shunting_yard->op_stack));
		RRR_LL_UNSHIFT(&shunting_yard->op_stack, carrier_new);
		carrier_new = NULL;
	}
	else {
		while (RRR_LL_COUNT(&shunting_yard->op_stack) > 0) {
			struct rrr_condition_shunting_yard_carrier *carrier = RRR_LL_FIRST(&shunting_yard->op_stack);
			if (carrier->op->prio < carrier_new->op->prio && carrier->op != operator_par_open) {
				carrier = RRR_LL_SHIFT(&shunting_yard->op_stack);
				RRR_LL_APPEND(shunting_yard, carrier);
			}
			else {
				break;
			}
		}
		RRR_LL_UNSHIFT(&shunting_yard->op_stack, carrier_new);
		carrier_new = NULL;
	}

	out:
	__rrr_condition_shunting_yard_carrier_free_if_not_null(carrier_new);
	return ret;
}

static int __rrr_condition_shunting_yard_shunt_value (
		struct rrr_condition_shunting_yard *shunting_yard,
		const char *value,
		size_t size
) {
	int ret = 0;
	struct rrr_condition_shunting_yard_carrier *carrier_new = __rrr_condition_shunting_yard_carrier_new(NULL, value, size);
	if (carrier_new == NULL) {
		RRR_MSG_0("Could not allocate memory for carrier in __rrr_condition_shunting_yard_shunt_value\n");
		ret = RRR_CONDITION_HARD_ERROR;
		goto out;
	}

//	printf("Shunting a value\n");

	RRR_LL_APPEND(shunting_yard, carrier_new);

	out:
	return ret;
}

static size_t __rrr_condition_min(size_t a, size_t b) {
	return (a < b ? a : b);
}

static void __rrr_condition_shunting_yard_dump (
		const struct rrr_condition_shunting_yard *shunting_yard
) {
	RRR_LL_ITERATE_BEGIN(shunting_yard, const struct rrr_condition_shunting_yard_carrier);
		if (node->op != NULL) {
			printf("%s ", node->op->op);
		}
		else {
			char tmp[64];
			memset(tmp, '\0', sizeof(tmp));
			memcpy(tmp, node->value, __rrr_condition_min(sizeof(tmp)-1, node->value_size));
			printf("%s ", tmp);
		}
	RRR_LL_ITERATE_END();
}

void rrr_condition_dump (
		const struct rrr_condition *condition
) {
	__rrr_condition_shunting_yard_dump(&condition->shunting_yard);
}

static const char *rrr_condition_str_false = "0";
//static const char *rrr_condition_str_true = "1";

int rrr_condition_parse (
		struct rrr_condition *target,
		struct rrr_parse_pos *pos
) {
	struct rrr_condition_shunting_yard *shunting_yard = &target->shunting_yard;

	int ret = RRR_CONDITION_OK;

	int par_level = 0;
//	int prev_was_value = 0;
	while (!RRR_PARSE_CHECK_EOF(pos)) {
//		printf("Parse position: %s\n", pos->data + pos->pos);
		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		const struct rrr_condition_op *op = __rrr_condition_parse_op(pos);
		if (par_level == 0 && op != operator_par_open) {
			RRR_MSG_0("Did not find expected opening paranthesis ( in condition expression\n");
			ret = RRR_CONDITION_SOFT_ERROR;
			goto out_clear;
		}

		if (op != NULL) {
			if ((ret = __rrr_condition_shunting_yard_shunt_op (
					&par_level,
					shunting_yard,
					op
			)) != 0) {
				goto out_clear;
			}

			if (par_level == 0) {
				// Last ) found
				break;
			}

//			prev_was_value = 0;
		}
		else {
			rrr_parse_ignore_spaces_and_increment_line(pos);
			if (RRR_PARSE_CHECK_EOF(pos)) {
				break;
			}

/*			if (prev_was_value) {
				RRR_MSG_0("Invalid expression in condition at line %i, found two values after each other without operator in between\n", pos->line);
				ret = RRR_CONDITION_SOFT_ERROR;
				goto out_clear;
			}*/

			int start;
			int end;

			// If there is 1 character, start will be equal to end.
			// If there are no matches, end minus start will be negative

			if (rrr_parse_match_word(pos, "{")) {
				// Variable name
				rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_LETTERS|RRR_PARSE_MATCH_NUMBERS);
				if (end - start < 0) {
					RRR_MSG_0("Variable name missing after {\n");
					break;
				}
				else {
					start -= 1;
				}
				if (!rrr_parse_match_word(pos, "}")) {
					RRR_MSG_0("Missing } after variable name in condition\n");
					break;
				}
				end += 1;
			}
			else if (rrr_parse_match_word_case(pos, "0x")) {
				rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_HEX);
				if (end - start < 0) {
					RRR_MSG_0("Hex value missing after 0x\n");
					break;
				}
				else {
					start -= 2;
				}
			}
			else {
				rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_NUMBERS);
				if (end - start < 0) {
					RRR_MSG_0("Value missing\n");
					break;
				}
			}

			if ((ret = __rrr_condition_shunting_yard_shunt_value(shunting_yard, pos->data + start, end - start + 1)) != 0) {
				goto out_clear;
			}

//			prev_was_value = 1;
		}
	}

	if (par_level != 0) {
		RRR_MSG_0("Syntax error in condition expression at line %i, no end parenthesis ) found, paranthesis level is now %i\n",
				pos->line, par_level);
		ret = RRR_CONDITION_SOFT_ERROR;
		goto out_clear;
	}

	if (RRR_LL_COUNT(shunting_yard) == 0) {
		// Push dummy false value
		if ((ret = __rrr_condition_shunting_yard_shunt_value (
				shunting_yard,
				rrr_condition_str_false,
				strlen(rrr_condition_str_false)
	)) != 0) {
			goto out_clear;
		}
	}

	if ((ret = __rrr_condition_shunting_yard_finalize(shunting_yard)) != 0) {
		goto out_clear;
	}

//	 __rrr_condition_shunting_yard_dump(shunting_yard);
//	printf("\n");

	goto out;
	out_clear:
		rrr_condition_clear(target);
	out:
		if (ret != 0) {
			RRR_MSG_0("Parsing of condition expression stopped at line %i position %i\n",
					pos->line, pos->pos - pos->line_begin_pos + 1);
		}
		return ret;
}
