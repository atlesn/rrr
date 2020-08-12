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
#include "util/linked_list.h"
#include "util/macro_utils.h"
#include "util/posix.h"

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

// Count correctly!
static const struct rrr_condition_op *operator_par_open =	&operators[0];
static const struct rrr_condition_op *operator_par_close =	&operators[1];
static const struct rrr_condition_op *operator_lteq =		&operators[2];
static const struct rrr_condition_op *operator_gteq =		&operators[3];
static const struct rrr_condition_op *operator_lt =			&operators[4];
static const struct rrr_condition_op *operator_gt =			&operators[5];
static const struct rrr_condition_op *operator_eq =			&operators[6];
static const struct rrr_condition_op *operator_ne =			&operators[7];
static const struct rrr_condition_op *operator_bw_and =		&operators[8];
static const struct rrr_condition_op *operator_and =		&operators[9];
static const struct rrr_condition_op *operator_or =			&operators[10];

int __rrr_condition_shunting_yard_carrier_allocate (
		struct rrr_condition_shunting_yard_carrier **target
) {
	*target = NULL;

	struct rrr_condition_shunting_yard_carrier *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_condition_shunting_yard_carrier_allocate\n");
		return RRR_CONDITION_HARD_ERROR;
	}

	memset(result, '\0', sizeof(*result));

	*target = result;

	return RRR_CONDITION_OK;
}

int __rrr_condition_shunting_yard_carrier_new (
		struct rrr_condition_shunting_yard_carrier **target,
		const struct rrr_condition_op *op,
		const char *value,
		size_t value_length
) {
	int ret = RRR_CONDITION_OK;

	struct rrr_condition_shunting_yard_carrier *result = NULL;

	if ((ret =__rrr_condition_shunting_yard_carrier_allocate(&result)) != 0) {
		goto out;
	}

	if (value_length > sizeof(result->value) - 1) {
		RRR_MSG_0("Value in condition was too long, max is %lu bytes\n", sizeof(result->value) - 1);
		ret = RRR_CONDITION_SOFT_ERROR;
		goto out_free;
	}

	result->op = op;

	if (value_length > 0) {
		memcpy(result->value, value, value_length);
		result->value[value_length] = '\0';
	}

	*target = result;

	goto out;
	out_free:
		free(result);
	out:
		return ret;
}

void __rrr_condition_shunting_yard_carrier_free_if_not_null (
		struct rrr_condition_shunting_yard_carrier *carrier
) {
	if (carrier == NULL) {
		return;
	}

//	printf ("Free carrier %p op %s value size %lu\n",
//			carrier, (carrier->op != NULL ? carrier->op->op : "(null)"), carrier->value_length);

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

static int __rrr_condition_shunting_yard_clone (
		struct rrr_condition_shunting_yard *target,
		const struct rrr_condition_shunting_yard *source
) {
	int ret = 0;

	// Note : Stack is not cloned, usually not needed and is empty after parsing

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_condition_shunting_yard_carrier);
		struct rrr_condition_shunting_yard_carrier *new_carrier = NULL;

		if ((ret =__rrr_condition_shunting_yard_carrier_allocate(&new_carrier)) != 0) {
			goto out;
		}

		*new_carrier = *node;
		RRR_LL_NODE_INIT(new_carrier);
		RRR_LL_APPEND(target, new_carrier);
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_condition_clone (
		struct rrr_condition *target,
		const struct rrr_condition *source
) {
	return __rrr_condition_shunting_yard_clone (&target->shunting_yard, &source->shunting_yard);
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

	struct rrr_condition_shunting_yard_carrier *carrier_new = NULL;
	if ((ret = __rrr_condition_shunting_yard_carrier_new(&carrier_new, op, NULL, 0)) != 0) {
		RRR_MSG_0("Could not allocate memory for op carrier in __rrr_condition_shunting_yard_shunt_op\n");
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

	struct rrr_condition_shunting_yard_carrier *carrier_new = NULL;
	if ((ret = __rrr_condition_shunting_yard_carrier_new(&carrier_new, NULL, value, size)) != 0) {
		RRR_MSG_0("Could not allocate memory for carrier in __rrr_condition_shunting_yard_shunt_value\n");
		goto out;
	}

//	printf("Shunting a value\n");

	RRR_LL_APPEND(shunting_yard, carrier_new);

	out:
	return ret;
}

static void __rrr_condition_shunting_yard_dump (
		const struct rrr_condition_shunting_yard *shunting_yard
) {
	RRR_LL_ITERATE_BEGIN(shunting_yard, const struct rrr_condition_shunting_yard_carrier);
		if (node->op != NULL) {
			printf("%s ", node->op->op);
		}
		else {
			printf("%s ", node->value);
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

static const char *__rrr_condition_extract_name (
		char value_tmp[RRR_CONDITION_VALUE_MAX],
		const char *value_orig
) {
	memcpy(value_tmp, value_orig, RRR_CONDITION_VALUE_MAX);
	value_tmp[strlen(value_tmp) - 1] = '\0'; // Chop of }
	return value_tmp + 1; // Chop of {
}

int rrr_condition_iterate (
		const struct rrr_condition *condition,
		int (*callback)(const struct rrr_condition_op *op, const char *value, const char *tag, void *arg),
		void *callback_arg
) {
	int ret = 0;

	char value_tmp[RRR_CONDITION_VALUE_MAX];

	RRR_LL_ITERATE_BEGIN(&condition->shunting_yard, const struct rrr_condition_shunting_yard_carrier);
		const char *tag_to_pass = NULL;
		const char *value_to_pass = NULL;

		if (*(node->value) == '{') {
			tag_to_pass = __rrr_condition_extract_name (value_tmp, node->value);
		}
		else {
			value_to_pass = node->value;
		}

		if ((ret = callback(node->op, value_to_pass, tag_to_pass, callback_arg)) != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

struct rrr_condition_running_result {
	// Set to NULL when evaluated
	const struct rrr_condition_shunting_yard_carrier *carrier;
	uint64_t result;
};

static uint64_t __rrr_condition_evaluate_operator (
		uint64_t a,
		uint64_t b,
		const struct rrr_condition_op *op
) {
	if (op == operator_lteq) {
		return (a <= b);
	}
	else if (op == operator_gteq) {
		return (a >= b);
	}
	else if (op == operator_lt) {
		return (a < b);
	}
	else if (op == operator_gt) {
		return (a > b);
	}
	else if (op == operator_eq) {
		return (a == b);
	}
	else if (op == operator_ne) {
		return (a != b);
	}
	else if (op == operator_bw_and) {
		return (a & b);
	}
	else if (op == operator_and) {
		return (a && b);
	}
	else if (op == operator_or) {
		return (a || b);
	}

	RRR_BUG("BUG: Unknown operator %p to __rrr_condition_evaluate_operator\n", op);

	return 0;
}

int rrr_condition_evaluate (
		uint64_t *result,
		const struct rrr_condition *condition,
		int (*name_evaluate_callback)(uint64_t *result, const char *name, void *arg),
		void *name_evaluate_callback_arg
) {
	int ret = RRR_CONDITION_OK;

	*result = 0;

	uint64_t result_tmp = 0;

	struct rrr_condition_running_result results[RRR_LL_COUNT(&condition->shunting_yard)];

	char value_tmp[RRR_CONDITION_VALUE_MAX];

	memset(results, '\0', sizeof(results));

	ssize_t element_count = 0;
	RRR_LL_ITERATE_BEGIN(&condition->shunting_yard, const struct rrr_condition_shunting_yard_carrier);
		results[element_count++].carrier = node;
	RRR_LL_ITERATE_END();

	for (ssize_t i = 0; i < element_count; i++) {
		struct rrr_condition_running_result *position = &results[i];
		if (position->carrier->op != NULL) {
			if (i < 2) {
				RRR_BUG("BUG: Too few values before operator in rrr_condition_evaluate\n");
			}
			struct rrr_condition_running_result *position_a = &results[i-1];
			struct rrr_condition_running_result *position_b = &results[i-2];
			position->result = __rrr_condition_evaluate_operator (
					position_a->result,
					position_b->result,
					position->carrier->op
			);
			position->carrier = NULL;
			result_tmp = position->result;
		}
		else {
			if (*(position->carrier->value) == '{') {
				const char *tag_to_pass = __rrr_condition_extract_name (value_tmp, position->carrier->value);
				if ((ret = name_evaluate_callback (
						&position->result,
						tag_to_pass,
						name_evaluate_callback_arg
				)) != 0) {
					RRR_MSG_0("Error %i from callback in rrr_condition_evaluate\n");
					ret = RRR_CONDITION_SOFT_ERROR;
					goto out;
				}
			}
			else if (	strlen(position->carrier->value) >= 2 &&
						rrr_posix_strncasecmp(position->carrier->value, "0x", 2) == 0
			) {
				const char *value_start = position->carrier->value + 2;
				char *endptr = NULL;
				position->result = strtoull(value_start, &endptr, 16);
				if (endptr == NULL || *endptr != '\0') {
					// This might be a bug, parser should validate the numbers
					RRR_MSG_0("Could not evaluate hex value '%s' in rrr_condition_evaluate\n");
					ret = RRR_CONDITION_SOFT_ERROR;
					goto out;
				}
			}
			else {
				char *endptr = NULL;
				position->result = strtoull(position->carrier->value, &endptr, 10);
				if (endptr == NULL || *endptr != '\0') {
					// This might be a bug, parser should validate the numbers
					RRR_MSG_0("Could not evaluate decimal value '%s' in rrr_condition_evaluate\n");
					ret = RRR_CONDITION_SOFT_ERROR;
					goto out;
				}
			}
			position->carrier = NULL;
		}
	}

	*result = result_tmp;

	out:
	return ret;
}
