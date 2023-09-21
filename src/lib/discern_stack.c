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

#include <assert.h>

#include "discern_stack.h"
#include "read_constants.h"

#include "parse.h"
#include "allocator.h"
#include "mqtt/mqtt_topic.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

#define RRR_DISCERN_STACK_OK     RRR_READ_OK
#define RRR_DISCERN_STACK_BAIL   RRR_READ_EOF

enum rrr_discern_stack_element_type {
	RRR_DISCERN_STACK_E_NONE,
	RRR_DISCERN_STACK_E_TOPIC_FILTER,
	RRR_DISCERN_STACK_E_ARRAY_TAG,
	RRR_DISCERN_STACK_E_BOOL,
	RRR_DISCERN_STACK_E_DESTINATION
};

// DO NOT change order of elements without understanding access macros
enum rrr_discern_stack_operator_type {
	RRR_DISCERN_STACK_OP_PUSH,
	RRR_DISCERN_STACK_OP_AND,
	RRR_DISCERN_STACK_OP_OR,
	RRR_DISCERN_STACK_OP_APPLY,
	RRR_DISCERN_STACK_OP_NOT,
	RRR_DISCERN_STACK_OP_POP,
	RRR_DISCERN_STACK_OP_BAIL
};

#define OP_ARG_COUNT(op) (op < RRR_DISCERN_STACK_OP_AND ? 0 : op > RRR_DISCERN_STACK_OP_APPLY ? 1 : 2)

#define OP_NAME(op)                                 \
  (op == RRR_DISCERN_STACK_OP_PUSH ? "PUSH" :               \
   op == RRR_DISCERN_STACK_OP_AND ? "AND" :                 \
   op == RRR_DISCERN_STACK_OP_OR ? "OR" :                   \
   op == RRR_DISCERN_STACK_OP_APPLY ? "APPLY" :             \
   op == RRR_DISCERN_STACK_OP_NOT ? "NOT" :                 \
   op == RRR_DISCERN_STACK_OP_POP ? "POP" :                 \
   op == RRR_DISCERN_STACK_OP_BAIL ? "BAIL" : "")

struct rrr_discern_stack_element {
	RRR_LL_NODE(struct rrr_discern_stack_element);
	enum rrr_discern_stack_element_type type;
	enum rrr_discern_stack_operator_type op;
	void *data;
	rrr_length data_size;
};

struct rrr_discern_stack_list {
	RRR_LL_HEAD(struct rrr_discern_stack_element);
};

struct rrr_discern_stack {
	RRR_LL_NODE(struct rrr_discern_stack);
	struct rrr_discern_stack_list list;
	char *name;
};

static void __rrr_discern_stack_element_destroy (
		struct rrr_discern_stack_element *element
) {
	RRR_FREE_IF_NOT_NULL(element->data);
	rrr_free(element);
}

static void __rrr_discern_stack_list_clear (struct rrr_discern_stack_list *discern_stack) {
	RRR_LL_DESTROY(discern_stack, struct rrr_discern_stack_element, __rrr_discern_stack_element_destroy(node));
}

static void __rrr_discern_stack_destroy (
		struct rrr_discern_stack *discern_stack
) {
	__rrr_discern_stack_list_clear(&discern_stack->list);
	rrr_free(discern_stack->name);
	rrr_free(discern_stack);
}

static void __rrr_discern_stack_list_pop (
		struct rrr_discern_stack_list *discern_stack
) {
	assert(RRR_LL_COUNT(discern_stack) > 0);
	struct rrr_discern_stack_element *e = RRR_LL_POP(discern_stack);
	__rrr_discern_stack_element_destroy(e);
}

static int __rrr_discern_stack_list_peek (
		struct rrr_discern_stack_list *discern_stack
) {
	assert(RRR_LL_COUNT(discern_stack) > 0);
	assert(RRR_LL_LAST(discern_stack)->type == RRR_DISCERN_STACK_E_BOOL);
	return *((int *) RRR_LL_LAST(discern_stack)->data) != 0;
}

static int __rrr_discern_stack_list_push (
		struct rrr_discern_stack_list *discern_stack,
		enum rrr_discern_stack_element_type type,
		enum rrr_discern_stack_operator_type op,
		const void *data,
		rrr_length data_size
) {
	int ret = 0;

	struct rrr_discern_stack_element *element = NULL;

	if ((element = rrr_allocate_zero(sizeof(*element))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	element->type = type;
	element->op = op;
	if (data != NULL) {
		assert(data_size > 0);
		if ((element->data = rrr_allocate(data_size)) == NULL) {
			RRR_MSG_0("Could not allocate memory for data in %s\n", __func__);
			ret = 1;
			goto out_free;
		}
		memcpy(element->data, data, data_size);
		element->data_size = data_size;
	}
	else {
		assert(data_size == 0);
	}

	RRR_LL_APPEND(discern_stack, element);

	goto out;
	out_free:
		rrr_free(element);
	out:
		return ret;
}

static int __rrr_discern_stack_list_push_bool (
		struct rrr_discern_stack_list *discern_stack,
		int result
) {
	return __rrr_discern_stack_list_push (
			discern_stack,
			RRR_DISCERN_STACK_E_BOOL,
			RRR_DISCERN_STACK_OP_PUSH,
			&result,
			sizeof(result)
	);
}

static int __rrr_discern_stack_list_add_from (
		struct rrr_discern_stack_list *target,
		const struct rrr_discern_stack_list *source
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_discern_stack_element);
		if ((ret = __rrr_discern_stack_list_push (
				target,
				node->type,
				node->op,
				node->data,
				node->data_size
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_discern_stack_new (
		struct rrr_discern_stack **result,
		const char *name
) {
	int ret = 0;

	struct rrr_discern_stack *discern_stack = NULL;

	*result = NULL;

	if ((discern_stack = rrr_allocate_zero(sizeof(*discern_stack))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((discern_stack->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate name in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	*result = discern_stack;
	discern_stack = NULL;

	goto out;
	out_free:
		rrr_free(discern_stack);
	out:
		return ret;
}

void rrr_discern_stack_collection_clear (
		struct rrr_discern_stack_collection *list
) {
	RRR_LL_DESTROY(list, struct rrr_discern_stack, __rrr_discern_stack_destroy(node));
}

const struct rrr_discern_stack *rrr_discern_stack_collection_get (
		const struct rrr_discern_stack_collection *list,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(list, const struct rrr_discern_stack);
		if (strcmp(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

int rrr_discern_stack_collection_add_cloned (
		struct rrr_discern_stack_collection *list,
		const struct rrr_discern_stack *discern_stack
) {
	int ret = 0;

	struct rrr_discern_stack *new_discern_stack;

	if ((ret = __rrr_discern_stack_new (&new_discern_stack, discern_stack->name)) != 0) {
		goto out;
	}

	if ((ret = __rrr_discern_stack_list_add_from (&new_discern_stack->list, &discern_stack->list)) != 0) {
		goto out_destroy;
	}

	RRR_LL_APPEND(list, new_discern_stack);

	goto out;
	out_destroy:
		__rrr_discern_stack_destroy(new_discern_stack);
	out:
		return ret;
}

void rrr_discern_stack_collection_iterate_names (
		const struct rrr_discern_stack_collection *list,
		void (*callback)(const char *name, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(list, const struct rrr_discern_stack);
		callback(node->name, callback_arg);
	RRR_LL_ITERATE_END();
}

static int __rrr_discern_stack_execute_resolve_and_push (
		struct rrr_discern_stack_list *stack,
		const struct rrr_discern_stack_element *node,
		int (*resolve_cb)(int *result, const char *data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int result = 0;

	if ((ret = resolve_cb (&result, node->data, callback_arg)) != 0) {
		goto out;
	}

	if ((ret = __rrr_discern_stack_list_push_bool (
			stack,
			result
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_discern_stack_execute_op_and (int a, int b) {
	return a && b;
}

static int __rrr_discern_stack_execute_op_or (int a, int b) {
	return a || b;
}

static int __rrr_discern_stack_execute_op_not (int a) {
	return !a;
}

static int __rrr_discern_stack_execute_op_bail (int a) {
	return a;
}

static int __rrr_discern_stack_execute_op_bool (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		int (*eval_one)(int a),
		int (*eval_two)(int a, int b)
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const struct rrr_discern_stack_element *a = RRR_LL_LAST(stack);
	const struct rrr_discern_stack_element *b = eval_two != NULL ? RRR_LL_PREV(a) : NULL;

	if (a->type != RRR_DISCERN_STACK_E_BOOL || (eval_two != NULL && b->type != RRR_DISCERN_STACK_E_BOOL)) {
		RRR_MSG_0("Operand(s) for operator were not of boolean type as expected\n");
		*fault = RRR_DISCERN_STACK_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	const int result = eval_one != NULL
		? eval_one(*((int *)(a->data)))
		: eval_two(*((int *)(a->data)), *((int*)(b->data)))
	;

	__rrr_discern_stack_list_pop(stack);
	if (eval_two != NULL) {
		__rrr_discern_stack_list_pop(stack);
	}

	if ((ret = __rrr_discern_stack_list_push_bool (
			stack,
			result
	)) != 0) {
		*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
		goto out;
	}

	out:
	return ret;
}
				
static int __rrr_discern_stack_execute_op_apply (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		int (*apply_cb)(int result, const char *destination, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const struct rrr_discern_stack_element *a = RRR_LL_LAST(stack);
	const struct rrr_discern_stack_element *b = RRR_LL_PREV(a);

	if (b->type != RRR_DISCERN_STACK_E_BOOL) {
		RRR_MSG_0("First operand for APPLY operator was not of boolean type as expected\n");
		*fault = RRR_DISCERN_STACK_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	if (a->type != RRR_DISCERN_STACK_E_DESTINATION) {
		RRR_MSG_0("Second operand for APPLY operator was not of destination type as expected\n");
		*fault = RRR_DISCERN_STACK_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	assert(b->type == RRR_DISCERN_STACK_E_BOOL);

	if ((ret = apply_cb(*((int*)(b->data)), a->data, callback_arg)) != 0) {
		*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
		goto out;
	}

	// Pop off destination name and leave boolean value
	__rrr_discern_stack_list_pop(stack);

	out:
	return ret;
}

static int __rrr_discern_stack_execute_step (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		const struct rrr_discern_stack_element *node,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		void *resolve_callback_arg,
		int (*apply_cb)(int result, const char *desination, void *arg),
		void *apply_callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const int args = OP_ARG_COUNT(node->op);
	if (args > RRR_LL_COUNT(stack)) {
		RRR_MSG_0("Not enough elements on stack for operator %s\n", OP_NAME(node->op));
		*fault = RRR_DISCERN_STACK_FAULT_STACK_COUNT;
		ret = 1;
		goto out;
	}

	switch (node->op) {
		case RRR_DISCERN_STACK_OP_PUSH:
			switch (node->type) {
				case RRR_DISCERN_STACK_E_TOPIC_FILTER:
					if ((ret = __rrr_discern_stack_execute_resolve_and_push (stack, node, resolve_topic_filter_cb, resolve_callback_arg)) != 0) {
						*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
						goto out;
					}
					break;
				case RRR_DISCERN_STACK_E_ARRAY_TAG:
					if ((ret = __rrr_discern_stack_execute_resolve_and_push (stack, node, resolve_array_tag_cb, resolve_callback_arg)) != 0) {
						*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
						goto out;
					}
					break;
				case RRR_DISCERN_STACK_E_DESTINATION:
				case RRR_DISCERN_STACK_E_BOOL:
					if ((ret = __rrr_discern_stack_list_push (
							stack,
							node->type,
							node->op,
							node->data,
							node->data_size
					)) != 0) {
						*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
						goto out;
					}
					break;
				default:
					assert(0);
			};
			break;
		case RRR_DISCERN_STACK_OP_AND:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					NULL,
					__rrr_discern_stack_execute_op_and
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_OR:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					NULL,
					__rrr_discern_stack_execute_op_or
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_APPLY:
			if ((ret = __rrr_discern_stack_execute_op_apply (
					fault,
					stack,
					apply_cb,
					apply_callback_arg
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_NOT:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					__rrr_discern_stack_execute_op_not,
					NULL
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_POP:
			__rrr_discern_stack_list_pop(stack);
			break;
		case RRR_DISCERN_STACK_OP_BAIL:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					__rrr_discern_stack_execute_op_bail,
					NULL
			)) != 0) {
				goto out;
			}
			int v = __rrr_discern_stack_list_peek (stack);
			__rrr_discern_stack_list_pop(stack);
			if (v) {
				ret = RRR_DISCERN_STACK_BAIL;
				goto out;
			}
			break;
	};

	out:
	return ret;
}

static int __rrr_discern_stack_execute (
		enum rrr_discern_stack_fault *fault,
		const struct rrr_discern_stack *discern_stack,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		void *resolve_callback_arg,
		int (*apply_cb)(int result, const char *destination, void *arg),
		void *apply_callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	struct rrr_discern_stack_list stack = {0};

	RRR_LL_ITERATE_BEGIN(&discern_stack->list, const struct rrr_discern_stack_element);
		if ((ret = __rrr_discern_stack_execute_step (
				fault,
				&stack,
				node,
				resolve_topic_filter_cb,
				resolve_array_tag_cb,
				resolve_callback_arg,
				apply_cb,
				apply_callback_arg
		)) != 0) {
			if (ret == RRR_DISCERN_STACK_BAIL) {
				ret = 0;
			}
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	__rrr_discern_stack_list_clear(&stack);
	return ret;
}

int rrr_discern_stack_collection_execute (
		enum rrr_discern_stack_fault *fault,
		const struct rrr_discern_stack_collection *collection,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		void *resolve_callback_arg,
		int (*apply_cb)(int result, const char *destination, void *arg),
		void *apply_callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_discern_stack);
		if ((ret = __rrr_discern_stack_execute (
				fault,
				node,
				resolve_topic_filter_cb,
				resolve_array_tag_cb,
				resolve_callback_arg,
				apply_cb,
				apply_callback_arg
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_discern_stack_parse_execute_resolve (
		int *result,
		const char *str,
		void *arg
) {
	(void)(str);
	(void)(arg);

	*result = 1;

	return 0;
}

static int __rrr_discern_stack_parse_execute_apply (
		int result,
		const char *str,
		void *arg
) {
	(void)(result);
	(void)(str);
	(void)(arg);
	return 0;
}

static int __rrr_discern_stack_parse (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack *discern_stack,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	struct rrr_discern_stack_list stack = {0};
	char *str_tmp = NULL;
	int bool_tmp;
	const void *data = NULL;
	size_t data_size = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	rrr_parse_ignore_control_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file while parsing discern_stack definition\n");
		ret = 1;
		*fault = RRR_DISCERN_STACK_FAULT_END_MISSING;
		goto out;
	}

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		enum rrr_discern_stack_element_type type = RRR_DISCERN_STACK_E_NONE;
		enum rrr_discern_stack_operator_type op = RRR_DISCERN_STACK_OP_PUSH;

		rrr_parse_ignore_spaces_and_increment_line(pos);

		data = NULL;
		data_size = 0;

		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
	
		if (rrr_parse_match_word(pos, "#")) {
			rrr_parse_comment(pos);
			continue;
		}
		else if (rrr_parse_match_word(pos, "TRUE")) {
			type = RRR_DISCERN_STACK_E_BOOL;
			bool_tmp = 1;
		}
		else if (rrr_parse_match_word(pos, "FALSE")) {
			type = RRR_DISCERN_STACK_E_BOOL;
			bool_tmp = 0;
		}
		else if (rrr_parse_match_word(pos, "T")) {
			type = RRR_DISCERN_STACK_E_TOPIC_FILTER;
		}
		else if (rrr_parse_match_word(pos, "H")) {
			type = RRR_DISCERN_STACK_E_ARRAY_TAG;
		}
		else if (rrr_parse_match_word(pos, "D")) {
			type = RRR_DISCERN_STACK_E_DESTINATION;
		}
		else if (rrr_parse_match_word(pos, "AND")) {
			op = RRR_DISCERN_STACK_OP_AND;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "OR")) {
			op = RRR_DISCERN_STACK_OP_OR;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "NOT")) {
			op = RRR_DISCERN_STACK_OP_NOT;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "APPLY")) {
			op = RRR_DISCERN_STACK_OP_APPLY;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "POP")) {
			op = RRR_DISCERN_STACK_OP_POP;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "BAIL")) {
			op = RRR_DISCERN_STACK_OP_BAIL;
			goto push;
		}
		else {
			RRR_MSG_0("Syntax error in discern stack definition, expected valid keyword or operator\n");
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_SYNTAX_ERROR;
			goto out;
		}

		if (rrr_parse_match_letters_peek(pos, RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_CONTROL) == 0) {
			RRR_MSG_0("Syntax error, possibly space missing after operator.\n");
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_SYNTAX_ERROR;
			goto out;
		}

		if (type == RRR_DISCERN_STACK_E_BOOL) {
			data = &bool_tmp;
			data_size = sizeof(bool_tmp);
			goto push;
		}

		// Parse value after keyword
		rrr_length start = 0;
		rrr_slength end = 0;

		rrr_parse_ignore_spaces_and_increment_line(pos);

		if (type == RRR_DISCERN_STACK_E_TOPIC_FILTER) {
			rrr_parse_non_control(pos, &start, &end);
		}
		else if (type == RRR_DISCERN_STACK_E_ARRAY_TAG) {
			rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_TAG);
		}
		else if (type == RRR_DISCERN_STACK_E_DESTINATION) {
			rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_NAME);
		}
		else {
			assert(0);
		}

		if (end < start) {
			RRR_MSG_0("Value missing after keyword in discern stack definition\n");
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_VALUE_MISSING;
			goto out;
		}

		if (RRR_PARSE_CHECK_EOF(pos)) {
			RRR_MSG_0("Syntax error, unexpected end of file after value.\n");
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_END_MISSING;
			goto out;
		}

		if (type == RRR_DISCERN_STACK_E_ARRAY_TAG || type == RRR_DISCERN_STACK_E_DESTINATION) {
			if (rrr_parse_match_letters_peek(pos, RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_CONTROL) == 0) {
				RRR_MSG_0("Possibly invalid characters in name or tag.\n");
				ret = 1;
				*fault = RRR_DISCERN_STACK_FAULT_INVALID_VALUE;
				goto out;
			}
		}

		rrr_length str_length;
		if ((ret = rrr_length_from_slength_sub_err(&str_length, end, start)) != 0) {
			RRR_MSG_0("Value length out of range in discern stack definition\n");
			*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(str_tmp);
		if ((ret = rrr_parse_str_extract(&str_tmp, pos, start, str_length + 1)) != 0) {
			*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
			goto out;
		}
		data = str_tmp;
		data_size = rrr_size_t_inc_bug_const(strlen(str_tmp));

		if (type == RRR_DISCERN_STACK_E_TOPIC_FILTER && rrr_mqtt_topic_filter_validate_name(str_tmp) != 0) {
			RRR_MSG_0("Invalid topic filter '%s' in discern stack definition\n", str_tmp);
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_INVALID_VALUE;
			goto out;
		}

                push:

		if ((ret = __rrr_discern_stack_list_push (
				&discern_stack->list,
				type,
				op,
				data,
				rrr_length_from_size_t_bug_const(data_size)
		)) != 0) {
			goto out;
		}

		if ((ret = __rrr_discern_stack_execute_step (
				fault,
				&stack,
				RRR_LL_LAST(&discern_stack->list),
				__rrr_discern_stack_parse_execute_resolve,
				__rrr_discern_stack_parse_execute_resolve,
				NULL,
				__rrr_discern_stack_parse_execute_apply,
				NULL
		)) != 0) {
			if (ret == RRR_DISCERN_STACK_BAIL) {
				ret = 0;
			}
			else {
				goto out;
			}
		}

		// Parsing is done when stack would have been empty
		if (RRR_LL_COUNT(&stack) == 0) {
			break;
		}
	}

	if (RRR_LL_COUNT(&stack) != 0) {
		// Happens if POP is missing and we reach EOF
		RRR_MSG_0("Discern definition would not have empty stack after execution, maybe there are not enough POP operators?\n");
		ret = 1;
		*fault = RRR_DISCERN_STACK_FAULT_STACK_COUNT;
		goto out;
	}

	goto out;
	out:
		if (ret != 0) {
			RRR_FREE_IF_NOT_NULL(str_tmp);
			rrr_parse_make_location_message(&str_tmp, pos);
			printf("%s", str_tmp);
		}
		__rrr_discern_stack_list_clear(&stack);
		RRR_FREE_IF_NOT_NULL(str_tmp);
		return ret;
}

int rrr_discern_stack_collection_iterate_destination_names (
		const struct rrr_discern_stack_collection *collection,
		int (*callback)(const char *discern_stack_name, const char *destination_name, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_discern_stack);
		const struct rrr_discern_stack *discern_stack = node;
		RRR_LL_ITERATE_BEGIN(&discern_stack->list, const struct rrr_discern_stack_element);
			if (node->type != RRR_DISCERN_STACK_E_DESTINATION) {
				RRR_LL_ITERATE_NEXT();
			}
			if ((ret = callback(discern_stack->name, node->data, callback_arg)) != 0) {
				goto out;
			}
		RRR_LL_ITERATE_END();
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_discern_stack_interpret (
		struct rrr_discern_stack_collection *target,
		enum rrr_discern_stack_fault *fault,
		struct rrr_parse_pos *pos,
		const char *name
) {
	int ret = 0;

	struct rrr_discern_stack *discern_stack = NULL;

	if ((ret = __rrr_discern_stack_new(&discern_stack, name)) != 0) {
		goto out;
	}

	if ((ret = __rrr_discern_stack_parse(fault, discern_stack, pos)) != 0) {
		goto out_destroy;
	}

	RRR_LL_APPEND(target, discern_stack);

	goto out;
	out_destroy:
		__rrr_discern_stack_destroy(discern_stack);
	out:
		return ret;
}
