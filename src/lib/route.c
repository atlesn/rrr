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

#include "route.h"

#include "parse.h"
#include "allocator.h"
#include "mqtt/mqtt_topic.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

enum rrr_route_element_type {
	RRR_ROUTE_E_NONE,
	RRR_ROUTE_E_TOPIC_FILTER,
	RRR_ROUTE_E_ARRAY_TAG,
	RRR_ROUTE_E_BOOL,
	RRR_ROUTE_E_INSTANCE
};

// DO NOT change order of elements without understanding access macros
enum rrr_route_operator_type {
	RRR_ROUTE_OP_PUSH,
	RRR_ROUTE_OP_AND,
	RRR_ROUTE_OP_OR,
	RRR_ROUTE_OP_APPLY,
	RRR_ROUTE_OP_NOT,
	RRR_ROUTE_OP_POP
};

#define OP_ARG_COUNT(op) (op < RRR_ROUTE_OP_AND ? 0 : op > RRR_ROUTE_OP_APPLY ? 1 : 2)

#define OP_NAME(op)                                 \
  (op == RRR_ROUTE_OP_PUSH ? "PUSH" :               \
   op == RRR_ROUTE_OP_AND ? "AND" :                 \
   op == RRR_ROUTE_OP_OR ? "OR" :                   \
   op == RRR_ROUTE_OP_APPLY ? "APPLY" :             \
   op == RRR_ROUTE_OP_NOT ? "NOT" :                 \
   op == RRR_ROUTE_OP_POP ? "POP" : "UNKNOWN")

struct rrr_route_element {
	RRR_LL_NODE(struct rrr_route_element);
	enum rrr_route_element_type type;
	enum rrr_route_operator_type op;
	void *data;
	rrr_length data_size;
};

struct rrr_route_list {
	RRR_LL_HEAD(struct rrr_route_element);
};

struct rrr_route {
	RRR_LL_NODE(struct rrr_route);
	struct rrr_route_list list;
	char *name;
};

static void __rrr_route_element_destroy (
		struct rrr_route_element *element
) {
	RRR_FREE_IF_NOT_NULL(element->data);
	rrr_free(element);
}

static void __rrr_route_list_clear (struct rrr_route_list *route) {
	RRR_LL_DESTROY(route, struct rrr_route_element, __rrr_route_element_destroy(node));
}

static void __rrr_route_destroy (
		struct rrr_route *route
) {
	__rrr_route_list_clear(&route->list);
	rrr_free(route->name);
	rrr_free(route);
}

static void __rrr_route_list_pop (
		struct rrr_route_list *route
) {
	assert(RRR_LL_COUNT(route) > 0);
	struct rrr_route_element *e = RRR_LL_POP(route);
	__rrr_route_element_destroy(e);
}

static int __rrr_route_list_push (
		struct rrr_route_list *route,
		enum rrr_route_element_type type,
		enum rrr_route_operator_type op,
		const void *data,
		rrr_length data_size
) {
	int ret = 0;

	struct rrr_route_element *element = NULL;

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

	RRR_LL_APPEND(route, element);

	goto out;
	out_free:
		rrr_free(element);
	out:
		return ret;
}

static int __rrr_route_list_push_bool (
		struct rrr_route_list *route,
		int result
) {
	return __rrr_route_list_push (
			route,
			RRR_ROUTE_E_BOOL,
			RRR_ROUTE_OP_PUSH,
			&result,
			sizeof(result)
	);
}

static int __rrr_route_list_add_from (
		struct rrr_route_list *target,
		const struct rrr_route_list *source
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_route_element);
		if ((ret = __rrr_route_list_push (
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

static int __rrr_route_new (
		struct rrr_route **result,
		const char *name
) {
	int ret = 0;

	struct rrr_route *route = NULL;

	*result = NULL;

	if ((route = rrr_allocate_zero(sizeof(*route))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((route->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate name in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	*result = route;
	route = NULL;

	goto out;
	out_free:
		rrr_free(route);
	out:
		return ret;
}

void rrr_route_collection_clear (
		struct rrr_route_collection *list
) {
	RRR_LL_DESTROY(list, struct rrr_route, __rrr_route_destroy(node));
}

const struct rrr_route *rrr_route_collection_get (
		const struct rrr_route_collection *list,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(list, const struct rrr_route);
		if (strcmp(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();

	return NULL;
}

int rrr_route_collection_add_cloned (
		struct rrr_route_collection *list,
		const struct rrr_route *route
) {
	int ret = 0;

	struct rrr_route *new_route;

	if ((ret = __rrr_route_new (&new_route, route->name)) != 0) {
		goto out;
	}

	if ((ret = __rrr_route_list_add_from (&new_route->list, &route->list)) != 0) {
		goto out_destroy;
	}

	RRR_LL_APPEND(list, new_route);

	goto out;
	out_destroy:
		__rrr_route_destroy(new_route);
	out:
		return ret;
}

void rrr_route_collection_iterate_names (
		const struct rrr_route_collection *list,
		void (*callback)(const char *name, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(list, const struct rrr_route);
		callback(node->name, callback_arg);
	RRR_LL_ITERATE_END();
}

static int __rrr_route_execute_resolve_and_push (
		struct rrr_route_list *stack,
		const struct rrr_route_element *node,
		int (*resolve_cb)(int *result, const char *data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int result = 0;

	if ((ret = resolve_cb (&result, node->data, callback_arg)) != 0) {
		goto out;
	}

	if ((ret = __rrr_route_list_push_bool (
			stack,
			result
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_route_execute_op_and (int a, int b) {
	return a && b;
}

static int __rrr_route_execute_op_or (int a, int b) {
	return a || b;
}

static int __rrr_route_execute_op_not (int a) {
	return !a;
}

static int __rrr_route_execute_op_bool (
		enum rrr_route_fault *fault,
		struct rrr_route_list *stack,
		int (*eval_one)(int a),
		int (*eval_two)(int a, int b)
) {
	int ret = 0;

	*fault = RRR_ROUTE_FAULT_OK;

	const struct rrr_route_element *a = RRR_LL_LAST(stack);
	const struct rrr_route_element *b = eval_two != NULL ? RRR_LL_PREV(a) : NULL;

	if (a->type != RRR_ROUTE_E_BOOL || (eval_two != NULL && b->type != RRR_ROUTE_E_BOOL)) {
		RRR_MSG_0("Operand(s) for operator were not of boolean type as expected\n");
		*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	const int result = eval_one != NULL
		? eval_one(*((int *)(a->data)))
		: eval_two(*((int *)(a->data)), *((int*)(b->data)))
	;

	__rrr_route_list_pop(stack);
	if (eval_two != NULL) {
		__rrr_route_list_pop(stack);
	}

	if ((ret = __rrr_route_list_push_bool (
			stack,
			result
	)) != 0) {
		*fault = RRR_ROUTE_FAULT_CRITICAL;
		goto out;
	}

	out:
	return ret;
}
				
static int __rrr_route_execute_op_apply (
		enum rrr_route_fault *fault,
		struct rrr_route_list *stack,
		int (*apply_cb)(int result, const char *instance, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_ROUTE_FAULT_OK;

	const struct rrr_route_element *a = RRR_LL_LAST(stack);
	const struct rrr_route_element *b = RRR_LL_PREV(a);

	if (b->type != RRR_ROUTE_E_BOOL) {
		RRR_MSG_0("First operand for APPLY operator was not of boolean type as expected\n");
		*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	if (a->type != RRR_ROUTE_E_INSTANCE) {
		RRR_MSG_0("Second operand for APPLY operator was not of instance type as expected\n");
		*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	}

	assert(b->type == RRR_ROUTE_E_BOOL);

	if ((ret = apply_cb(*((int*)(b->data)), a->data, callback_arg)) != 0) {
		*fault = RRR_ROUTE_FAULT_CRITICAL;
		goto out;
	}

	// Pop off instance name and leave boolean value
	__rrr_route_list_pop(stack);

	out:
	return ret;
}

static int __rrr_route_execute_step (
		enum rrr_route_fault *fault,
		struct rrr_route_list *stack,
		const struct rrr_route_element *node,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		int (*apply_cb)(int result, const char *instance, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_ROUTE_FAULT_OK;

	const int args = OP_ARG_COUNT(node->op);
	if (args > RRR_LL_COUNT(stack)) {
		RRR_MSG_0("Not enough elements on stack for operator %s\n", OP_NAME(node->op));
		*fault = RRR_ROUTE_FAULT_STACK_COUNT;
		ret = 1;
		goto out;
	}

	switch (node->op) {
		case RRR_ROUTE_OP_PUSH:
			switch (node->type) {
				case RRR_ROUTE_E_TOPIC_FILTER:
					if ((ret = __rrr_route_execute_resolve_and_push (stack, node, resolve_topic_filter_cb, callback_arg)) != 0) {
						*fault = RRR_ROUTE_FAULT_CRITICAL;
						goto out;
					}
					break;
				case RRR_ROUTE_E_ARRAY_TAG:
					if ((ret = __rrr_route_execute_resolve_and_push (stack, node, resolve_array_tag_cb, callback_arg)) != 0) {
						*fault = RRR_ROUTE_FAULT_CRITICAL;
						goto out;
					}
					break;
				case RRR_ROUTE_E_INSTANCE:
					if ((ret = __rrr_route_list_push (
							stack,
							node->type,
							node->op,
							node->data,
							node->data_size
					)) != 0) {
						*fault = RRR_ROUTE_FAULT_CRITICAL;
						goto out;
					}
					break;
				default:
					assert(0);
			};
			break;
		case RRR_ROUTE_OP_AND:
			if ((ret = __rrr_route_execute_op_bool (
					fault,
					stack,
					NULL,
					__rrr_route_execute_op_and
			)) != 0) {
				goto out;
			}
			break;
		case RRR_ROUTE_OP_OR:
			if ((ret = __rrr_route_execute_op_bool (
					fault,
					stack,
					NULL,
					__rrr_route_execute_op_or
			)) != 0) {
				goto out;
			}
			break;
		case RRR_ROUTE_OP_APPLY:
			if ((ret = __rrr_route_execute_op_apply (
					fault,
					stack,
					apply_cb,
					callback_arg
			)) != 0) {
				goto out;
			}
			break;
		case RRR_ROUTE_OP_NOT:
			if ((ret = __rrr_route_execute_op_bool (
					fault,
					stack,
					__rrr_route_execute_op_not,
					NULL
			)) != 0) {
				goto out;
			}
			break;
		case RRR_ROUTE_OP_POP:
			__rrr_route_list_pop(stack);
			break;
	};

	out:
	return ret;
}

static int __rrr_route_execute (
		enum rrr_route_fault *fault,
		const struct rrr_route *route,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		int (*apply_cb)(int result, const char *instance, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_ROUTE_FAULT_OK;

	struct rrr_route_list stack = {0};

	RRR_LL_ITERATE_BEGIN(&route->list, const struct rrr_route_element);
		if ((ret = __rrr_route_execute_step (
				fault,
				&stack,
				node,
				resolve_topic_filter_cb,
				resolve_array_tag_cb,
				apply_cb,
				callback_arg
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	__rrr_route_list_clear(&stack);
	return ret;
}

int rrr_route_collection_execute (
		enum rrr_route_fault *fault,
		const struct rrr_route_collection *collection,
		int (*resolve_topic_filter_cb)(int *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(int *result, const char *tag, void *arg),
		int (*apply_cb)(int result, const char *instance, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_ROUTE_FAULT_OK;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_route);
		if ((ret = __rrr_route_execute (
				fault,
				node,
				resolve_topic_filter_cb,
				resolve_array_tag_cb,
				apply_cb,
				callback_arg
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_route_parse_execute_resolve (
		int *result,
		const char *str,
		void *arg
) {
	(void)(str);
	(void)(arg);

	*result = 1;

	return 0;
}

static int __rrr_route_parse_execute_apply (
		int result,
		const char *str,
		void *arg
) {
	(void)(result);
	(void)(str);
	(void)(arg);
	return 0;
}

static int __rrr_route_parse (
		enum rrr_route_fault *fault,
		struct rrr_route *route,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	struct rrr_route_list stack = {0};
	char *str_tmp = NULL;

	*fault = RRR_ROUTE_FAULT_OK;

	rrr_parse_ignore_control_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file while parsing route definition\n");
		ret = 1;
		*fault = RRR_ROUTE_FAULT_END_MISSING;
		goto out;
	}

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		enum rrr_route_element_type type = RRR_ROUTE_E_NONE;
		enum rrr_route_operator_type op = RRR_ROUTE_OP_PUSH;

		rrr_parse_ignore_spaces_and_increment_line(pos);

		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
	
		if (rrr_parse_match_word(pos, "#")) {
			rrr_parse_comment(pos);
			continue;
		}
		else if (rrr_parse_match_word(pos, "T")) {
			type = RRR_ROUTE_E_TOPIC_FILTER;
		}
		else if (rrr_parse_match_word(pos, "H")) {
			type = RRR_ROUTE_E_ARRAY_TAG;
		}
		else if (rrr_parse_match_word(pos, "I")) {
			type = RRR_ROUTE_E_INSTANCE;
		}
		else if (rrr_parse_match_word(pos, "AND")) {
			op = RRR_ROUTE_OP_AND;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "OR")) {
			op = RRR_ROUTE_OP_OR;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "NOT")) {
			op = RRR_ROUTE_OP_NOT;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "APPLY")) {
			op = RRR_ROUTE_OP_APPLY;
			goto push;
		}
		else if (rrr_parse_match_word(pos, "POP")) {
			op = RRR_ROUTE_OP_POP;
			goto push;
		}
		else {
			RRR_MSG_0("Syntax error in route definition, expected valid keyword or operator\n");
			ret = 1;
			*fault = RRR_ROUTE_FAULT_SYNTAX_ERROR;
			goto out;
		}

		if (rrr_parse_match_letters_peek(pos, RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_CONTROL) == 0) {
			RRR_MSG_0("Syntax error, possibly space missing after operator.\n");
			ret = 1;
			*fault = RRR_ROUTE_FAULT_SYNTAX_ERROR;
			goto out;
		}

		// Parse value after keyword
		rrr_length start = 0;
		rrr_slength end = 0;

		rrr_parse_ignore_spaces_and_increment_line(pos);

		if (type == RRR_ROUTE_E_TOPIC_FILTER) {
			rrr_parse_non_control(pos, &start, &end);
		}
		else if (type == RRR_ROUTE_E_ARRAY_TAG) {
			rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_TAG);
		}
		else if (type == RRR_ROUTE_E_INSTANCE) {
			rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_NAME);
		}
		else {
			assert(0);
		}

		if (end < start) {
			RRR_MSG_0("Value missing after keyword in route definition\n");
			ret = 1;
			*fault = RRR_ROUTE_FAULT_VALUE_MISSING;
			goto out;
		}

		if (RRR_PARSE_CHECK_EOF(pos)) {
			RRR_MSG_0("Syntax error, unexpected end of file after value.\n");
			ret = 1;
			*fault = RRR_ROUTE_FAULT_END_MISSING;
			goto out;
		}

		if (type == RRR_ROUTE_E_ARRAY_TAG || type == RRR_ROUTE_E_INSTANCE) {
			if (rrr_parse_match_letters_peek(pos, RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_CONTROL) == 0) {
				RRR_MSG_0("Possibly invalid characters in name or tag.\n");
				ret = 1;
				*fault = RRR_ROUTE_FAULT_INVALID_VALUE;
				goto out;
			}
		}

		rrr_length str_length;
		if ((ret = rrr_length_from_slength_sub_err(&str_length, end, start)) != 0) {
			RRR_MSG_0("Value length out of range in route definition\n");
			*fault = RRR_ROUTE_FAULT_CRITICAL;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(str_tmp);
		if ((ret = rrr_parse_str_extract(&str_tmp, pos, start, str_length + 1)) != 0) {
			*fault = RRR_ROUTE_FAULT_CRITICAL;
			goto out;
		}

		if (type == RRR_ROUTE_E_TOPIC_FILTER && rrr_mqtt_topic_filter_validate_name(str_tmp) != 0) {
			RRR_MSG_0("Invalid topic filter '%s' in route definition\n", str_tmp);
			ret = 1;
			*fault = RRR_ROUTE_FAULT_INVALID_VALUE;
			goto out;
		}

                push:

		if ((ret = __rrr_route_list_push (
				&route->list,
				type, op,
				str_tmp,
				str_tmp != NULL
					? rrr_length_inc_bug_const(rrr_length_from_size_t_bug_const(strlen(str_tmp)))
					: 0
		)) != 0) {
			goto out;
		}

		if ((ret = __rrr_route_execute_step (
				fault,
				&stack,
				RRR_LL_LAST(&route->list),
				__rrr_route_parse_execute_resolve,
				__rrr_route_parse_execute_resolve,
				__rrr_route_parse_execute_apply,
				NULL
		)) != 0) {
			goto out;
		}

		// Parsing is done when stack would have been empty
		if (RRR_LL_COUNT(&stack) == 0) {
			break;
		}
	}

	if (RRR_LL_COUNT(&stack) != 0) {
		// Happens if POP is missing and we reach EOF
		RRR_MSG_0("Route definition would not have empty stack after execution, maybe there are not enough POP operators?\n");
		ret = 1;
		*fault = RRR_ROUTE_FAULT_STACK_COUNT;
		goto out;
	}

	goto out;
	out:
		__rrr_route_list_clear(&stack);
		RRR_FREE_IF_NOT_NULL(str_tmp);
		return ret;
}

int rrr_route_collection_iterate_instance_names (
		const struct rrr_route_collection *collection,
		int (*callback)(const char *route_name, const char *instance_name, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_route);
		const struct rrr_route *route = node;
		RRR_LL_ITERATE_BEGIN(&route->list, const struct rrr_route_element);
			if (node->type != RRR_ROUTE_E_INSTANCE) {
				RRR_LL_ITERATE_NEXT();
			}
			if ((ret = callback(route->name, node->data, callback_arg)) != 0) {
				goto out;
			}
		RRR_LL_ITERATE_END();
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_route_interpret (
		struct rrr_route_collection *target,
		enum rrr_route_fault *fault,
		struct rrr_parse_pos *pos,
		const char *name
) {
	int ret = 0;

	struct rrr_route *route = NULL;

	if ((ret = __rrr_route_new(&route, name)) != 0) {
		goto out;
	}

	if ((ret = __rrr_route_parse(fault, route, pos)) != 0) {
		goto out_destroy;
	}

	RRR_LL_APPEND(target, route);

	goto out;
	out_destroy:
		__rrr_route_destroy(route);
	out:
		return ret;
}
