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

// DO NOT change order of elements without understanding access macros
enum rrr_route_element_type {
	RRR_ROUTE_E_NONE,
	RRR_ROUTE_E_TOPIC_FILTER,
	RRR_ROUTE_E_ARRAY_TAG,
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

#define OP_ARG_COUNT(op) (op < RRR_ROUTE_OP_AND || op > RRR_ROUTE_OP_APPLY ? 1 : 2)
#define OP_RES_COUNT(op) (op<=RRR_ROUTE_OP_APPLY ? 1 : 0)
#define OP_DIFF(op)      (OP_RES_COUNT(op)-OP_ARG_COUNT(op))

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
};

#define STACK_E_IS_BOOL(e) \
  (e->type == RRR_ROUTE_E_TOPIC_FILTER || e->type == RRR_ROUTE_E_ARRAY_TAG || (e->op >= RRR_ROUTE_OP_AND && e->op <= RRR_ROUTE_OP_NOT))

#define STACK_E_IS_INSTANCE(e) \
  (e->type == RRR_ROUTE_E_INSTANCE)

struct rrr_route_list {
	RRR_LL_HEAD(struct rrr_route_element);
};

struct rrr_route {
	struct rrr_route_list list;
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

static int __rrr_route_list_push (
		struct rrr_route_list *route,
		enum rrr_route_element_type type,
		enum rrr_route_operator_type op,
		void **data
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
	element->data = *data;
	*data = NULL;

	RRR_LL_APPEND(route, element);

	out:
	return ret;
}

static int __rrr_route_new (
		struct rrr_route **result
) {
	int ret = 0;

	struct rrr_route *route = NULL;

	*result = NULL;

	if ((route = rrr_allocate_zero(sizeof(*route))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*result = route;
	route = NULL;

	out:
	return ret;
}

void rrr_route_destroy (
		struct rrr_route *route
) {
	__rrr_route_list_clear(&route->list);
	rrr_free(route);
}

static int __rrr_route_parse (
		enum rrr_route_fault *fault,
		struct rrr_route *route,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	char *str_tmp = NULL;

	*fault = RRR_ROUTE_FAULT_OK;

	rrr_parse_ignore_control_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file while parsing route definition\n");
		ret = 1;
		*fault = RRR_ROUTE_FAULT_END_MISSING;
		goto out;
	}

	rrr_slength stack_size = 0;

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

		assert(str_tmp == NULL);

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

		stack_size++;

                push:

		if (op != RRR_ROUTE_OP_PUSH) {
			if (stack_size < OP_ARG_COUNT(op)) {
				RRR_MSG_0("Not enough values would be present on stack for operator %s (%" PRIrrrl " would be present but at least %i %s requried)\n",
						OP_NAME(op), stack_size, OP_ARG_COUNT(op), OP_ARG_COUNT(op) == 1 ? "is" : "are");
				ret = 1;
				*fault = RRR_ROUTE_FAULT_VALUE_MISSING;
				goto out;
			}

			const struct rrr_route_element *top = RRR_LL_LAST(&route->list);
			const struct rrr_route_element *toptop = RRR_LL_PREV(top);

			switch (op) {
	                        case RRR_ROUTE_OP_AND:
                        	case RRR_ROUTE_OP_OR:
					if (!STACK_E_IS_BOOL(top) || !STACK_E_IS_BOOL(toptop)) {
						RRR_MSG_0("Top two elements on stack would not be boolean types which is required by OR and AND operators\n");
						ret = 1;
						*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
						goto out;
					}
	                                break;
	                        case RRR_ROUTE_OP_APPLY:
					if (!STACK_E_IS_INSTANCE(top)) {
						RRR_MSG_0("Top element on stack would not be an instance name which is required by APPLY operator\n");
						ret = 1;
						*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
						goto out;
					}
					if (!STACK_E_IS_BOOL(toptop)) {
						RRR_MSG_0("Second topmost element on stack would not be a boolean which is required by APPLY operator\n");
						ret = 1;
						*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
						goto out;
					}
					break;
        	                case RRR_ROUTE_OP_NOT:
                	        case RRR_ROUTE_OP_POP:
					if (!STACK_E_IS_BOOL(top)) {
						RRR_MSG_0("Top element was not a boolean which is required by POP and NOT operators\n");
						ret = 1;
						*fault = RRR_ROUTE_FAULT_INVALID_TYPE;
						goto out;
					}
					break;
	                        case RRR_ROUTE_OP_PUSH:
				default:
					assert(0);
                        };
                }

		stack_size += OP_DIFF(op);

		assert (stack_size >= 0);

		// Consumes the str_tmp upon success
		if ((ret = __rrr_route_list_push(&route->list, type, op, (void **) &str_tmp)) != 0) {
			goto out;
		}
	}

	if (stack_size != 0) {
		// Happens if POP is missing and we reach EOF
		RRR_MSG_0("Route definition would not have empty stack after execution, maybe there are not enough POP operators?\n");
		ret = 1;
		*fault = RRR_ROUTE_FAULT_STACK_COUNT;
		goto out;
	}

	goto out;
	out:
		RRR_FREE_IF_NOT_NULL(str_tmp);
		return ret;
}

int rrr_route_interpret (
		enum rrr_route_fault *fault,
		struct rrr_route **result,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	struct rrr_route *route = NULL;

	*result = NULL;

	if ((ret = __rrr_route_new(&route)) != 0) {
		goto out;
	}

	if ((ret = __rrr_route_parse(fault, route, pos)) != 0) {
		goto out_destroy;
	}

	*result = route;

	goto out;
	out_destroy:
		rrr_route_destroy(route);
	out:
		return ret;
}
