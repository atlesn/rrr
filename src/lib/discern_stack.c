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

#define RRR_DISCERN_STACK_DATA_MAX_SIZE 64

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

struct rrr_discern_stack_storage {
	void *data;
	rrr_length size;
	rrr_length capacity;
};

struct rrr_discern_stack_value {
	rrr_length data_size;
	union {
		rrr_length value;
		rrr_length data_pos;
	};
};

struct rrr_discern_stack_element {
	enum rrr_discern_stack_element_type type;
	enum rrr_discern_stack_operator_type op;
	struct rrr_discern_stack_value value;
};

struct rrr_discern_stack_list {
	struct rrr_discern_stack_element *elements;
	rrr_length size;
	rrr_length wpos;
};

struct rrr_discern_stack_value_list {
	rrr_length data_pos;
	rrr_length size;
	rrr_length wpos;
};

struct rrr_discern_stack {
	RRR_LL_NODE(struct rrr_discern_stack);
	struct rrr_discern_stack_list list;
	struct rrr_discern_stack_value_list exe_stack;
	struct rrr_discern_stack_list parse_stack;
	struct rrr_discern_stack_storage storage;
	char *name;
};

static int __rrr_discern_stack_storage_push (
		rrr_length *position,
		struct rrr_discern_stack_storage *target,
		const void *data,
		rrr_length data_size
) {
	int ret = 0;

	if (data != NULL && data >= target->data && data < target->data + target->capacity) {
		// Copy from and to same storage, just return
		// the position of the existing data.
		*position = rrr_length_from_ptr_sub_bug_const(data, target->data);
		goto out;
	}

	rrr_length new_capacity = rrr_length_add_bug_const(target->size, data_size);
	if (new_capacity > target->capacity) {
		void *new_data;
		if ((new_data = rrr_reallocate(target->data, target->capacity, new_capacity)) == NULL) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		target->capacity = new_capacity;
		target->data = new_data;
	}

	rrr_length new_position = target->size;
	if (data != NULL)
		memcpy(target->data + new_position, data, data_size);
	target->size += data_size;
	*position = new_position;

	out:
	return ret;
}

static void __rrr_discern_stack_storage_clear (
		struct rrr_discern_stack_storage *target
) {
	RRR_FREE_IF_NOT_NULL(target->data);
	memset(target, '\0', sizeof(*target));
}

static void __rrr_discern_stack_list_clear (struct rrr_discern_stack_list *list) {
	RRR_FREE_IF_NOT_NULL(list->elements);
	memset(list, '\0', sizeof(*list));
}

static void __rrr_discern_stack_value_list_clear (struct rrr_discern_stack_value_list *list) {
	memset(list, '\0', sizeof(*list));
}

static void __rrr_discern_stack_destroy (
		struct rrr_discern_stack *discern_stack
) {
	__rrr_discern_stack_list_clear(&discern_stack->list);
	__rrr_discern_stack_list_clear(&discern_stack->parse_stack);
	__rrr_discern_stack_value_list_clear(&discern_stack->exe_stack);
	__rrr_discern_stack_storage_clear(&discern_stack->storage);
	rrr_free(discern_stack->name);
	rrr_free(discern_stack);
}

static void __rrr_discern_stack_list_pop (
		struct rrr_discern_stack_list *discern_stack
) {
	assert(discern_stack->wpos > 0);
	discern_stack->wpos--;
}

static int __rrr_discern_stack_list_peek (
		struct rrr_discern_stack_list *discern_stack
) {
	assert(discern_stack->wpos > 0);
	const struct rrr_discern_stack_element *e = &discern_stack->elements[discern_stack->wpos - 1];
	assert(e->type == RRR_DISCERN_STACK_E_BOOL);
	return e->value.value != 0;
}

static int __rrr_discern_stack_expand (
		void **data,
		rrr_length *old_size,
		rrr_length increase_size,
		size_t element_size
) {
	int ret = 0;

	const rrr_length new_size = rrr_length_add_bug_const(*old_size, increase_size);
	void *data_new;
	if ((data_new = rrr_reallocate (
			*data,
			*old_size * element_size,
			new_size * element_size
	)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*data = data_new;
	*old_size = new_size;

	out:
	return ret;
}

static int __rrr_discern_stack_value_list_expand (
		struct rrr_discern_stack_value_list *list,
		struct rrr_discern_stack_storage *storage,
		rrr_length size
) {
	int ret = 0;

	struct rrr_discern_stack_value *elements;
	rrr_length new_size = list->size + size;

	if (list->size > 0) {
		elements = storage->data + list->data_pos;

		// The list must already be in the given storage as the last data segment.
		assert((void *) elements >= storage->data && (void *) elements < storage->data + storage->size);
		assert(storage->size >= sizeof(*elements) * list->size);

		storage->size -= sizeof(*elements) * list->size;

		assert(elements == storage->data + storage->size);
	}

	if ((ret = __rrr_discern_stack_storage_push (
			&list->data_pos,
			storage,
			NULL,
			new_size * sizeof(*elements)
	)) != 0) {
		goto out;
	}

	list->size = new_size;

	out:
	return ret;
}

static int __rrr_discern_stack_list_reserve (
		struct rrr_discern_stack_list *list,
		rrr_length size
) {
	return __rrr_discern_stack_expand((void **) &list->elements, &list->size, size, sizeof(*list->elements));
}

static int __rrr_discern_stack_list_push (
		struct rrr_discern_stack_list *discern_stack,
		struct rrr_discern_stack_storage *storage,
		enum rrr_discern_stack_element_type type,
		enum rrr_discern_stack_operator_type op,
		const void *data,
		rrr_length data_size,
		rrr_length value
) {
	int ret = 0;

	assert (discern_stack->wpos <= discern_stack->size);

	if (discern_stack->wpos == discern_stack->size) {
		if ((ret = __rrr_discern_stack_list_reserve (discern_stack, 8)) != 0) {
			goto out;
		}
	}

	struct rrr_discern_stack_element *element = &discern_stack->elements[discern_stack->wpos];

	element->type = type;
	element->op = op;
	if (data_size > 0) {
		assert(data != NULL);
		if ((ret = __rrr_discern_stack_storage_push (
				&element->value.data_pos,
				storage,
				data,
				data_size
		)) != 0) {
			goto out;
		}
		element->value.data_size = data_size;
	}
	else {
		assert(data_size == 0);
		element->value.data_size = 0;
		element->value.value = value;
	}

	discern_stack->wpos++;

	goto out;
	out:
		return ret;
}

static int __rrr_discern_stack_list_push_bool (
		struct rrr_discern_stack_list *discern_stack,
		struct rrr_discern_stack_storage *storage,
		rrr_length result
) {
	return __rrr_discern_stack_list_push (
			discern_stack,
			storage,
			RRR_DISCERN_STACK_E_BOOL,
			RRR_DISCERN_STACK_OP_PUSH,
			NULL,
			0,
			result
	);
}

static int __rrr_discern_stack_add_from (
		struct rrr_discern_stack *target,
		const struct rrr_discern_stack *source
) {
	int ret = 0;

	for (rrr_length i = 0; i < source->list.wpos; i++) {
		const struct rrr_discern_stack_element *node = &source->list.elements[i];
		if ((ret = __rrr_discern_stack_list_push (
				&target->list,
				&target->storage,
				node->type,
				node->op,
				node->value.data_size > 0 ? source->storage.data + node->value.data_pos : NULL,
				node->value.data_size,
				node->value.value
		)) != 0) {
			goto out;
		}
	}

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

	if ((ret = __rrr_discern_stack_add_from (
			new_discern_stack,
			discern_stack
	)) != 0) {
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
		struct rrr_discern_stack_storage *storage,
		const struct rrr_discern_stack_element *node,
		int (*resolve_cb)(rrr_length *result, const char *data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	rrr_length result = 0;

	assert (node->value.data_size > 0);

	if ((ret = resolve_cb (&result, storage->data + node->value.data_pos, callback_arg)) != 0) {
		goto out;
	}

	if ((ret = __rrr_discern_stack_list_push_bool (
			stack,
			storage,
			result
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static rrr_length __rrr_discern_stack_execute_op_and (rrr_length a, rrr_length b) {
	return a && b;
}

static rrr_length __rrr_discern_stack_execute_op_or (rrr_length a, rrr_length b) {
	return a || b;
}

static rrr_length __rrr_discern_stack_execute_op_not (rrr_length a) {
	return !a;
}

static rrr_length __rrr_discern_stack_execute_op_bail (rrr_length a) {
	return a;
}

static int __rrr_discern_stack_execute_op_bool (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *storage,
		rrr_length (*eval_one)(rrr_length a),
		rrr_length (*eval_two)(rrr_length a, rrr_length b)
) {
	int ret = 0;

	const struct rrr_discern_stack_element *a;
	const struct rrr_discern_stack_element *b;
	rrr_length result;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	assert(stack->wpos > 0);
	a = &stack->elements[stack->wpos - 1];
	if (a->type != RRR_DISCERN_STACK_E_BOOL)
		goto out_fail_type;

	if (eval_two) {
		assert(stack->wpos > 1);
		b = &stack->elements[stack->wpos - 2];
		if (b->type != RRR_DISCERN_STACK_E_BOOL)
			goto out_fail_type;
		result = eval_two(a->value.value, b->value.value);
		__rrr_discern_stack_list_pop(stack);
		__rrr_discern_stack_list_pop(stack);
	}
	else {
		result = eval_one(a->value.value);
		__rrr_discern_stack_list_pop(stack);
	}

	if ((ret = __rrr_discern_stack_list_push_bool (
			stack,
			storage,
			result
	)) != 0) {
		*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
		goto out;
	}

	goto out;
	out_fail_type:
		RRR_MSG_0("Operand(s) for operator were not of boolean type as expected\n");
		*fault = RRR_DISCERN_STACK_FAULT_INVALID_TYPE;
		ret = 1;
		goto out;
	out:
		return ret;
}
				
static int __rrr_discern_stack_execute_op_apply (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *storage,
		int (*apply_cb)(rrr_length result, const char *destination, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const struct rrr_discern_stack_element *a = &stack->elements[stack->wpos - 1];
	const struct rrr_discern_stack_element *b = &stack->elements[stack->wpos - 2];

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
	assert(a->value.data_size > 0);

	if ((ret = apply_cb(b->value.value, storage->data + a->value.data_pos, callback_arg)) != 0) {
		*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
		goto out;
	}

	// Pop off destination name and leave boolean value
	__rrr_discern_stack_list_pop(stack);

	out:
	return ret;
}

static int __rrr_discern_stack_execute_op_push (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *storage,
		const struct rrr_discern_stack_element *node,
		int (*resolve_topic_filter_cb)(rrr_length *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(rrr_length *result, const char *tag, void *arg),
		void *resolve_cb_arg
) {
	int ret = 0;

	switch (node->type) {
		case RRR_DISCERN_STACK_E_TOPIC_FILTER:
			if ((ret = __rrr_discern_stack_execute_resolve_and_push (
					stack,
					storage,
					node,
					resolve_topic_filter_cb,
					resolve_cb_arg
			)) != 0) {
				*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_E_ARRAY_TAG:
			if ((ret = __rrr_discern_stack_execute_resolve_and_push (
					stack,
					storage,
					node,
					resolve_array_tag_cb,
					resolve_cb_arg
			)) != 0) {
				*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_E_DESTINATION:
		case RRR_DISCERN_STACK_E_BOOL:
			if ((ret = __rrr_discern_stack_list_push (
					stack,
					storage,
					node->type,
					node->op,
					storage->data + node->value.data_pos,
					node->value.data_size,
					node->value.value
			)) != 0) {
				*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
				goto out;
			}
			break;
		default:
			assert(0);
	};

	out:
	return ret;
}

/*
 * Fast execute with no checks of any kind. The list being
 * run should be verified first during parsing.
 */
static int __rrr_discern_stack_execute (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack *discern_stack,
		int (*resolve_topic_filter_cb)(rrr_length *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(rrr_length *result, const char *tag, void *arg),
		void *resolve_cb_arg,
		int (*apply_cb)(rrr_length result, const char *destination, void *arg),
		void *apply_cb_arg
) {
	struct rrr_discern_stack_list *list = &discern_stack->list;
	struct rrr_discern_stack_value_list *stack = &discern_stack->exe_stack;
	struct rrr_discern_stack_storage *storage = &discern_stack->storage;
	struct rrr_discern_stack_value *elements = storage->data + stack->data_pos;

	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	for (rrr_length i = 0; i < list->wpos; i++) {
		struct rrr_discern_stack_element *node = &discern_stack->list.elements[i];

		if (stack->wpos == stack->size) {
			if ((ret = __rrr_discern_stack_value_list_expand (
					stack,
					storage,
					8
			)) != 0) {
				goto out;
			}
			elements = storage->data + stack->data_pos;
		}

		switch (node->op) {
			case RRR_DISCERN_STACK_OP_PUSH:
				switch (node->type) {
					case RRR_DISCERN_STACK_E_TOPIC_FILTER:
						if ((ret = resolve_topic_filter_cb (
								&(elements[stack->wpos++].value),
								storage->data + node->value.data_pos,
								resolve_cb_arg
						)) != 0) {
							goto out;
						}
						break;
					case RRR_DISCERN_STACK_E_ARRAY_TAG:
						if ((ret = resolve_array_tag_cb (
								&elements[stack->wpos++].value,
								storage->data + node->value.data_pos,
								resolve_cb_arg
						)) != 0) {
							goto out;
						}
						break;
					case RRR_DISCERN_STACK_E_BOOL:
						elements[stack->wpos++].value = 1;
						break;
					case RRR_DISCERN_STACK_E_DESTINATION:
						elements[stack->wpos++] = node->value;
						break;
					default:
						assert(0);
				};
				break;
			case RRR_DISCERN_STACK_OP_AND:
				elements[stack->wpos - 1].value =
					elements[stack->wpos - 1].value &&
					elements[stack->wpos - 2].value;
				stack->wpos--;
				break;
			case RRR_DISCERN_STACK_OP_OR:
				elements[stack->wpos - 1].value =
					elements[stack->wpos - 1].value ||
					elements[stack->wpos - 2].value;
				stack->wpos--;
				break;
			case RRR_DISCERN_STACK_OP_APPLY:
				if ((ret = apply_cb(elements[stack->wpos - 2].value, storage->data + elements[stack->wpos - 1].data_pos, apply_cb_arg)) != 0) {
					*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
					goto out;
				}
				stack->wpos--;
				break;
			case RRR_DISCERN_STACK_OP_NOT:
				elements[stack->wpos - 1].value = !elements[stack->wpos - 1].value;
				break;
			case RRR_DISCERN_STACK_OP_POP:
				stack->wpos--;
				break;
			case RRR_DISCERN_STACK_OP_BAIL:
				if (elements[stack->wpos - 1].value) {
					ret = RRR_DISCERN_STACK_BAIL;
					goto out;
				}
				break;
		}
	}

	out:
	return ret;
}

int rrr_discern_stack_collection_execute (
		enum rrr_discern_stack_fault *fault,
		const struct rrr_discern_stack_collection *collection,
		int (*resolve_topic_filter_cb)(rrr_length *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(rrr_length *result, const char *tag, void *arg),
		void *resolve_callback_arg,
		int (*apply_cb)(rrr_length result, const char *destination, void *arg),
		void *apply_callback_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_discern_stack);
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

/*
 * Slow execution of one list operator. Used only during parsing, but it is
 * possible to use it during run-time as well as the callbacks are the same
 * as for the runtime function.
 */
static int __rrr_discern_stack_parse_execute_step (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *storage,
		const struct rrr_discern_stack_element *node,
		int (*resolve_topic_filter_cb)(rrr_length *result, const char *topic_filter, void *arg),
		int (*resolve_array_tag_cb)(rrr_length *result, const char *tag, void *arg),
		void *resolve_cb_arg,
		int (*apply_cb)(rrr_length result, const char *desination, void *arg),
		void *apply_cb_arg
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const int args = OP_ARG_COUNT(node->op);
	if ((rrr_length) args > stack->wpos) {
		RRR_MSG_0("Not enough elements on stack for operator %s\n", OP_NAME(node->op));
		*fault = RRR_DISCERN_STACK_FAULT_STACK_COUNT;
		ret = 1;
		goto out;
	}

	switch (node->op) {
		case RRR_DISCERN_STACK_OP_PUSH:
			if ((ret =__rrr_discern_stack_execute_op_push (
					fault,
					stack,
					storage,
					node,
					resolve_topic_filter_cb,
					resolve_array_tag_cb,
					resolve_cb_arg
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_AND:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					storage,
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
					storage,
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
					storage,
					apply_cb,
					apply_cb_arg
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_NOT:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					storage,
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
					storage,
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
	}

	out:
	return ret;
}

static int __rrr_discern_stack_parse_execute_resolve (
		rrr_length *result,
		const char *str,
		void *arg
) {
	(void)(str);
	(void)(arg);

	*result = 1;

	return 0;
}

static int __rrr_discern_stack_parse_execute_apply (
		rrr_length result,
		const char *str,
		void *arg
) {
	(void)(result);
	(void)(str);
	(void)(arg);
	return 0;
}

/*
 * Parse and slow execute with all kinds of checks to verify data types and operators. The
 * execution is a dummy one evaluating all operations as we go to produce a stack.
 */
static int __rrr_discern_stack_parse (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack *discern_stack,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	char *str_tmp = NULL;
	const void *data = NULL;
	rrr_length data_size = 0;
	rrr_length value = 0;

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
		value = 0;

		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}
	
		if (rrr_parse_match_word(pos, "#")) {
			rrr_parse_comment(pos);
			continue;
		}
		else if (rrr_parse_match_word(pos, "TRUE")) {
			type = RRR_DISCERN_STACK_E_BOOL;
			value = 1;
		}
		else if (rrr_parse_match_word(pos, "FALSE")) {
			type = RRR_DISCERN_STACK_E_BOOL;
			value = 0;
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
		else if (rrr_parse_match_word(pos, "I")) {
			RRR_MSG_0("Warning: Operator I is depracated in discern stacks. Please update the configuration and use D instead.\n");
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
		data_size = rrr_length_from_size_t_bug_const(rrr_size_t_inc_bug_const(strlen(str_tmp)));

		if (type == RRR_DISCERN_STACK_E_TOPIC_FILTER && rrr_mqtt_topic_filter_validate_name(str_tmp) != 0) {
			RRR_MSG_0("Invalid topic filter '%s' in discern stack definition\n", str_tmp);
			ret = 1;
			*fault = RRR_DISCERN_STACK_FAULT_INVALID_VALUE;
			goto out;
		}

                push:

		if ((ret = __rrr_discern_stack_list_push (
				&discern_stack->list,
				&discern_stack->storage,
				type,
				op,
				data,
				data_size,
				value
		)) != 0) {
			goto out;
		}

		if ((ret = __rrr_discern_stack_parse_execute_step (
				fault,
				&discern_stack->parse_stack,
				&discern_stack->storage,
				&discern_stack->list.elements[discern_stack->list.wpos - 1],
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
		if (discern_stack->parse_stack.wpos == 0) {
			break;
		}
	}

	if (discern_stack->parse_stack.wpos != 0) {
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
		for (rrr_length i = 0; i < discern_stack->list.wpos; i++) {
			const struct rrr_discern_stack_element *e = &discern_stack->list.elements[i];
			if (e->type != RRR_DISCERN_STACK_E_DESTINATION) {
				RRR_LL_ITERATE_NEXT();
			}
			if ((ret = callback(discern_stack->name, node->storage.data + e->value.data_pos, callback_arg)) != 0) {
				goto out;
			}
		}
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
