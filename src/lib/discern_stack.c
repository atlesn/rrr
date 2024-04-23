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
#include "rrr_inttypes.h"
#include "mqtt/mqtt_topic.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

#define RRR_DISCERN_STACK_OK     RRR_READ_OK
#define RRR_DISCERN_STACK_BAIL   RRR_READ_EOF

#define RRR_DISCERN_STACK_MAX 64

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
	rrr_length data_pos;
	rrr_length value;
	rrr_length pad;
};

struct rrr_discern_stack_element {
	enum rrr_discern_stack_element_type type;
	enum rrr_discern_stack_operator_type op;
	struct rrr_discern_stack_value value;
};

struct rrr_discern_stack_list {
	rrr_length data_pos;
	rrr_length size;
	rrr_length wpos;
};

struct rrr_discern_stack_value_list {
	rrr_length data_pos;
	rrr_length size;
};

struct rrr_discern_stack {
	RRR_LL_NODE(struct rrr_discern_stack);
	struct rrr_discern_stack_list exe_list;
	struct rrr_discern_stack_storage exe_storage;
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
		if ((new_data = rrr_reallocate(target->data, new_capacity)) == NULL) {
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

static int __rrr_discern_stack_storage_merge (
		struct rrr_discern_stack_storage *target,
		rrr_length *a_pos,
		rrr_length *b_pos,
		struct rrr_discern_stack_storage *source_a,
		struct rrr_discern_stack_storage *source_b
) {
	int ret = 0;

	if ((ret = __rrr_discern_stack_storage_push (
			a_pos,
			target,
			source_a->data,
			source_a->size
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_discern_stack_storage_push (
			b_pos,
			target,
			source_b->data,
			source_b->size
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void __rrr_discern_stack_storage_clear (
		struct rrr_discern_stack_storage *target
) {
	RRR_FREE_IF_NOT_NULL(target->data);
	memset(target, '\0', sizeof(*target));
}

static void __rrr_discern_stack_destroy (
		struct rrr_discern_stack *discern_stack
) {
	__rrr_discern_stack_storage_clear(&discern_stack->exe_storage);
	rrr_free(discern_stack->name);
	rrr_free(discern_stack);
}

static void __rrr_discern_stack_list_pop (
		struct rrr_discern_stack_list *discern_stack
) {
	assert(discern_stack->wpos > 0);
	discern_stack->wpos--;
}

static int __rrr_discern_stack_data_expand (
		void **data,
		rrr_length *data_size,
		rrr_length *data_pos,
		struct rrr_discern_stack_storage *storage,
		rrr_length expand_size,
		rrr_length element_size
) {
	int ret = 0;

	rrr_length new_size = *data_size + expand_size;
	rrr_length new_size_bytes = new_size * element_size;

	if (*data_size > 0) {
		// The data must already be in the given storage as the last data segment
		assert((void *) *data >= storage->data && (void *) *data < storage->data + storage->size);
		assert(storage->size >= *data_size * element_size);

		storage->size -= *data_size * element_size;

		assert(*data_pos == storage->size);
		assert(*data == storage->data + storage->size);
	}

	if ((ret = __rrr_discern_stack_storage_push (
			data_pos,
			storage,
			NULL,
			new_size_bytes
	)) != 0) {
		goto out;
	}

	*data = storage->data + *data_pos;
	*data_size = new_size;

	out:
	return ret;
}

static int __rrr_discern_stack_list_expand (
		struct rrr_discern_stack_list *list,
		struct rrr_discern_stack_storage *storage,
		rrr_length expand_size
) {
	struct rrr_discern_stack_element *elements = storage->data + list->data_pos;

	int ret = 0;

	rrr_length size_tmp = list->size;
	rrr_length data_pos_tmp = list->data_pos;

	if ((ret = __rrr_discern_stack_data_expand (
			(void **) &elements,
			&size_tmp,
			&data_pos_tmp,
			storage,
			expand_size,
			sizeof(*elements)
	)) != 0) {
		goto out;
	}

	list->size = size_tmp;
	list->data_pos = data_pos_tmp;

	out:
	return ret;
}

static int __rrr_discern_stack_list_push (
		struct rrr_discern_stack_list *list,
		struct rrr_discern_stack_storage *list_storage,
		enum rrr_discern_stack_element_type type,
		enum rrr_discern_stack_operator_type op,
		struct rrr_discern_stack_storage *value_storage,
		const void *data,
		rrr_length data_size,
		rrr_length value
) {
	int ret = 0;

	assert (list->wpos <= list->size);

	struct rrr_discern_stack_element *element = &((struct rrr_discern_stack_element *) (list_storage->data + list->data_pos))[list->wpos];

	if (list->wpos == list->size) {
		if ((ret = __rrr_discern_stack_list_expand (
				list,
				list_storage,
				8
		)) != 0) {
			goto out;
		}
		element = &((struct rrr_discern_stack_element *) (list_storage->data + list->data_pos))[list->wpos];
	}

	element->type = type;
	element->op = op;
	if (data_size > 0) {
		assert(data != NULL);

		if ((ret = __rrr_discern_stack_storage_push (
				&element->value.data_pos,
				value_storage,
				data,
				data_size
		)) != 0) {
			goto out;
		}

		RRR_ASSERT(sizeof(rrr_length) == sizeof(rrr_u32),size_of_rrr_length_is_4_bytes);

		const char *str = value_storage->data + element->value.data_pos;
		element->value.value = RRR_DISCERN_STACK_FIRST_LAST_INDEX(str, strlen(str));
		element->value.data_size = data_size;
	}
	else {
		assert(data_size == 0);
		element->value.data_size = 0;
		element->value.value = value;
	}

	list->wpos++;

	goto out;
	out:
		return ret;
}

static int __rrr_discern_stack_list_push_bool (
		struct rrr_discern_stack_list *list,
		struct rrr_discern_stack_storage *storage,
		rrr_length result
) {
	return __rrr_discern_stack_list_push (
			list,
			storage,
			RRR_DISCERN_STACK_E_BOOL,
			RRR_DISCERN_STACK_OP_PUSH,
			NULL,
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

	assert(target->exe_storage.data == NULL);

	target->exe_storage = source->exe_storage;

	if ((target->exe_storage.data = rrr_allocate(source->exe_storage.capacity)) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memcpy(target->exe_storage.data, source->exe_storage.data, source->exe_storage.capacity);

	target->exe_list = source->exe_list;

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
		struct rrr_discern_stack_storage *stack_storage,
		rrr_length (*eval_one)(rrr_length a),
		rrr_length (*eval_two)(rrr_length a, rrr_length b)
) {
	int ret = 0;

	const struct rrr_discern_stack_element *a;
	const struct rrr_discern_stack_element *b;
	rrr_length result;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	assert(stack->wpos > 0);
	a = &((const struct rrr_discern_stack_element *) (stack_storage->data + stack->data_pos))[stack->wpos - 1];
	if (a->type != RRR_DISCERN_STACK_E_BOOL)
		goto out_fail_type;

	if (eval_two) {
		assert(stack->wpos > 1);
		b = &((const struct rrr_discern_stack_element *) (stack_storage->data + stack->data_pos))[stack->wpos - 2];
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
			stack_storage,
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
		struct rrr_discern_stack_storage *stack_storage
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	const struct rrr_discern_stack_element *a = &((const struct rrr_discern_stack_element *) (stack_storage->data + stack->data_pos))[stack->wpos - 1];
	const struct rrr_discern_stack_element *b = &((const struct rrr_discern_stack_element *) (stack_storage->data + stack->data_pos))[stack->wpos - 2];

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

	// No apply callback for parsing, it would otherwise go here. Nothing do do.
	// (call apply cb)

	// Pop off destination name and leave boolean value
	__rrr_discern_stack_list_pop(stack);

	out:
	return ret;
}

static int __rrr_discern_stack_execute_op_push (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *stack_storage,
		const struct rrr_discern_stack_element *node,
		struct rrr_discern_stack_storage *value_storage
) {
	int ret = 0;

	rrr_length result;

	switch (node->type) {
		case RRR_DISCERN_STACK_E_TOPIC_FILTER:
			// Pretend topic filter matches
			result = 1;
			if ((ret = __rrr_discern_stack_list_push_bool (
					stack,
					stack_storage,
					result
			)) != 0) {
				*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_E_ARRAY_TAG:
			// Pretend array tag exists
			result = 1;
			if ((ret = __rrr_discern_stack_list_push_bool (
					stack,
					stack_storage,
					result
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_E_DESTINATION:
		case RRR_DISCERN_STACK_E_BOOL:
			if ((ret = __rrr_discern_stack_list_push (
					stack,
					stack_storage,
					node->type,
					node->op,
					value_storage,
					value_storage->data + node->value.data_pos,
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

static int __rrr_discern_stack_execute_apply_cb_dummy (RRR_DISCERN_STACK_APPLY_CB_ARGS) {
	(void)(destination);
	(void)(arg);
	return 0;
}

/*
 * Fast execute with no checks of any kind. The list being
 * run should be verified first during parsing.
 */
static int __rrr_discern_stack_execute (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack *discern_stack,
		const struct rrr_discern_stack_callbacks *callbacks
) {
	const struct rrr_discern_stack_list *list = &discern_stack->exe_list;
	struct rrr_discern_stack_storage *list_storage = &discern_stack->exe_storage;

	int ret = 0;

	struct rrr_discern_stack_value_list stack = {
		.data_pos = 0,
		.size = RRR_DISCERN_STACK_MAX
	};
	struct rrr_discern_stack_value stack_e[RRR_DISCERN_STACK_MAX];
	rrr_length wpos = 0;

	int (*const apply_cbs[2])(RRR_DISCERN_STACK_APPLY_CB_ARGS) = {
		callbacks->apply_cb_false ? callbacks->apply_cb_false : __rrr_discern_stack_execute_apply_cb_dummy,
		callbacks->apply_cb_true
	};

	const struct rrr_discern_stack_element *node;
	struct rrr_discern_stack_index_entry *index_tmp = NULL;
	rrr_length index_tmp_size = 0;
	rrr_length index_result;

	memset(stack_e, '\0', sizeof(stack_e));

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	for (rrr_length i = 0; i < list->wpos; i++) {
		assert (wpos < stack.size);

		node = &((const struct rrr_discern_stack_element *) (list_storage->data + list->data_pos))[i];

		switch (node->op) {
			case RRR_DISCERN_STACK_OP_PUSH:
				switch (node->type) {
					case RRR_DISCERN_STACK_E_TOPIC_FILTER:
						if ((ret = callbacks->resolve_topic_filter_cb (
								&stack_e[wpos++].value,
								list_storage->data + node->value.data_pos,
								node->value.data_size,
								callbacks->resolve_cb_arg
						)) != 0) {
							goto out;
						}
						break;
					case RRR_DISCERN_STACK_E_ARRAY_TAG:
						// Check against any index from the callback. If the first and last
						// letter do not match any index entry, we produce false result
						// immediately.
						index_result = 1;
						for (rrr_length i = 0; i < index_tmp_size; i++) {
							if ((index_result = index_tmp[i].id == node->value.value)) {
								break;
							}
						}

						if (!index_result) {
							stack_e[wpos++].value = 0;
							break;
						}

						// The callback may set a temporary index used to quickly eliminate
						// H array tag check without calling the callback. The callback
						// may set the index one time during an execution session.
						if ((ret = callbacks->resolve_array_tag_cb (
								&stack_e[wpos++].value,
								&index_tmp,
								&index_tmp_size,
								list_storage->data + node->value.data_pos,
								callbacks->resolve_cb_arg
						)) != 0) {
							goto out;
						}
						break;
					case RRR_DISCERN_STACK_E_BOOL:
						stack_e[wpos++].value = 1;
						break;
					case RRR_DISCERN_STACK_E_DESTINATION:
						stack_e[wpos++] = node->value;
						break;
					default:
						assert(0);
				};
				break;
			case RRR_DISCERN_STACK_OP_AND:
				stack_e[wpos - 2].value =
					stack_e[wpos - 1].value &&
					stack_e[wpos - 2].value;
				wpos--;
				break;
			case RRR_DISCERN_STACK_OP_OR:
				stack_e[wpos - 2].value =
					stack_e[wpos - 1].value ||
					stack_e[wpos - 2].value;
				wpos--;
				break;
			case RRR_DISCERN_STACK_OP_APPLY:
				if ((ret = apply_cbs[stack_e[wpos - 2].value & 1](list_storage->data + stack_e[wpos - 1].data_pos, callbacks->apply_cb_arg)) != 0) {
					*fault = RRR_DISCERN_STACK_FAULT_CRITICAL;
					goto out;
				}
				wpos--;
				break;
			case RRR_DISCERN_STACK_OP_NOT:
				stack_e[wpos - 1].value = !stack_e[wpos - 1].value;
				break;
			case RRR_DISCERN_STACK_OP_POP:
				wpos--;
				break;
			case RRR_DISCERN_STACK_OP_BAIL:
				if (stack_e[wpos - 1].value) {
					ret = RRR_DISCERN_STACK_BAIL;
					goto out;
				}
				break;
			default:
				assert(0);
		}
	}

	assert(wpos == 0);

	out:
	RRR_FREE_IF_NOT_NULL(index_tmp);
	return ret;
}

int rrr_discern_stack_collection_execute (
		enum rrr_discern_stack_fault *fault,
		const struct rrr_discern_stack_collection *collection,
		const struct rrr_discern_stack_callbacks *callbacks
) {
	int ret = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_discern_stack);
		if ((ret = __rrr_discern_stack_execute (
				fault,
				node,
				callbacks
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

/*
 * Slow execution of one list operator, used only during parsing.
 */
static int __rrr_discern_stack_parse_execute_step (
		enum rrr_discern_stack_fault *fault,
		struct rrr_discern_stack_list *stack,
		struct rrr_discern_stack_storage *stack_storage,
		const struct rrr_discern_stack_element *node,
		struct rrr_discern_stack_storage *value_storage
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
					stack_storage,
					node,
					value_storage
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_AND:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					stack_storage,
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
					stack_storage,
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
					stack_storage
			)) != 0) {
				goto out;
			}
			break;
		case RRR_DISCERN_STACK_OP_NOT:
			if ((ret = __rrr_discern_stack_execute_op_bool (
					fault,
					stack,
					stack_storage,
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
					stack_storage,
					__rrr_discern_stack_execute_op_bail,
					NULL
			)) != 0) {
				goto out;
			}

			// XXX : Probably not useful to check if we are to bail or not as the
			//       parser ignores bail return value.

			// Note : Subtract wpos, first then don't do -1 when retrieving value
			stack->wpos--;
			if (((struct rrr_discern_stack_element *) (stack_storage->data + stack->data_pos))[stack->wpos].value.value) {
				ret = RRR_DISCERN_STACK_BAIL;
				goto out;
			}

			break;
	}

	assert(stack->wpos <= RRR_DISCERN_STACK_MAX);
	if (stack->wpos == RRR_DISCERN_STACK_MAX) {
		RRR_MSG_0("Stack overflow in discern stack. The maximum of %u pushed elements exceeded.\n", RRR_DISCERN_STACK_MAX);
		*fault = RRR_DISCERN_STACK_FAULT_STACK_OVERFLOW;
		ret = 1;
		goto out;
	}

	out:
	return ret;
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

	struct rrr_discern_stack_storage stack_storage = {0};
	struct rrr_discern_stack_storage list_storage = {0};
	struct rrr_discern_stack_storage value_storage = {0};
	struct rrr_discern_stack_list stack = {0};
	struct rrr_discern_stack_list list = {0};

	char *str_tmp = NULL;
	const void *data = NULL;
	rrr_length data_size = 0;
	rrr_length value = 0;

	*fault = RRR_DISCERN_STACK_FAULT_OK;

	rrr_parse_ignore_control_and_increment_line(pos);

	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Unexpected end of file while parsing discern stack definition\n");
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

		if (type == RRR_DISCERN_STACK_E_TOPIC_FILTER) {
			if (rrr_mqtt_topic_filter_validate_name(str_tmp) != 0) {
				RRR_MSG_0("Invalid topic filter '%s' in discern stack definition\n", str_tmp);
				ret = 1;
				*fault = RRR_DISCERN_STACK_FAULT_INVALID_VALUE;
				goto out;
			}
		}

		data = str_tmp;
		data_size = rrr_length_from_size_t_bug_const(rrr_size_t_inc_bug_const(strlen(str_tmp)));

                push:

		if ((ret = __rrr_discern_stack_list_push (
				&list,
				&list_storage,
				type,
				op,
				&value_storage,
				data,
				data_size,
				value
		)) != 0) {
			goto out;
		}

		if ((ret = __rrr_discern_stack_parse_execute_step (
				fault,
				&stack,
				&stack_storage,
				&((const struct rrr_discern_stack_element *) (list_storage.data + list.data_pos))[list.wpos - 1],
				&value_storage
		)) != 0) {
			if (ret == RRR_DISCERN_STACK_BAIL) {
				ret = 0;
			}
			else {
				goto out;
			}
		}

		// Parsing is done when stack would have been empty
		if (stack.wpos == 0) {
			break;
		}
	}

	if (stack.wpos != 0) {
		// Happens if POP is missing and we reach EOF
		RRR_MSG_0("Discern definition would not have empty stack after execution, maybe there are not enough POP operators?\n");
		ret = 1;
		*fault = RRR_DISCERN_STACK_FAULT_STACK_COUNT;
		goto out;
	}

	rrr_length list_pos;
	rrr_length value_pos;

	if ((ret = __rrr_discern_stack_storage_merge (
			&discern_stack->exe_storage,
			&value_pos,
			&list_pos,
			&value_storage,
			&list_storage
	)) != 0) {
		goto out;
	}

	// Value references in the list still have valid references
	// as long as the values are first in the target storage 
	assert(value_pos == 0);

	discern_stack->exe_list = list;
	discern_stack->exe_list.data_pos = list_pos;

	goto out;
	out:
		if (ret != 0) {
			RRR_FREE_IF_NOT_NULL(str_tmp);
			rrr_parse_make_location_message(&str_tmp, pos);
			printf("%s", str_tmp);
		}
		__rrr_discern_stack_storage_clear(&stack_storage);
		__rrr_discern_stack_storage_clear(&list_storage);
		__rrr_discern_stack_storage_clear(&value_storage);
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
		for (rrr_length i = 0; i < discern_stack->exe_list.wpos; i++) {
			const struct rrr_discern_stack_element *e = &((const struct rrr_discern_stack_element *) (discern_stack->exe_storage.data + discern_stack->exe_list.data_pos))[i];
			if (e->type != RRR_DISCERN_STACK_E_DESTINATION) {
				continue;
			}
			if ((ret = callback(discern_stack->name, node->exe_storage.data + e->value.data_pos, callback_arg)) != 0) {
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
