/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "array_tree.h"
#include "array.h"
#include "type.h"
#include "parse.h"
#include "string_builder.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"

static void __rrr_array_branch_destroy (
		struct rrr_array_branch *branch
) {
	rrr_condition_clear(&branch->condition);
	if (branch->array_tree != NULL) {
		rrr_array_tree_destroy(branch->array_tree);
	}
	RRR_LL_DESTROY(&branch->branches_elsif, struct rrr_array_branch, __rrr_array_branch_destroy(node));
	if (branch->tree_else != NULL) {
		rrr_array_tree_destroy(branch->tree_else);
	}
	free(branch);
}

static void __rrr_array_node_destroy (
		struct rrr_array_node *node
) {
	rrr_array_clear(&node->array);
	if (node->branch_if != NULL) {
		__rrr_array_branch_destroy(node->branch_if);
	}
	free(node);
}

void rrr_array_tree_clear (
		struct rrr_array_tree *tree
) {
	RRR_LL_DESTROY(tree, struct rrr_array_node, __rrr_array_node_destroy(node));
	RRR_FREE_IF_NOT_NULL(tree->name);
}

void rrr_array_tree_destroy (
		struct rrr_array_tree *tree
) {
	 rrr_array_tree_clear(tree);
	free(tree);
}

int rrr_array_tree_new (
		struct rrr_array_tree **target,
		const char *name
) {
	int ret = 0;

	struct rrr_array_tree *new_tree = malloc(sizeof(*new_tree));
	if (new_tree == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_array_tree_new\n");
		ret = 1;
		goto out;
	}

	memset(new_tree, '\0', sizeof(*new_tree));

	if ((new_tree->name = strdup(name != NULL ? name : "-")) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_array_tree_new\n");
		ret = 1;
		goto out;
	}

	*target = new_tree;
	new_tree = NULL;

	out:
	if (new_tree != NULL) {
		free(new_tree);
	}
	return ret;
}

void rrr_array_tree_list_clear (
		struct rrr_array_tree_list *list
) {
	RRR_LL_DESTROY(list, struct rrr_array_tree, rrr_array_tree_destroy(node));
}

const struct rrr_array_tree *rrr_array_tree_list_get_tree_by_name (
		const struct rrr_array_tree_list *list,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(list, const struct rrr_array_tree);
		if (node->name != NULL && strcmp(node->name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

static struct rrr_array_branch *__rrr_array_branch_allocate (void) {
	struct rrr_array_branch *branch = malloc(sizeof(*branch));
	if (branch == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_array_branch_allocate\n");
		return NULL;
	}
	memset(branch, '\0', sizeof(*branch));
	return branch;
}

static struct rrr_array_node *__rrr_array_node_allocate (void) {
	struct rrr_array_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_array_node_allocate\n");
		return NULL;
	}
	memset(node, '\0', sizeof(*node));
	return node;
}

static int __rrr_array_branch_clone_without_data (
		struct rrr_array_branch **target,
		const struct rrr_array_branch *source
) {
	int ret = 0;

	struct rrr_array_branch *new_branch = __rrr_array_branch_allocate();
	if (new_branch == NULL) {
		ret = 1;
		goto out;
	}

	if ((ret = rrr_condition_clone(&new_branch->condition, &source->condition)) != 0) {
		goto out;
	}

	if (source->array_tree != NULL) {
		if ((ret = rrr_array_tree_clone_without_data(&new_branch->array_tree, source->array_tree)) != 0) {
			goto out;
		}
	}

	RRR_LL_ITERATE_BEGIN(&source->branches_elsif, const struct rrr_array_branch);
		struct rrr_array_branch *new_branch_elsif = NULL;
		if ((ret = __rrr_array_branch_clone_without_data(&new_branch_elsif, node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	if (source->tree_else != NULL) {
		if ((ret = rrr_array_tree_clone_without_data(&new_branch->tree_else, source->tree_else)) != 0) {
			goto out;
		}
	}

	*target = new_branch;
	new_branch = NULL;

	out:
	if (new_branch != NULL) {
		__rrr_array_branch_destroy(new_branch);
	}
	return ret;
}

static int __rrr_array_node_clone_without_data (
		struct rrr_array_node **target,
		const struct rrr_array_node *source
) {
	int ret = 0;

	*target = NULL;

	struct rrr_array_node *new_node =__rrr_array_node_allocate();
	if (new_node == NULL) {
		ret = 1;
		goto out;
	}

	new_node->rewind_count = source->rewind_count;

	if ((ret = rrr_array_clone_without_data(&new_node->array, &source->array)) != 0) {
		goto out;
	}

	if (source->branch_if != NULL) {
		if ((ret = __rrr_array_branch_clone_without_data(&new_node->branch_if, source->branch_if)) != 0) {
			goto out;
		}
	}

	*target = new_node;
	new_node = NULL;

	out:
	if (new_node != NULL) {
		__rrr_array_node_destroy(new_node);
	}
	return ret;
}

static int __rrr_array_tree_interpret_if_or_elsif (
		struct rrr_array_branch **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	struct rrr_array_branch *branch;
	if ((branch = __rrr_array_branch_allocate()) == NULL) {
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	if ((ret = rrr_condition_interpret(&branch->condition, pos)) != 0) {
		goto out_destroy_branch;
	}

	if ((ret = rrr_array_tree_interpret(&branch->array_tree, pos, NULL)) != 0) {
		goto out_destroy_branch;
	}

	*target = branch;

	goto out;
	out_destroy_branch:
		__rrr_array_branch_destroy(branch);
	out:
	return ret;
}

static int __rrr_array_tree_interpret_conditional_node (
		struct rrr_array_node **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	struct rrr_array_node *node;
	if ((node = __rrr_array_node_allocate()) == NULL) {
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	if ((ret = __rrr_array_tree_interpret_if_or_elsif(&node->branch_if, pos)) != 0) {
		goto out_destroy_node;
	}

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (rrr_parse_match_word(pos, "ELSIF")) {
			struct rrr_array_branch *branch_elsif;
			if ((ret = __rrr_array_tree_interpret_if_or_elsif(&branch_elsif, pos)) != 0) {
				goto out_destroy_node;
			}
			RRR_LL_APPEND(&node->branch_if->branches_elsif, branch_elsif);
		}
		else {
			break;
		}
	}

	if (rrr_parse_match_word(pos, "ELSE")) {
		struct rrr_array_tree *tree_else;
		if ((ret = rrr_array_tree_interpret(&tree_else, pos, NULL)) != 0) {
			goto out_destroy_node;
		}
		node->branch_if->tree_else = tree_else;
	}

	*target = node;

	goto out;
	out_destroy_node:
		__rrr_array_node_destroy(node);
	out:
		return ret;
}

static int __rrr_array_tree_interpret_identifier_and_size_tag (
		char **target,
		const char **start,
		rrr_length *parsed_bytes
) {
	int ret = RRR_ARRAY_TREE_OK;

	char *result = NULL;

	// Step over {
	(*start)++;
	(*parsed_bytes)++;

	const char *tag_begin = (*start);
	while (**start != '\0' && (RRR_PARSE_MATCH_C_LETTER(**start) || RRR_PARSE_MATCH_C_NUMBER(**start))) {
		(*parsed_bytes)++;
		(*start)++;
	}

	size_t length = (*start) - tag_begin;
	if (length == 0) {
		RRR_MSG_0("Missing tag name after { in defintion\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	if ((**start) != '}') {
		RRR_MSG_0("Missing } after tag name in defintion\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	(*parsed_bytes)++;
	(*start)++;

	if ((result = malloc(length + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for ref tag in __rrr_array_parse_identifier_and_size\n");
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	memcpy(result, tag_begin, length);

	result[length] = '\0';

	*target = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_array_tree_interpret_unsigned_integer_10(const char **end, unsigned long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, (char **) end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_array_tree_interpret_identifier_and_size (
		const struct rrr_type_definition **type_return,
		unsigned int *length_return,
		char **length_ref_return,
		unsigned int *item_count_return,
		char **item_count_ref_return,
		rrr_type_flags *flags_return,
		rrr_length *bytes_parsed_return,
		const char *start,
		const char *end
) {
	int ret = 0;

	rrr_length parsed_bytes = 0;
	rrr_type_flags flags = 0;
	const struct rrr_type_definition *type = NULL;

	char *length_ref = NULL;
	unsigned long long int length = 0;

	char *item_count_ref = NULL;
	unsigned long long int item_count = 1;

	const char *integer_end = NULL;

	*type_return = NULL;
	*length_return = 0;
	*length_ref_return = NULL;
	*item_count_return = 0;
	*item_count_ref_return = NULL;
	*bytes_parsed_return = 0;
	*flags_return = 0;

	type = rrr_type_parse_from_string(&parsed_bytes, start, end);
	if (type == NULL) {
		RRR_MSG_0("Unknown type identifier in type definition here --> '%s'\n", start);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out_err;
	}
	start += parsed_bytes;

	if (type->max_length > 0) {
		if (start >= end || *start == '\0') {
			RRR_MSG_0("Missing size for type '%s' in type definition\n", type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}

		if (*start == '{') {
			if ((ret = __rrr_array_tree_interpret_identifier_and_size_tag(&length_ref, &start, &parsed_bytes)) != 0) {
				goto out_err;
			}
		}
		else {
			if (__rrr_array_tree_interpret_unsigned_integer_10(&integer_end, &length, start) != 0) {
				RRR_MSG_0("Size argument '%s' in type definition '%s' was not a valid number\n",
						start, type->identifier);
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out_err;
			}

			if (length > 0xffffffff) {
				RRR_MSG_0("Size argument '%s' in type definition '%s' was too long, max is 0xffffffff\n",
						start, type->identifier);
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out_err;
			}

			parsed_bytes += integer_end - start;
			start = integer_end;

			if (length <= 0) {
				RRR_MSG_0("Size argument '%lli' in type definition '%s' must be >0\n",
						length, type->identifier);
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out_err;
			}
		}

		if (start >= end || *start == '\0') {
			goto out_ok;
		}

		if (*start == 's' || *start == 'S' || *start == 'u' || *start == 'U') {
			if (!RRR_TYPE_ALLOWS_SIGN(type->type)) {
				RRR_MSG_0("Sign indicator '%c' found in type definition for type '%s' which does not support being signed\n",
						*start, type->identifier);
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out_err;
			}

			if (*start == 's' || *start == 'S') {
				RRR_TYPE_FLAG_SET_SIGNED(flags);
			}

			start++;
			parsed_bytes++;
		}
		else if (RRR_TYPE_ALLOWS_SIGN(type->type)) {
			RRR_TYPE_FLAG_SET_UNSIGNED(flags);
		}
	}
	else {
		if (*start != '\0' && *start != '#' && *start != '@') {
			RRR_MSG_0("Extra data or size argument after type definition '%s' which has automatic size\n",
					type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}
	}

	if (start >= end || *start == '\0') {
		goto out_ok;
	}

	if (*start == '@') {
		start++;
		parsed_bytes++;

		if (start >= end || *start == '\0') {
			RRR_MSG_0("Item count missing after item count definition @ in type %s\n", type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}

		if (*start == '{') {
			if ((ret = __rrr_array_tree_interpret_identifier_and_size_tag(&item_count_ref, &start, &parsed_bytes)) != 0) {
				goto out_err;
			}
		}
		else {
			if (__rrr_array_tree_interpret_unsigned_integer_10(&integer_end, &item_count, start) != 0) {
				RRR_MSG_0("Item count argument '%s' in type definition '%s' was not a valid number\n",
						start, type->identifier);
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out_err;
			}

			parsed_bytes += integer_end - start;
		}

		// start = integer_end; - Enable if more parsing is to be performed

		if (item_count == 0) {
			RRR_MSG_0("Item count definition @ was zero after type '%s', must be in the range 1-65535\n",
					type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}
		if (item_count > 0xffffffff) {
			RRR_MSG_0("Item count definition @ was too big after type '%s', must be in the range 1-65535\n",
					type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}
		/*
		 *  XXX  : It is not possible to allow multiple values for these types as multiple values
		 *         in a node must have equal lengths
		 *         && type->type != RRR_TYPE_STR && type->type != RRR_TYPE_MSG
		 */
		if ((item_count > 1 || item_count_ref != NULL) && type->max_length == 0) {
			RRR_MSG_0("Item count definition @ found after type '%s' which cannot have multiple values\n",
					type->identifier);
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_err;
		}
	}

	out_ok:
		*type_return = type;
		*length_ref_return = length_ref;
		*length_return = length;
		*item_count_return = item_count;
		*item_count_ref_return = item_count_ref;
		*flags_return = flags;
		*bytes_parsed_return = parsed_bytes;
		return 0;

	out_err:
		RRR_FREE_IF_NOT_NULL(item_count_ref);
		RRR_FREE_IF_NOT_NULL(length_ref);
		return ret;
}

static int __rrr_array_tree_interpret_single_definition (
		struct rrr_array *target,
		const char *start,
		const char *end
) {
	int ret = 0;

	rrr_length parsed_bytes = 0;
	const struct rrr_type_definition *type = NULL;
	unsigned int length = 0;
	char *length_ref = NULL;
	unsigned int item_count = 0;
	char *item_count_ref = NULL;
	rrr_type_flags flags = 0;
	const char *tag_start = NULL;
	unsigned int tag_length = 0;

	if ((ret = __rrr_array_tree_interpret_identifier_and_size (
			&type,
			&length,
			&length_ref,
			&item_count,
			&item_count_ref,
			&flags,
			&parsed_bytes,
			start,
			end
	)) != 0) {
		RRR_MSG_0("Error while parsing type identifier and size\n");
		goto out;
	}

	start += parsed_bytes;

	if (*start == '#') {
		start++;
		tag_start = start;

		while (*start != '\0') {
			if (!RRR_PARSE_MATCH_C_LETTER(*start) && !RRR_PARSE_MATCH_C_NUMBER(*start)) {
				RRR_MSG_0("Invalid character '%c' in tag name (decimal %u)\n", (*start), (unsigned char) (*start));
				ret = RRR_ARRAY_TREE_SOFT_ERROR;
				goto out;
			}
			tag_length++;
			start++;
		}

		if (tag_length == 0) {
			RRR_MSG_0("Missing tag name after #\n");
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out;
		}
	}

	if (*start != '\0') {
		RRR_MSG_0("Extra data after type definition here --> '%s'\n", start);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	if (length > type->max_length) {
		RRR_MSG_0("Size argument in type definition '%s' is too large, max is '%u'\n",
				type->identifier, type->max_length);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	struct rrr_type_value *template = NULL;

	if (rrr_type_value_new (
			&template,
			type,
			flags,
			tag_length,
			tag_start,
			length,
			length_ref,
			item_count,
			item_count_ref,
			0
	) != 0) {
		RRR_MSG_0("Could not create value in rrr_array_parse_definition\n");
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	RRR_LL_APPEND(target,template);

	out:
	RRR_FREE_IF_NOT_NULL(length_ref);
	RRR_FREE_IF_NOT_NULL(item_count_ref);
	return ret;
}

#define CHECK_KEYWORDS								\
	do {int pos_orig = pos->pos;					\
	if (rrr_parse_match_word(pos, "IF") ||			\
		rrr_parse_match_word(pos, "ELSIF") ||		\
		rrr_parse_match_word(pos, "ELSE") ||		\
		rrr_parse_match_word(pos, "REWIND")			\
	) {												\
		pos->pos = pos_orig;						\
		*special_found = 1;							\
		goto out;									\
	}} while(0)

static void __rrr_array_tree_interpret_node_check_end (
		struct rrr_parse_pos *pos,
		int *eof_found,
		int *semicolon_found,
		int *comma_found,
		int *special_found
) {
	*eof_found = 0;
	*semicolon_found = 0;
	*comma_found = 0;
	*special_found = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		*eof_found = 1;
		goto out;
	}

	CHECK_KEYWORDS;

	if (*(pos->data + pos->pos) == ',') {
		*comma_found = 1;

		pos->pos++;

		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			*eof_found = 1;
			goto out;
		}

		CHECK_KEYWORDS;

		goto out;
	}
	else if (*(pos->data + pos->pos) == ';') {
		// End of node tree
		*semicolon_found = 1;
		pos->pos++;
		goto out;
	}

	out:
	rrr_parse_ignore_spaces_and_increment_line(pos);
}

static int __rrr_array_tree_interpret_node (
		int *semicolon_found,
		struct rrr_array_node **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	int eof_found = 0;
	int comma_found = 0;
	int special_found = 0;

	struct rrr_array_node *node;
	if ((node = __rrr_array_node_allocate()) == NULL) {
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		__rrr_array_tree_interpret_node_check_end (
				pos,
				&eof_found,
				semicolon_found,
				&comma_found,
				&special_found
		);

		if (eof_found || *semicolon_found || special_found || comma_found) {
			break;
		}

		int start;
		int end;

		rrr_parse_match_until (
				pos,
				&start,
				&end,
				RRR_PARSE_MATCH_COMMAS|RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_NEWLINES|RRR_PARSE_MATCH_NULL|RRR_PARSE_MATCH_END
		);

		if (end < start) {
			break;
		}
		else if (end == start) {
			RRR_MSG_0("Array value definition was too short (only 1 character long)\n");
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_destroy;
		}
		else if (end - start > 64) {
			RRR_MSG_0("Array value definition was too long (more than 64 characters long)\n");
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_destroy;
		}

		size_t length = end - start + 1; // +1 here is not for the \0

		char tmp[length + 1];
		memcpy(tmp, pos->data + start, length);
		tmp[length] = '\0';

//		printf("tmp: %s\n", tmp);

		int i; // DO NOT use unsigned
		for (i = length - 1; i >= 0; i--) {
			if (tmp[i] == ' ' || tmp[i] == '\t' || tmp[i] == '\n' || tmp[i] == '\r') {
				tmp[i] = '\0';
			}
			else {
				break;
			}
		}

		if (i < 2) {
			RRR_MSG_0("Array value definition was too short (less than 2 characters long)\n");
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_destroy;
		}

		if ((ret = __rrr_array_tree_interpret_single_definition(&node->array, tmp, tmp + length)) != 0) {
			goto out_destroy;
		}

		__rrr_array_tree_interpret_node_check_end (
				pos,
				&eof_found,
				semicolon_found,
				&comma_found,
				&special_found
		);

		if (eof_found || *semicolon_found || special_found) {
			break;
		}

		if (!comma_found && !(*semicolon_found)) {
			RRR_MSG_0("Comma or semicolon not found while parsing array definition\n");
			ret = RRR_ARRAY_TREE_SOFT_ERROR;
			goto out_destroy;
		}
	}

	*target = node;

	goto out;
	out_destroy:
		__rrr_array_node_destroy(node);
	out:
		return ret;
}

int __rrr_array_tree_interpret_rewind (
		struct rrr_array_tree *tree,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	struct rrr_array_node *node = NULL;

	int start;
	int end;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		RRR_MSG_0("Missing unsigned number after REWIND keyword in array tree\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	rrr_parse_match_letters(pos, &start, &end, RRR_PARSE_MATCH_NUMBERS);

	if (end < start) {
		RRR_MSG_0("Missing unsigned number after REWIND keyword in array tree\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	rrr_length length = end - start + 1;

	if (length > 12) {
		RRR_MSG_0("Count after REWIND keyword too long in array tree\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	char tmp[32];
	memcpy(tmp, pos->data + start, length);
	tmp[length] = '\0';

	char *endptr;
	rrr_length count = strtoul(tmp, &endptr, 10);

	if ((node = __rrr_array_node_allocate()) == NULL) {
		ret = RRR_ARRAY_TREE_HARD_ERROR;
		goto out;
	}

	node->rewind_count = count;

	RRR_LL_APPEND(tree, node);
	node = NULL;

	out:
	if (node != NULL) {
		__rrr_array_node_destroy(node);
	}
	return ret;
}

int rrr_array_tree_interpret (
		struct rrr_array_tree **target,
		struct rrr_parse_pos *pos,
		const char *name
) {
	int ret = RRR_ARRAY_TREE_OK;

	*target = NULL;

	struct rrr_array_tree *tree = NULL;
	if ((ret = rrr_array_tree_new(&tree, name)) != 0) {
		goto out;
	}

	int semicolon_found = 0;
	while (!RRR_PARSE_CHECK_EOF(pos)) {
		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (*(pos->data + pos->pos) == ';') {
			pos->pos++;
			semicolon_found = 1;
			break;
		}

		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (rrr_parse_match_word(pos, "IF")) {
			struct rrr_array_node *node;
			if ((ret = __rrr_array_tree_interpret_conditional_node(&node, pos)) != 0) {
				goto out_destroy;
			}
			RRR_LL_APPEND(tree, node);
		}
		else if (rrr_parse_match_word(pos, "REWIND")) {
			if ((ret = __rrr_array_tree_interpret_rewind(tree, pos)) != 0) {
				goto out_destroy;
			}
		}

		// Start array definition node
		struct rrr_array_node *node;
		if ((ret = __rrr_array_tree_interpret_node(&semicolon_found, &node, pos)) != 0) {
			goto out_destroy;
		}

		if (RRR_LL_COUNT(&node->array) == 0) {
			__rrr_array_node_destroy(node);
		}
		else {
			RRR_LL_APPEND(tree, node);
		}

		if (semicolon_found) {
			break;
		}
	}

	if (!semicolon_found) {
		RRR_MSG_0("Could not find terminating ; in array tree\n");
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out_destroy;
	}

	*target = tree;

	goto out;
	out_destroy:
		rrr_array_tree_destroy(tree);
	out:
		if (ret != 0) {
			RRR_MSG_0("Array tree parsing failed at line %i position %i\n",
					pos->line, pos->pos - pos->line_begin_pos + 1);
		}
		return ret;
}

int rrr_array_tree_interpret_raw (
		struct rrr_array_tree **target,
		const char *data,
		int data_length,
		const char *name
) {
	struct rrr_parse_pos pos;
	rrr_parse_pos_init(&pos, data, data_length);
	return rrr_array_tree_interpret(target, &pos, name);
}

static void __rrr_array_tree_dump (
		struct rrr_string_builder *string_builder,
		const struct rrr_array_tree *tree,
		int level
);

#define MAKE_TABS						\
	char tabs[level + 1];				\
	for (int i = 0; i < level; i++) {	\
		tabs[i] = '\t';					\
	}									\
	tabs[level] = '\0'

static void __rrr_array_tree_branch_dump (
		struct rrr_string_builder *string_builder,
		const struct rrr_array_branch *branch,
		int level
) {
	MAKE_TABS;

	rrr_string_builder_append_format(string_builder, "%sIF (", tabs);
	rrr_condition_dump(string_builder, &branch->condition);
	rrr_string_builder_append(string_builder, ")\n");
	__rrr_array_tree_dump(string_builder, branch->array_tree, level + 1);

	RRR_LL_ITERATE_BEGIN(&branch->branches_elsif, const struct rrr_array_branch);
		rrr_string_builder_append_format(string_builder, "\n%sELSIF (", tabs);
		rrr_condition_dump(string_builder, &node->condition);
		rrr_string_builder_append(string_builder, ")\n");
		__rrr_array_tree_dump(string_builder, node->array_tree, level + 1);
	RRR_LL_ITERATE_END();

	if (branch->tree_else != NULL) {
		rrr_string_builder_append_format(string_builder, "\n%sELSE\n", tabs);
		__rrr_array_tree_dump(string_builder, branch->tree_else, level + 1);
	}
}

static void __rrr_array_definition_dump (
		struct rrr_string_builder *string_builder,
		const struct rrr_array *array,
		int level
) {
	MAKE_TABS;

	rrr_string_builder_append_format(string_builder, "%s", tabs);

	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (node != RRR_LL_FIRST(array)) {
			rrr_string_builder_append(string_builder, ",");
		}
		rrr_string_builder_append_format(string_builder, "%s", node->definition->identifier);
		if (node->definition->max_length > 0) {
			if (node->import_length_ref != NULL) {
				rrr_string_builder_append_format(string_builder, "{%s}", node->import_length_ref);
			}
			else {
				rrr_string_builder_append_format(string_builder, "%u", node->import_length);
			}
		}
		if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
			rrr_string_builder_append(string_builder, "s");
		}
		if (node->element_count_ref != NULL) {
			rrr_string_builder_append_format(string_builder, "@{%s}", node->element_count_ref);
		}
		else if (node->element_count > 1) {
			rrr_string_builder_append_format(string_builder, "@%u", node->element_count);
		}
		if (node->tag != NULL && *(node->tag) != '\0' && node->tag_length > 0) {
			if (node->tag_length > 32) {
				rrr_string_builder_append(string_builder, "#(very long name)");
			}
			else {
				char tag_tmp[node->tag_length + 1];
				memcpy(tag_tmp, node->tag, node->tag_length);
				tag_tmp[node->tag_length] = '\0';
				rrr_string_builder_append_format(string_builder, "#%s", tag_tmp);
			}
		}
	RRR_LL_ITERATE_END();
}

static void __rrr_array_tree_dump (
		struct rrr_string_builder *string_builder,
		const struct rrr_array_tree *tree,
		int level
) {
	MAKE_TABS;

	RRR_LL_ITERATE_BEGIN(tree, const struct rrr_array_node);
		if (node != RRR_LL_FIRST(tree)) {
			rrr_string_builder_append(string_builder, ",\n");
		}
		if (node->rewind_count > 0) {
			rrr_string_builder_append_format(string_builder, "REWIND%" PRIrrrl, node->rewind_count);
		}
		else if (node->branch_if != NULL) {
			__rrr_array_tree_branch_dump(string_builder, node->branch_if, level);
		}
		else if (RRR_LL_COUNT(&node->array) > 0) {
			__rrr_array_definition_dump(string_builder, &node->array, level);
		}
	RRR_LL_ITERATE_END();
	rrr_string_builder_append (string_builder, "\n");
	rrr_string_builder_append (string_builder, tabs);
	rrr_string_builder_append (string_builder, ";");
}

void rrr_array_tree_dump (
		const struct rrr_array_tree *tree
) {
	struct rrr_string_builder string_builder = {0};

	__rrr_array_tree_dump(&string_builder, tree, 0);

	RRR_DBG_1 ("## ARRAY TREE DUMP BEGIN #############################\n");
	RRR_DBG_1 ("%s", string_builder.buf);
	RRR_DBG_1 ("## ARRAY TREE DUMP END ###############################\n");

	rrr_string_builder_clear(&string_builder);
}

// 1: Check if return value from previous branch condition is FALSE or CONTINUE
// 2: Proceed into tree if current condition return is TRUE or CONTINUE
#define ITERATE_BRANCH_TREE_IF_TRUE(branch)													\
	do { if (ret & (RRR_ARRAY_TREE_CONTINUE|RRR_ARRAY_TREE_CONDITION_FALSE)) {	\
	ret = condition_callback(&branch->condition, callback_arg);								\
	if ((ret & ~(RRR_ARRAY_TREE_CONTINUE|RRR_ARRAY_TREE_CONDITION_FALSE)) != 0) {	\
		goto out;																			\
	}																						\
	if ((ret == RRR_ARRAY_TREE_CONDITION_TRUE) ||											\
		(ret & (RRR_ARRAY_TREE_CONTINUE)													\
	)) { int ret_tmp;																		\
		if ((ret_tmp = __rrr_array_tree_iterate (											\
				branch->array_tree,															\
				value_count,																\
				rewind_callback,															\
				value_callback,																\
				condition_callback,															\
				leaf_callback,																\
				post_loop_callback,															\
				callback_arg																\
		)) != 0) {																			\
			ret = ret_tmp;																	\
			goto out;																		\
		}																					\
	}}} while(0)

static int __rrr_array_tree_iterate (
		const struct rrr_array_tree *tree,
		int value_count,
		int (*rewind_callback)(rrr_length rewind_count, void *arg),
		int (*value_callback)(const struct rrr_type_value *value, void *arg),
		int (*condition_callback)(const struct rrr_condition *condition, void *arg),
		int (*leaf_callback)(void *arg),
		void (*post_loop_callback)(int value_count_orig, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int value_count_orig = value_count;

	RRR_LL_ITERATE_BEGIN(tree, const struct rrr_array_node);
		if (node->rewind_count > 0 && rewind_callback != NULL) {
			if ((ret = rewind_callback(node->rewind_count, callback_arg)) != 0) {
				goto out;
			}
		}

		const struct rrr_array *array = &node->array;
		RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
			value_count++;
			if ((ret = value_callback(node, callback_arg)) != 0) {
				goto out;
			}
		RRR_LL_ITERATE_END();

		if (node->branch_if != NULL) {
			const struct rrr_array_branch *branch_if = node->branch_if;

			// Needs to be set to continue and/or false to start check of first condition
			ret = RRR_ARRAY_TREE_CONTINUE;

			ITERATE_BRANCH_TREE_IF_TRUE(branch_if);

			RRR_LL_ITERATE_BEGIN(&branch_if->branches_elsif, const struct rrr_array_branch);
				ITERATE_BRANCH_TREE_IF_TRUE(node);
			RRR_LL_ITERATE_END();

			if (branch_if->tree_else != NULL && (ret & (RRR_ARRAY_TREE_CONTINUE|RRR_ARRAY_TREE_CONDITION_FALSE))) {
				int ret_tmp;
				if ((ret_tmp = __rrr_array_tree_iterate (
						branch_if->tree_else,
						value_count,
						rewind_callback,
						value_callback,
						condition_callback,
						leaf_callback,
						post_loop_callback,
						callback_arg
				)) != 0) {
					ret = ret_tmp;
					goto out;
				}
			}
		}
		else if (RRR_LL_LAST(tree) == node) {
			if ((ret = leaf_callback(callback_arg)) != 0) {
				if (ret != RRR_ARRAY_TREE_CONTINUE) {
					goto out;
				}
			}
		}
	RRR_LL_ITERATE_END();

	if (post_loop_callback != NULL) {
		post_loop_callback(value_count_orig, callback_arg);
	}

	out:
	ret &= ~(RRR_ARRAY_TREE_CONDITION_FALSE|RRR_ARRAY_TREE_CONTINUE);
	return ret;
}

struct rrr_array_tree_import_callback_data {
	struct rrr_array array;
	const char *start; // Only for bug-check when rewinding
	const char *pos;
	const char *end;
};

int __rrr_array_tree_import_rewind_callback (
		rrr_length count,
		void *arg
) {
	struct rrr_array_tree_import_callback_data *callback_data = arg;
	int ret = 0;

	if ((rrr_slength) count > (rrr_slength) RRR_LL_COUNT(&callback_data->array)) {
		RRR_MSG_0("Attempt to REWIND %" PRIrrrl " positions past beginning of array which currently has %i elements, check configuration\n",
				count, RRR_LL_COUNT(&callback_data->array));
		return RRR_ARRAY_TREE_SOFT_ERROR;
	}

	rrr_slength target = (rrr_slength) RRR_LL_COUNT(&callback_data->array) - (rrr_slength) count;

	rrr_length total_length = 0;
	while (RRR_LL_COUNT(&callback_data->array) > target) {
		struct rrr_type_value *value = RRR_LL_POP(&callback_data->array);
		callback_data->pos -= value->import_length * value->element_count;
		total_length += value->import_length * value->element_count;
		if (callback_data->pos < callback_data->start) {
			RRR_BUG("BUG: REWIND past beginning of buffer occured in __rrr_array_tree_import_rewind_callback\n");
		}
		rrr_type_value_destroy(value);
	}

	RRR_DBG_3("REWIND %" PRIrrrl " array positions and %" PRIrrrl " bytes while parsing array tree\n",
			count, total_length);

	return ret;
}

int __rrr_array_tree_import_value_resolve_ref (
		rrr_length *result,
		const struct rrr_array *source,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN_REVERSE(source, struct rrr_type_value);
		if (node->tag != NULL && strncmp(name, node->tag, node->tag_length) == 0) {
			uint64_t result_tmp = node->definition->to_64(node);
			if (result_tmp > RRR_LENGTH_MAX) {
				RRR_MSG_0("Evaluation of reference '%s' resulted in a value of %" PRIu64 " while maximum value is %" PRIrrrl "\n",
						name, result_tmp, RRR_LENGTH_MAX);
				return RRR_ARRAY_TREE_SOFT_ERROR;
			}
			*result = result_tmp;
			return RRR_ARRAY_TREE_OK;
		}
	RRR_LL_ITERATE_END();

	RRR_MSG_0("Failed to find tag '%s' while resolving reference\n", name);

	return RRR_ARRAY_TREE_SOFT_ERROR;
}

#define RESOLVE_REF(target,ref)																			\
	do {if (new_value->ref != NULL) {																	\
		if ((ret = __rrr_array_tree_import_value_resolve_ref (											\
				&new_value->target, target_array, new_value->ref										\
		)) != 0) {																						\
			goto out;																					\
		}																								\
		RRR_FREE_IF_NOT_NULL(new_value->ref);															\
		if (new_value->target == 0) {																	\
			RRR_MSG_0("Resolve of reference '%s' to use as " RRR_QUOTE(target) " had 0 result\n",		\
				new_value->ref);																		\
			ret = RRR_ARRAY_TREE_SOFT_ERROR;															\
			goto out;																					\
		}																								\
	}} while (0)

int __rrr_array_tree_import_value_callback (
		const struct rrr_type_value *value,
		void *arg
) {
	struct rrr_array_tree_import_callback_data *callback_data = arg;
	struct rrr_array *target_array = &callback_data->array;

	int ret = 0;

	struct rrr_type_value *new_value = NULL;
	if ((ret = rrr_type_value_clone(&new_value, value, 0)) != 0) {
		goto out;
	}

	if (new_value->definition->import == NULL) {
		RRR_BUG("BUG: No convert function found for type %d\n", new_value->definition->type);
	}

	if (new_value->data != NULL) {
		RRR_BUG("node->data was not NULL in __rrr_array_tree_import_data_into_value\n");
	}

	RESOLVE_REF(import_length,import_length_ref);
	RESOLVE_REF(element_count,element_count_ref);

	if (new_value->import_length == 0 && new_value->definition->max_length != 0) {
		RRR_MSG_0("Import length was %" PRIrrrl " while importing array value of type %s, must be non-zero\n",
				new_value->import_length, new_value->definition->identifier);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	if (new_value->element_count == 0) {
		RRR_MSG_0("Element count was %" PRIrrrl " while importing array value of type %s, must be non-zero\n",
				new_value->element_count, new_value->definition->identifier);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	if (new_value->import_length > new_value->definition->max_length) {
		RRR_MSG_0("Import length was %" PRIrrrl " while maximum is %" PRIrrrl " while importing array value of type %s\n",
				new_value->import_length, new_value->definition->max_length, new_value->definition->identifier);
		ret = RRR_ARRAY_TREE_SOFT_ERROR;
		goto out;
	}

	rrr_length parsed_bytes = 0;
	if ((ret = new_value->definition->import (
			new_value,
			&parsed_bytes,
			callback_data->pos,
			callback_data->end
	)) != 0) {
		if (ret == RRR_TYPE_PARSE_INCOMPLETE) {
			goto out;
		}
		else if (ret == RRR_TYPE_PARSE_SOFT_ERR) {
			RRR_MSG_0("Invalid data in type conversion\n");
		}
		else {
			RRR_MSG_0("Hard error while importing data in __rrr_array_tree_import_data_into_value, return was %i\n", ret);
			ret = RRR_ARRAY_TREE_HARD_ERROR;
		}
		goto out;
	}

	if (parsed_bytes == 0) {
		RRR_BUG("Parsed bytes was zero in rrr_array_parse_data_from_definition\n");
	}

	RRR_DBG_3("Imported a value of type %s size %" PRIrrrl "x%" PRIrrrl "\n",
			new_value->definition->identifier, new_value->import_length, new_value->element_count);

	callback_data->pos += parsed_bytes;

	RRR_LL_APPEND(&callback_data->array, new_value);
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	return ret;
}

static int __rrr_array_tree_import_condition_name_evaluate_callback (
		RRR_CONDITION_NAME_EVALUATE_CALLBACK_ARGS
) {
	*result = 0;

	struct rrr_array *array_tmp = arg;

	RRR_LL_ITERATE_BEGIN_REVERSE(array_tmp, struct rrr_type_value);
		if (node->tag != NULL && strncmp(node->tag, name, node->tag_length) == 0) {
			*result = node->definition->to_64(node);
			*is_signed = RRR_TYPE_FLAG_IS_SIGNED(node->flags);
			return RRR_ARRAY_TREE_OK;
		}
	RRR_LL_ITERATE_END();

	RRR_MSG_0("Array tag '%s' could not be resolved while parsing input data. Check configuration and REWIND usage.\n", name);

	return RRR_ARRAY_TREE_SOFT_ERROR;
}

int __rrr_array_tree_import_condition_callback (
		const struct rrr_condition *condition,
		void *arg
) {
	struct rrr_array_tree_import_callback_data *callback_data = arg;

	int ret = RRR_ARRAY_TREE_CONDITION_FALSE;
	uint64_t result = 0;

	if ((ret = rrr_condition_evaluate (
			&result,
			condition,
			__rrr_array_tree_import_condition_name_evaluate_callback,
			&callback_data->array
	)) != 0) {
		goto out;
	}

	if (!result) {
		ret = RRR_ARRAY_TREE_CONDITION_FALSE;
	}

	out:
	return ret;
}


int __rrr_array_tree_import_leaf_callback (
		void *arg
) {
	struct rrr_array_tree_import_callback_data *callback_data = arg;

	(void)(callback_data);

	// Nothing to do but returning 0 to signal completion

	return 0;
}

int rrr_array_tree_clone_without_data (
		struct rrr_array_tree **target,
		const struct rrr_array_tree *source
) {
	int ret = 0;

	struct rrr_array_tree *new_tree = NULL;

	if ((ret = rrr_array_tree_new(&new_tree, source->name)) != 0) {
		goto out;
	}

	struct rrr_array_node *node_tmp = NULL;

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_array_node);
		if ((ret = __rrr_array_node_clone_without_data(&node_tmp, node)) != 0) {
			goto out;
		}
		RRR_LL_PUSH(new_tree, node_tmp);
	RRR_LL_ITERATE_END();

	*target = new_tree;
	new_tree = NULL;

	out:
	if (new_tree != NULL) {
		rrr_array_tree_destroy(new_tree);
	}
	return ret;
}

int rrr_array_tree_import_from_buffer (
		ssize_t *parsed_bytes,
		const char *buf,
		ssize_t buf_len,
		const struct rrr_array_tree *tree,
		int (*callback)(struct rrr_array *array, void *arg),
		void *callback_arg
) {
	int ret = 0;

	*parsed_bytes = 0;

	struct rrr_array_tree_import_callback_data callback_data = {0};

	callback_data.start = buf;
	callback_data.pos = buf;
	callback_data.end = buf + buf_len;

	if ((ret = __rrr_array_tree_iterate (
			tree,
			0,
			__rrr_array_tree_import_rewind_callback,
			__rrr_array_tree_import_value_callback,
			__rrr_array_tree_import_condition_callback,
			__rrr_array_tree_import_leaf_callback,
			NULL,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = callback(&callback_data.array, callback_arg)) != 0) {
		goto out;
	}

	*parsed_bytes = callback_data.pos - buf;

	out:
	rrr_array_clear(&callback_data.array);
	return ret;
}

