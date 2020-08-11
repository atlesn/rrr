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
#include "util/linked_list.h"
#include "array_tree.h"
#include "array.h"
#include "type.h"
#include "parse.h"

static void __rrr_array_branch_destroy(struct rrr_array_branch *branch) {
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

static void __rrr_array_node_destroy (struct rrr_array_node *node) {
	rrr_array_clear(&node->array);
	if (node->branch_if != NULL) {
		__rrr_array_branch_destroy(node->branch_if);
	}
	free(node);
}

void rrr_array_tree_destroy (struct rrr_array_tree *tree) {
	RRR_LL_DESTROY(tree, struct rrr_array_node, __rrr_array_node_destroy(node));
	RRR_FREE_IF_NOT_NULL(tree->name);
	free(tree);
}

void rrr_array_tree_list_destroy (
		struct rrr_array_tree_list *list
) {
	RRR_LL_DESTROY(list, struct rrr_array_tree, rrr_array_tree_destroy(node));
}

static struct rrr_array_branch *__rrr_array_branch_allocate(void) {
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

static int __rrr_array_tree_parse_if (
		struct rrr_array_branch **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	struct rrr_array_branch *branch;
	if ((branch = __rrr_array_branch_allocate()) == NULL) {
		ret = RRR_ARRAY_HARD_ERROR;
		goto out;
	}

	if ((ret = rrr_condition_parse(&branch->condition, pos)) != 0) {
		goto out_destroy_branch;
	}

	if ((ret = rrr_array_tree_parse(&branch->array_tree, pos, NULL)) != 0) {
		goto out_destroy_branch;
	}

	*target = branch;

	goto out;
	out_destroy_branch:
		__rrr_array_branch_destroy(branch);
	out:
	return ret;
}

static int __rrr_array_tree_parse_if_node (
		struct rrr_array_node **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	struct rrr_array_node *node;
	if ((node = __rrr_array_node_allocate()) == NULL) {
		ret = RRR_ARRAY_HARD_ERROR;
		goto out;
	}

	if ((ret = __rrr_array_tree_parse_if(&node->branch_if, pos)) != 0) {
		goto out_destroy_node;
	}

	*target = node;

	goto out;
	out_destroy_node:
		__rrr_array_node_destroy(node);
	out:
		return ret;
}

static int __rrr_array_tree_parse_single_definition (
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

	if ((ret = rrr_array_parse_identifier_and_size (
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
			if (!RRR_PARSE_MATCH_C_LETTER(*start)) {
				RRR_MSG_0("Invalid character '%c' in tag name (decimal %u)\n", (*start), (unsigned char) (*start));
				ret = RRR_ARRAY_SOFT_ERROR;
				goto out;
			}
			tag_length++;
			start++;
		}

		if (tag_length == 0) {
			RRR_MSG_0("Missing tag name after #\n");
			ret = RRR_ARRAY_SOFT_ERROR;
			goto out;
		}
	}

	if (*start != '\0') {
		RRR_MSG_0("Extra data after type definition here --> '%s'\n", start);
		ret = RRR_ARRAY_SOFT_ERROR;
		goto out;
	}

	if (length > type->max_length) {
		RRR_MSG_0("Size argument in type definition '%s' is too large, max is '%u'\n",
				type->identifier, type->max_length);
		ret = RRR_ARRAY_SOFT_ERROR;
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
		ret = RRR_ARRAY_HARD_ERROR;
		goto out;
	}

	RRR_LL_APPEND(target,template);

	out:
	RRR_FREE_IF_NOT_NULL(length_ref);
	RRR_FREE_IF_NOT_NULL(item_count_ref);
	return ret;
}

#define CHECK_BRANCH								\
	do {int pos_orig = pos->pos;					\
	if (rrr_parse_match_word(pos, "IF") ||			\
		rrr_parse_match_word(pos, "ELSIF") ||		\
		rrr_parse_match_word(pos, "ELSE")			\
	) {												\
		pos->pos = pos_orig;						\
		*branch_found = 1;							\
		goto out;									\
	}} while(0)

static void __rrr_array_tree_parse_definition_node_check_end (
		struct rrr_parse_pos *pos,
		int *eof_found,
		int *semicolon_found,
		int *comma_found,
		int *branch_found
) {
	*eof_found = 0;
	*semicolon_found = 0;
	*comma_found = 0;
	*branch_found = 0;

	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		*eof_found = 1;
		goto out;
	}

	CHECK_BRANCH;

	if (*(pos->data + pos->pos) == ',') {
		*comma_found = 1;

		pos->pos++;

		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			*eof_found = 1;
			goto out;
		}

		CHECK_BRANCH;

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

static int __rrr_array_tree_parse_definition_node (
		int *semicolon_found,
		struct rrr_array_node **target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*target = NULL;

	int eof_found = 0;
	int comma_found = 0;
	int branch_found = 0;

	struct rrr_array_node *node;
	if ((node = __rrr_array_node_allocate()) == NULL) {
		ret = RRR_ARRAY_HARD_ERROR;
		goto out;
	}

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		__rrr_array_tree_parse_definition_node_check_end(
				pos,
				&eof_found,
				semicolon_found,
				&comma_found,
				&branch_found
		);

		if (eof_found || *semicolon_found || branch_found || comma_found) {
			break;
		}

		int start;
		int end;

		rrr_parse_match_until (
				pos,
				&start,
				&end,
				RRR_PARSE_MATCH_COMMAS|RRR_PARSE_MATCH_SPACE_TAB|RRR_PARSE_MATCH_NEWLINES
		);

		if (end < start) {
			break;
		}
		else if (end == start) {
			RRR_MSG_0("Array value definition was too short (only 1 character long)\n");
			ret = RRR_ARRAY_SOFT_ERROR;
			goto out_destroy;
		}
		else if (end - start > 64) {
			RRR_MSG_0("Array value definition was too long (more than 64 characters long)\n");
			ret = RRR_ARRAY_SOFT_ERROR;
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
			ret = RRR_ARRAY_SOFT_ERROR;
			goto out_destroy;
		}

		if ((ret = __rrr_array_tree_parse_single_definition(&node->array, tmp, tmp + length)) != 0) {
			goto out_destroy;
		}

		__rrr_array_tree_parse_definition_node_check_end (
				pos,
				&eof_found,
				semicolon_found,
				&comma_found,
				&branch_found
		);

		if (eof_found || *semicolon_found || branch_found) {
			break;
		}

		if (!comma_found && !(*semicolon_found)) {
			RRR_MSG_0("Comma or semicolon not found while parsing array definition\n");
			ret = RRR_ARRAY_SOFT_ERROR;
			goto out;
		}
	}

	*target = node;

	goto out;
	out_destroy:
		__rrr_array_node_destroy(node);
	out:
		return ret;
}

int rrr_array_tree_parse (
		struct rrr_array_tree **target,
		struct rrr_parse_pos *pos,
		const char *name
) {
	int ret = RRR_ARRAY_OK;

	*target = NULL;

	struct rrr_array_tree *tree = malloc(sizeof(*tree));
	if (tree == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_array_tree_parse\n");
		ret = RRR_ARRAY_HARD_ERROR;
		goto out;
	}

	memset(tree, '\0', sizeof(*tree));

	if ((tree->name = strdup(name != NULL ? name : "-")) == NULL) {
		RRR_MSG_0("Could not allocate name in rrr_array_tree_parse\n");
		ret = 1;
		goto out_destroy;
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

//		printf("parse tree at position: >>%s\n", pos->data + pos->pos);

		if (rrr_parse_match_word(pos, "IF")) {
//			printf("Found IF\n");
			struct rrr_array_node *node;
			if ((ret = __rrr_array_tree_parse_if_node(&node, pos)) != 0) {
				goto out_destroy;
			}
			RRR_LL_APPEND(tree, node);

//			printf("parse tree at position after IF: >>%s\n", pos->data + pos->pos);

			while (!RRR_PARSE_CHECK_EOF(pos)) {
				rrr_parse_ignore_spaces_and_increment_line(pos);
				if (RRR_PARSE_CHECK_EOF(pos)) {
					break;
				}

//				printf("Check elsif\n");
				if (rrr_parse_match_word(pos, "ELSIF")) {
					struct rrr_array_branch *branch_elsif;
					if ((ret = __rrr_array_tree_parse_if(&branch_elsif, pos)) != 0) {
						goto out_destroy;
					}
					RRR_LL_APPEND(&(RRR_LL_LAST(tree)->branch_if->branches_elsif), branch_elsif);
				}
				else {
					break;
				}
			}

//			printf("Check else\n");
			if (rrr_parse_match_word(pos, "ELSE")) {
				struct rrr_array_tree *tree_else;
				if ((ret = rrr_array_tree_parse(&tree_else, pos, NULL)) != 0) {
					goto out_destroy;
				}
				RRR_LL_LAST(tree)->branch_if->tree_else = tree_else;
			}
		}

		// Start array definition node
		struct rrr_array_node *node;
		if ((ret = __rrr_array_tree_parse_definition_node(&semicolon_found, &node, pos)) != 0) {
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
		ret = RRR_ARRAY_SOFT_ERROR;
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

static void __rrr_array_tree_dump (
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
		const struct rrr_array_branch *branch,
		int level
) {
	MAKE_TABS;

	printf("%sIF (", tabs);
	rrr_condition_dump(&branch->condition);
	printf(")\n");
	__rrr_array_tree_dump(branch->array_tree, level + 1);
	RRR_LL_ITERATE_BEGIN(&branch->branches_elsif, const struct rrr_array_branch);
		printf("\n%sELSIF (", tabs);
		rrr_condition_dump(&node->condition);
		printf(")\n");
		__rrr_array_tree_dump(node->array_tree, level + 1);
	RRR_LL_ITERATE_END();
	if (branch->tree_else != NULL) {
		printf("\n%sELSE\n", tabs);
		__rrr_array_tree_dump(branch->tree_else, level + 1);
	}
}

static void __rrr_array_definition_dump (
		const struct rrr_array *array,
		int level
) {
	MAKE_TABS;

	printf("%s", tabs);

	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (node != RRR_LL_FIRST(array)) {
			printf(",");
		}
		printf("%s", node->definition->identifier);
		if (node->definition->max_length > 0) {
			if (node->import_length_ref != NULL) {
				printf ("{%s}", node->import_length_ref);
			}
			else {
				printf ("%u", node->import_length);
			}
		}
		if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
			printf("s");
		}
		if (node->element_count_ref != NULL) {
			printf("@{%s}", node->element_count_ref);
		}
		else if (node->element_count > 1) {
			printf("@%u", node->element_count);
		}
		if (node->tag != NULL && *(node->tag) != '\0') {
			printf("#%s", node->tag);
		}
	RRR_LL_ITERATE_END();
}

static void __rrr_array_tree_dump (
		const struct rrr_array_tree *tree,
		int level
) {
	MAKE_TABS;

	RRR_LL_ITERATE_BEGIN(tree, const struct rrr_array_node);
		if (node != RRR_LL_FIRST(tree)) {
			printf(",\n");
		}
		if (node->branch_if != NULL) {
			__rrr_array_tree_branch_dump(node->branch_if, level);
		}
		else {
			__rrr_array_definition_dump(&node->array, level);
		}
	RRR_LL_ITERATE_END();
	printf("\n%s;", tabs);
}

void rrr_array_tree_dump (
		const struct rrr_array_tree *tree
) {
	printf ("## ARRAY TREE DUMP BEGIN #############################\n");
	__rrr_array_tree_dump(tree, 0);
	printf ("\n## ARRAY TREE DUMP END ###############################\n");
}

struct rrr_array_reference_node {
	RRR_LL_NODE(struct rrr_array_reference_node);
	const struct rrr_type_value *value;
};

struct rrr_array_reference {
	RRR_LL_HEAD(struct rrr_array_reference_node);
};

static int __rrr_array_reference_push (
		struct rrr_array_reference *reference,
		const struct rrr_type_value *value
) {
	struct rrr_array_reference_node *new_reference_value = malloc(sizeof(*new_reference_value));
	if (new_reference_value == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_array_reference_push\n");
		return 1;
	}

	memset(new_reference_value, '\0', sizeof(*new_reference_value));

	new_reference_value->value = value;

	RRR_LL_PUSH(reference, new_reference_value);

	return 0;
}

static void __rrr_array_reference_pop (
		struct rrr_array_reference *reference
) {
	struct rrr_array_reference_node *node = RRR_LL_POP(reference);
	if (node == NULL) {
		RRR_BUG("BUG: Tried to pop off empty array reference in __rrr_array_reference_pop\n");
	}
	free(node);
}

static void __rrr_array_reference_clear (
		struct rrr_array_reference *reference
) {
	RRR_LL_DESTROY(reference, struct rrr_array_reference_node, free(node));
}

static int __rrr_array_validate_definition_reference_check_tag (
		const struct rrr_array_reference *reference,
		const struct rrr_array_reference_node *self,
		const char *tag
) {
	RRR_LL_ITERATE_BEGIN(reference, const struct rrr_array_reference_node);
		if (node == self) {
			RRR_LL_ITERATE_BREAK();
		}
		if (node->value->tag != NULL) {
			if (strcmp(node->value->tag, tag) == 0) {
				return 0;
			}
		}
	RRR_LL_ITERATE_END();

	RRR_MSG_0("Could not resolve tag {%s}, no previous array value found with this name\n", tag);

	return 1;
}

static int __rrr_array_validate_definition_reference (
		const struct rrr_array_reference *reference
) {
	int ret = 0;

	struct rrr_array_reference_node *node = RRR_LL_LAST(reference);

	if (node == NULL) {
		goto out;
	}

	if (node->value->definition->max_length == 0 &&
		node->value->definition->type != RRR_TYPE_MSG &&
		node->value->definition->type != RRR_TYPE_STR &&
		node->value->definition->type != RRR_TYPE_NSEP
	) {
		RRR_MSG_0("Type %s has dynamic size and cannot be at the end of a definition\n",
				node->value->definition->identifier);
		ret = 1;
	}

	RRR_LL_ITERATE_BEGIN(reference, const struct rrr_array_reference_node);
		const struct rrr_type_value *value = node->value;

		if (value->element_count_ref != NULL) {
			ret |= __rrr_array_validate_definition_reference_check_tag(reference, node, value->element_count_ref);
		}
		if (value->import_length_ref != NULL) {
			ret |= __rrr_array_validate_definition_reference_check_tag(reference, node, value->import_length_ref);
		}

		const struct rrr_type_value *prev_value = (prev != NULL ? prev->value : NULL);

		if (prev_value != NULL) {
			if (prev_value->definition->max_length == 0 &&
				prev_value->definition->type != RRR_TYPE_STR &&
				prev_value->definition->type != RRR_TYPE_NSEP &&
				value->definition->max_length == 0 &&
				value->definition->type != RRR_TYPE_STR
			) {
				RRR_MSG_0("Type %s cannot be followed type %s in array definition as we cannot know where the first ends, use a separator in between\n",
						prev_value->definition->identifier, value->definition->identifier);
				ret = 1;
			}
			else if (prev_value->definition->type == RRR_TYPE_FIXP) {
				if ((RRR_TYPE_IS_BLOB(value->definition->type) ||
					RRR_TYPE_IS_MSG(value->definition->type) ||
					RRR_TYPE_IS_64(value->definition->type)) && (
							!RRR_TYPE_IS_SEP(value->definition->type) &&
							!RRR_TYPE_IS_STR(value->definition->type)
					)
				) {
					RRR_MSG_0("Fixed point type cannot be followed type %s (binary data) in array definition as we cannot know where the fixed point ends if the binary data corresponds with ASCII characters, use a separator in between\n",
							value->definition->identifier);
					ret = 1;
				}
			}
		}
		prev = node;
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_array_tree_validate (
		struct rrr_array_reference *reference,
		const struct rrr_array_tree *tree
);

static int __rrr_array_tree_branch_condition_validate_callback (
		const struct rrr_condition_op *op,
		const char *value,
		const char *tag,
		void *arg
) {
	const struct rrr_array_reference *reference = arg;

	(void)(value);
	(void)(op);

	if (tag == NULL) {
		return RRR_ARRAY_OK;
	}

	return __rrr_array_validate_definition_reference_check_tag(
			reference,
			NULL,
			tag
	);
}

static int __rrr_array_tree_branch_condition_validate (
		struct rrr_array_reference *reference,
		const struct rrr_condition *condition
) {
	return rrr_condition_iterate (
			condition,
			__rrr_array_tree_branch_condition_validate_callback,
			reference
	);
}

static int __rrr_array_tree_branch_validate (
		struct rrr_array_reference *reference,
		const struct rrr_array_branch *branch
) {
	int ret = 0;

	ret |= __rrr_array_tree_branch_condition_validate(reference, &branch->condition);
	ret |= __rrr_array_tree_validate(reference, branch->array_tree);

	RRR_LL_ITERATE_BEGIN(&branch->branches_elsif, const struct rrr_array_branch);
		ret |= __rrr_array_tree_branch_condition_validate(reference, &node->condition);
		ret |= __rrr_array_tree_validate(reference, node->array_tree);
	RRR_LL_ITERATE_END();

	if (branch->tree_else != NULL) {
		ret |= __rrr_array_tree_validate(reference, branch->tree_else);
	}

	return ret;
}

static int __rrr_array_tree_validate (
		struct rrr_array_reference *reference,
		const struct rrr_array_tree *tree
) {
	int ret = 0;

	int ref_length_orig = RRR_LL_COUNT(reference);

	RRR_LL_ITERATE_BEGIN(tree, const struct rrr_array_node);
		const struct rrr_array *array = &node->array;
		RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
			if (__rrr_array_reference_push(reference, node) != 0) {
				ret = RRR_ARRAY_HARD_ERROR;
				goto out;
			}
		RRR_LL_ITERATE_END();

		if (node->branch_if != NULL) {
			ret |= __rrr_array_tree_branch_validate(reference, node->branch_if);
		}
		else if (RRR_LL_LAST(tree) == node) {
			ret |= __rrr_array_validate_definition_reference(reference);
		}
/*			if (rrr_array_count(&node->array) == 0) {
				RRR_MSG_0("An array definition was empty in array tree\n");
				ret |= 1;
			}*/

	RRR_LL_ITERATE_END();

	while (RRR_LL_COUNT(reference) > ref_length_orig) {
		__rrr_array_reference_pop(reference);
	}

	out:
	return ret;
}

int rrr_array_tree_validate (
		const struct rrr_array_tree *tree
) {
	int ret = 0;

	struct rrr_array_reference reference = {0};

	ret = __rrr_array_tree_validate(&reference, tree);

	__rrr_array_reference_clear(&reference);
	return ret;
}

int rrr_array_tree_get_packed_length_from_buffer (
		ssize_t *import_length,
		const struct rrr_array_tree *tree,
		const char *buf,
		ssize_t buf_length
) {
	int ret = RRR_TYPE_PARSE_OK;

	*import_length = 0;

	RRR_LL_ITERATE_BEGIN(tree, struct rrr_array_node);
		ssize_t import_length_tmp = 0;
		if (node->branch_if != NULL) {

		}
		else {

		}
	RRR_LL_ITERATE_END();

	return ret;
}
