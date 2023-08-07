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

#ifndef RRR_ARRAY_TREE_H
#define RRR_ARRAY_TREE_H

#include "array.h"
#include "util/linked_list.h"
#include "type.h"
#include "condition.h"
#include "read_constants.h"

#define RRR_ARRAY_TREE_OK                RRR_READ_OK
#define RRR_ARRAY_TREE_HARD_ERROR        RRR_READ_HARD_ERROR
#define RRR_ARRAY_TREE_SOFT_ERROR        RRR_READ_SOFT_ERROR
#define RRR_ARRAY_TREE_PARSE_INCOMPLETE  RRR_READ_INCOMPLETE
#define RRR_ARRAY_TREE_CONDITION_FALSE   RRR_READ_EOF
#define RRR_ARRAY_TREE_CONDITION_TRUE    RRR_READ_OK
#define RRR_ARRAY_TREE_CONTINUE          RRR_READ_CONTINUE

struct rrr_array_branch;
struct rrr_array_node;

struct rrr_array_branch_collection {
	RRR_LL_HEAD(struct rrr_array_branch);
};

struct rrr_array_branch {
	RRR_LL_NODE(struct rrr_array_branch);
	int branch_id;
	struct rrr_condition condition;
	struct rrr_array_tree *array_tree;
	struct rrr_array_branch_collection branches_elsif;
	struct rrr_array_tree *tree_else;
};

struct rrr_array_node {
	RRR_LL_NODE(struct rrr_array_node);
	rrr_length rewind_count;
	struct rrr_array array;
	struct rrr_array_branch *branch_if;
};

struct rrr_array_tree {
	RRR_LL_HEAD(struct rrr_array_node);
	RRR_LL_NODE(struct rrr_array_tree);
	char *name;
};

struct rrr_array_tree_list {
	RRR_LL_HEAD(struct rrr_array_tree);
};

void rrr_array_tree_clear (
		struct rrr_array_tree *tree
);
void rrr_array_tree_destroy (
		struct rrr_array_tree *tree
);
int rrr_array_tree_new (
		struct rrr_array_tree **target,
		const char *name
);
void rrr_array_tree_list_clear (
		struct rrr_array_tree_list *list
);
const struct rrr_array_tree *rrr_array_tree_list_get_tree_by_name (
		const struct rrr_array_tree_list *list,
		const char *name
);
int rrr_array_tree_interpret (
		struct rrr_array_tree **target,
		struct rrr_parse_pos *pos,
		const char *name
);
int rrr_array_tree_interpret_raw (
		struct rrr_array_tree **target,
		const char *data,
		rrr_length data_length,
		const char *name
);
void rrr_array_tree_dump (
		const struct rrr_array_tree *tree
);
int rrr_array_tree_get_import_length_from_buffer (
		struct rrr_array *final_array,
		rrr_length *import_length,
		const struct rrr_array_tree *tree,
		const char *buf,
		rrr_length buf_length
);
int rrr_array_tree_clone_without_data (
		struct rrr_array_tree **target,
		const struct rrr_array_tree *source
);
int rrr_array_tree_import_from_buffer (
		rrr_length *parsed_bytes,
		const char *buf,
		rrr_length buf_len,
		const struct rrr_array_tree *tree,
		int (*callback)(struct rrr_array *array, void *arg),
		void *callback_arg
);

#endif /* RRR_ARRAY_TREE_H */
