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

#include <stdio.h>

#include "array.h"
#include "util/linked_list.h"
#include "type.h"
#include "condition.h"
#include "read_constants.h"

struct rrr_array_branch;
struct rrr_array_node;

struct rrr_array_branch_collection {
	RRR_LL_HEAD(struct rrr_array_branch);
};

struct rrr_array_branch {
	RRR_LL_NODE(struct rrr_array_branch);
	struct rrr_condition condition;
	struct rrr_array_tree *array_tree;
	struct rrr_array_branch_collection branches_elsif;
	struct rrr_array_tree *tree_else;
};

struct rrr_array_node {
	RRR_LL_NODE(struct rrr_array_node);
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

void rrr_array_tree_destroy (
		struct rrr_array_tree *tree
);
void rrr_array_tree_list_destroy (
		struct rrr_array_tree_list *list
);
int rrr_array_tree_parse (
		struct rrr_array_tree **target,
		struct rrr_parse_pos *pos,
		const char *name
);
void rrr_array_tree_dump (
		const struct rrr_array_tree *tree
);
int rrr_array_tree_validate (
		const struct rrr_array_tree *tree
);

#endif /* RRR_ARRAY_TREE_H */
