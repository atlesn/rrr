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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "btree.h"
#include "../global.h"

int rrr_btree_new (struct rrr_btree **target, void (*destroy_function)(void *)) {
	int ret = 0;

	*target = NULL;

	struct rrr_btree *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_btree_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));
	result->destroy_function = destroy_function;

	*target = result;

	out:
	return ret;
}

static void __rrr_btree_clear_leaf (struct rrr_btree *btree, struct rrr_btree_leaf *leaf) {
	if (leaf->data != NULL && btree->destroy_function != NULL) {
		btree->destroy_function(leaf->data);
	}
	memset(leaf, '\0', sizeof(*leaf));
}

static void __rrr_btree_clear_branch (struct rrr_btree *btree, struct rrr_btree_branch *branch) {
	for (int i = 0; i < RRR_BTREE_LEAF_MAX; i++) {
		__rrr_btree_clear_leaf(btree, &branch->leaves[i]);
	}

	for (int i = 0; i < RRR_BTREE_LEAF_MAX + 1; i++) {
		if (branch->branches[i] != NULL) {
			__rrr_btree_clear_branch(btree, branch->branches[i]);
			free(branch->branches[i]);
		}
	}
}

void rrr_btree_destroy (struct rrr_btree *btree) {
	__rrr_btree_clear_branch (btree, &btree->trunk);
}

static void __rrr_btree_leaf_populate (struct rrr_btree_leaf *leaf, uint64_t key, void *value) {
	leaf->used = 1;
	leaf->key = key;
	leaf->data = value;
}

static struct rrr_btree_branch *__rrr_btree_branch_create (uint64_t key, void *value) {
	struct rrr_btree_branch *result = malloc(sizeof(*result));

	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_btree_branch_create\n");
		return NULL;
	}

	memset(result, '\0', sizeof(*result));

	__rrr_btree_leaf_populate(&result->leaves[0], key, value);

	return result;
}

static void __rrr_btree_branch_shift_right (struct rrr_btree_branch *branch, struct rrr_btree_leaf *stop) {
	if (branch->leaves[RRR_BTREE_LEAF_MAX - 1].used != 0) {
		return;
	}

	for (int i = RRR_BTREE_LEAF_MAX - 1; i--; i >= 0) {
		if (&branch->leaves[i - 1] == stop) {
			return;
		}
		memcpy(&branch->leaves[i], &branch->leaves[i - 1], sizeof(struct rrr_btree_leaf));
		memset(&branch->leaves[i - 1], '\0', sizeof(struct rrr_btree_leaf));
	}
}

static int __rrr_btree_branch_insert (struct rrr_btree_branch *parent, struct rrr_btree_branch *branch, uint64_t key, void *value) {
	for (int i = 0; i < RRR_BTREE_LEAF_MAX; i++) {
		struct rrr_btree_leaf *leaf = &branch->leaves[i];

		if (i == RRR_BTREE_LEAF_MAX - 1) {
			if (leaf->used == 0) {
				__rrr_btree_leaf_populate(leaf, key, value);
				return 0;
			}

			if (branch->branches[i + 1] == NULL) {
				if ((branch->branches[i + 1] = __rrr_btree_branch_create (key, value)) == NULL) {
					return 1;
				}
				return 0;
			}

			return __rrr_btree_branch_insert(parent, branch->branches[i + 1], key, value);
		}

		struct rrr_btree_leaf *next_leaf = &branch->leaves[i + 1];
		if (leaf->used == 0) {
			__rrr_btree_leaf_populate(leaf, key, value);
			return 0;
		}

		if (key <= leaf->key) {
			if (branch->branches[i] != NULL) {
				return __rrr_btree_branch_insert(branch, branch->branches[i], key, value);
			}

			__rrr_btree_branch_shift_right(branch, leaf);

			if (leaf->used == 0) {
				__rrr_btree_leaf_populate(leaf, key, value);
				return 0;
			}

			
		}
	}
}

int rrr_btree_insert (struct rrr_btree *btree, uint64_t key, void *value) {

}
