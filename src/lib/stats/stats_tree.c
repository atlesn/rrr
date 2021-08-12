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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "stats_tree.h"
#include "stats_message.h"

#include "../util/rrr_time.h"
#include "../util/macro_utils.h"

static int __rrr_stats_tree_branch_new (
		struct rrr_stats_tree_branch **target,
		const char *name
) {
	int ret = 0;

	*target = NULL;

	struct rrr_stats_tree_branch *result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_tree_branch_new A\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->name = rrr_strdup(name);
	if (name == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_tree_branch_new B\n");
		ret = 1;
		goto out_free_result;
	}

	result->last_seen = rrr_time_get_64();

	*target = result;
	goto out;

//	out_free_name:
//		free(result->name);
	out_free_result:
		rrr_free(result);
	out:
		return ret;
}

static int __rrr_stats_tree_branch_destroy (struct rrr_stats_tree_branch *branch) {
	RRR_LL_DESTROY(branch, struct rrr_stats_tree_branch, __rrr_stats_tree_branch_destroy(node));
	if (branch->value != NULL) {
		rrr_msg_stats_destroy(branch->value);
	}
	RRR_FREE_IF_NOT_NULL(branch->name);
	rrr_free(branch);
	return 0;
}

int rrr_stats_tree_init (struct rrr_stats_tree *tree) {
	memset(tree, '\0', sizeof(*tree));
	return __rrr_stats_tree_branch_new(&tree->first_branch, "rrr");
}

void rrr_stats_tree_clear (struct rrr_stats_tree *tree) {
	__rrr_stats_tree_branch_destroy(tree->first_branch);
}

// This function is supposed to be robust and must handle any \0-terminated input. If no
// path can be extracted from the input, first_level[0] is set to '\0' and *next_level
// points to the end of the original string. All preceding /'s are lost, the first characters
// in the input which are not /'s are considered the first level and are returned.
static void __rrr_stats_get_first_path_level (
		char first_level[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1],
		const char **next_level,
		const char *path
) {
	const char *max = path + strlen(path);
	const char *begin = path;
	const char *end = path;

	first_level[0] = '\0';
	*next_level = max;

	while (begin < max) {
		end = strchr(begin, '/');
		if (end == NULL) {
			strcpy(first_level, begin);
			return;
		}
		if (end - begin > 0) {
			break;
		}
		begin++;
	}

	if (end - begin <= 0) {
		*next_level = max;
		return;
	}

	strncpy(first_level, begin, rrr_length_from_ptr_sub_bug_const (end, begin));
	first_level[end - begin] = '\0';

	if (end >= max) {
		*next_level = max;
	}
	else {
		*next_level = end;
	}
}

static int __rrr_stats_tree_insert_or_update_branch (
		struct rrr_stats_tree_branch *branch,
		const char *path_position,
		const struct rrr_msg_stats *value
) {
	branch->last_seen = rrr_time_get_64();

	// Last level (leaf)?
	if (strlen(path_position) == 0) {
		struct rrr_msg_stats *new_value;
		if (rrr_msg_stats_duplicate(&new_value, value) != 0) {
			RRR_MSG_0("Could not duplicate message in __rrr_stats_tree_insert_or_update_branch n");
			return RRR_STATS_TREE_HARD_ERROR;
		}
		if (branch->value != NULL) {
			rrr_msg_stats_destroy(branch->value);
		}
		branch->value = new_value;

		return RRR_STATS_TREE_OK;
	}

	char path_tmp[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1];
	__rrr_stats_get_first_path_level(path_tmp, &path_position, path_position);

	if (strlen(path_tmp) == 0) {
		RRR_MSG_0("Invalid path '%s' in message\n", value->path);
		return RRR_STATS_TREE_SOFT_ERROR;
	}

	RRR_LL_ITERATE_BEGIN(branch, struct rrr_stats_tree_branch);
		if (strcmp(node->name, path_tmp) == 0) {
			return __rrr_stats_tree_insert_or_update_branch(node, path_position, value);
		}
	RRR_LL_ITERATE_END();

	struct rrr_stats_tree_branch *new_branch;
	if (__rrr_stats_tree_branch_new(&new_branch, path_tmp) != 0) {
		RRR_MSG_0("Could not create new branch in __rrr_stats_tree_insert_or_update_branch \n");
		return RRR_STATS_TREE_HARD_ERROR;
	}
	RRR_LL_APPEND(branch, new_branch);

	return __rrr_stats_tree_insert_or_update_branch(new_branch, path_position, value);
}

int rrr_stats_tree_insert_or_update (struct rrr_stats_tree *tree, const struct rrr_msg_stats *message) {
	if (strlen (message->path) < 2) {
		RRR_MSG_0("Path of message was too short in rrr_stats_tree_insert_or_update (value was '%s')", message->path);
		return RRR_STATS_TREE_SOFT_ERROR;
	}

	return __rrr_stats_tree_insert_or_update_branch(tree->first_branch, message->path, message);
}

static int __rrr_stats_branch_has_leaf (struct rrr_stats_tree_branch *branch, const char *path_postfix) {
	if (RRR_LL_COUNT(branch) == 0) {
		if (strcmp(branch->name, path_postfix) == 0) {
			return 1;
		}
	}
	else {
		RRR_LL_ITERATE_BEGIN(branch, struct rrr_stats_tree_branch);
			if (__rrr_stats_branch_has_leaf(node, path_postfix)) {
				return 1;
			}
		RRR_LL_ITERATE_END();
	}

	return 0;
}

int rrr_stats_tree_has_leaf (struct rrr_stats_tree *tree, const char *path_postfix) {
	return __rrr_stats_branch_has_leaf(tree->first_branch, path_postfix);
}

static void __rrr_stats_tree_branch_dump (struct rrr_stats_tree_branch *branch, const char *path_prefix) {
	char path_tmp[RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1];

//	printf("Branch: %s/%s\n", path_prefix, branch->name);
	if (branch->value != NULL) {
		if (	branch->value->type == RRR_STATS_MESSAGE_TYPE_TEXT ||
				branch->value->type == RRR_STATS_MESSAGE_TYPE_BASE10_TEXT ||
				branch->value->type == RRR_STATS_MESSAGE_TYPE_DOUBLE_TEXT
		) {
			printf ("-- %s/%s: %s\n", path_prefix, branch->name, branch->value->data);
		}
		else {
			printf ("-- %s/%s (not text): %s\n", path_prefix, branch->name, branch->value->path);
		}
	}

	if (snprintf(path_tmp, RRR_STATS_MESSAGE_PATH_MAX_LENGTH, "%s/%s", path_prefix, branch->name) >= RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		strcpy(path_tmp, path_prefix);
		printf ("Note: Path name too long in branch %s, not descending further\n", branch->name);
		printf ("%i children not printed\n", RRR_LL_COUNT(branch));
	}
	else {
		RRR_LL_ITERATE_BEGIN(branch, struct rrr_stats_tree_branch);
			__rrr_stats_tree_branch_dump(node, path_tmp);
		RRR_LL_ITERATE_END();
	}
}

void rrr_stats_tree_dump (struct rrr_stats_tree *tree) {
	__rrr_stats_tree_branch_dump(tree->first_branch, "");
}

static void __rrr_stats_tree_branch_purge_old_branches (unsigned int *purged_total, struct rrr_stats_tree_branch *branch, uint64_t min_time) {
	RRR_LL_ITERATE_BEGIN(branch, struct rrr_stats_tree_branch);
		if (node->last_seen < min_time) {
			RRR_LL_ITERATE_SET_DESTROY();
			(*purged_total)++;
		}
		else {
			__rrr_stats_tree_branch_purge_old_branches(purged_total, node, min_time);
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(branch, __rrr_stats_tree_branch_destroy(node));
}

void rrr_stats_tree_purge_old_branches (unsigned int *purged_total, struct rrr_stats_tree *tree, uint64_t min_time) {
	*purged_total = 0;

	RRR_LL_ITERATE_BEGIN(tree->first_branch, struct rrr_stats_tree_branch);
		if (node->last_seen < min_time) {
			RRR_LL_ITERATE_SET_DESTROY();
			(*purged_total)++;
		}
		else {
			__rrr_stats_tree_branch_purge_old_branches(purged_total, node, min_time);
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(tree->first_branch, __rrr_stats_tree_branch_destroy(node));
}
