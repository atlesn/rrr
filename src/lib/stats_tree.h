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

#ifndef RRR_STATS_TREE_H
#define RRR_STATS_TREE_H

#include <stdint.h>

#include "linked_list.h"
#include "stats_message.h"

#define RRR_STATS_TREE_OK			0
#define RRR_STATS_TREE_HARD_ERROR	1
#define RRR_STATS_TREE_SOFT_ERROR	2

struct rrr_stats_tree_branch {
	RRR_LL_NODE(struct rrr_stats_tree_branch);
	RRR_LL_HEAD(struct rrr_stats_tree_branch);
	struct rrr_stats_message *value;
	char *name;
	uint64_t last_seen;
};

struct rrr_stats_tree {
	struct rrr_stats_tree_branch *first_branch;
};

int rrr_stats_tree_init (struct rrr_stats_tree *tree);
void rrr_stats_tree_clear (struct rrr_stats_tree *tree);
int rrr_stats_tree_insert_or_update (struct rrr_stats_tree *tree, const struct rrr_stats_message *message);
int rrr_stats_tree_has_leaf (struct rrr_stats_tree *tree, const char *path_postfix);
void rrr_stats_tree_dump (struct rrr_stats_tree *tree);
void rrr_stats_tree_purge_old_branches (unsigned int *purged_total, struct rrr_stats_tree *tree, uint64_t min_time);

#endif /* RRR_STATS_TREE_H */
