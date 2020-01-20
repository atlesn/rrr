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

#ifndef RRR_BTREE_H
#define RRR_BTREE_H

#include <stdint.h>

#define RRR_BTREE_LEAF_MAX 10

struct rrr_btree_leaf {
	unsigned short int used;
	uint64_t key;
	void *data;
};

struct rrr_btree_branch {
	struct rrr_btree_leaf leaves[RRR_BTREE_LEAF_MAX];
	struct rrr_btree_branch *branches[RRR_BTREE_LEAF_MAX + 1];
};

struct rrr_btree {
	struct rrr_btree_branch trunk;
	void (*destroy_function)(void *);
};

int rrr_btree_new (struct rrr_btree **target, void (*destroy_function)(void *));

#endif
