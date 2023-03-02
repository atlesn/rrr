
/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "test.h"
#include "test_linked_list.h"
#include "../lib/util/linked_list.h"
#include "../lib/log.h"

struct test_node {
	RRR_LL_NODE(struct test_node);
};

struct test_head {
	RRR_LL_HEAD(struct test_node);
};

int check(struct test_head *head, struct test_node **nodes, int count) {
	int ret = 0;

	assert(count == RRR_LL_COUNT(head));

	RRR_LL_VERIFY_HEAD(head);

	int i = 0;
	RRR_LL_ITERATE_BEGIN(head, struct test_node);
		RRR_LL_VERIFY_NODE(head);

		if (node != nodes[i]) {
			TEST_MSG("- Mismatch at position %i\n", i);
			ret = 1;
		}
		if (++i == count) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_test_linked_list(void) {
	int ret = 0;

	struct test_node *node_ptrs[6];
	struct test_node nodes[6];
	struct test_head head = {0};
	memset(nodes, 0, sizeof(nodes));

	TEST_MSG("Checking empty...\n");
	if (!RRR_LL_IS_EMPTY(&head)) {
		TEST_MSG("- Failed, not reported as empty\n");
		ret = 1;
	}

	TEST_MSG("Checking append...\n");
	RRR_LL_APPEND(&head, &nodes[0]);
	RRR_LL_APPEND(&head, &nodes[1]);
	RRR_LL_APPEND(&head, &nodes[2]);
	RRR_LL_APPEND(&head, &nodes[3]);
	RRR_LL_APPEND(&head, &nodes[4]);
	RRR_LL_APPEND(&head, &nodes[5]);

	node_ptrs[0] = &nodes[0];
	node_ptrs[1] = &nodes[1];
	node_ptrs[2] = &nodes[2];
	node_ptrs[3] = &nodes[3];
	node_ptrs[4] = &nodes[4];
	node_ptrs[5] = &nodes[5];

	ret |= check(&head, node_ptrs, 6);

	// Pop off last node
	TEST_MSG("Checking pop...\n");
	{
		struct test_node *pop = RRR_LL_POP(&head);
		if (pop != &nodes[5] || RRR_LL_COUNT(&head) != 5) {
			TEST_MSG("- Wrong or no node popped\n");
			ret = 1;
		}
		ret |= check(&head, node_ptrs, 5);
	}

	// Place last node at the beginning
	TEST_MSG("Checking unshift...\n");
	RRR_LL_UNSHIFT(&head, &nodes[5]);

	node_ptrs[0] = &nodes[5];
	node_ptrs[1] = &nodes[0];
	node_ptrs[2] = &nodes[1];
	node_ptrs[3] = &nodes[2];
	node_ptrs[4] = &nodes[3];
	node_ptrs[5] = &nodes[4];

	ret |= check(&head, node_ptrs, 6);

	// Rotate so that last node comes last again
	TEST_MSG("Checking rotate...\n");
	RRR_LL_ROTATE(&head, struct test_node, 1);

	node_ptrs[0] = &nodes[0];
	node_ptrs[1] = &nodes[1];
	node_ptrs[2] = &nodes[2];
	node_ptrs[3] = &nodes[3];
	node_ptrs[4] = &nodes[4];
	node_ptrs[5] = &nodes[5];

	ret |= check(&head, node_ptrs, 6);

	return ret;
}

