/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TEST_RAFT_H
#define RRR_TEST_RAFT_H

#include <stdio.h>

#include "test.h"
#include "test_raft.h"
#include "../lib/raft/rrr_raft.h"

static volatile int rrr_test_raft_pong_received;

static void __rrr_test_raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	(void)(arg);

	TEST_MSG("Pong received\n");

	rrr_test_raft_pong_received = 1;
}

int rrr_test_raft (
		const volatile int *main_running,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue
) {
	int ret = 0;

	struct rrr_raft_channel *channel;

	if ((ret = rrr_raft_fork (
			&channel,
			fork_handler,
			queue,
			"test",
			__rrr_test_raft_pong_callback,
			NULL
	)) != 0) {
		TEST_MSG("Failed to fork out raft process\n");
		ret = 1;
		goto out;
	}

	if (!rrr_test_raft_pong_received) {
		TEST_MSG("No pong message received from fork\n");
		ret = 1;
	}

	goto out_cleanup;
	out_cleanup:
		rrr_raft_cleanup(channel);
	out:
		return ret;
}

#endif /* RRR_TEST_RAFT_H */
