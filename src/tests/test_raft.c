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
#include "../lib/rrr_strerror.h"
#include "../lib/event/event.h"
#include "../lib/raft/rrr_raft.h"
#include "../lib/socket/rrr_socket.h"

struct rrr_test_raft_callback_data {
	int rrr_test_raft_pong_received;
	const volatile int *main_running;
};

static void __rrr_test_raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	TEST_MSG("Pong received\n");

	callback_data->rrr_test_raft_pong_received = 1;
}

static int __rrr_test_raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	TEST_MSG("Periodic\n");

	if (callback_data->rrr_test_raft_pong_received) {
		return RRR_EVENT_EXIT;
	}

	if (!*(callback_data->main_running)) {
		return RRR_EVENT_ERR;
	}

	return RRR_EVENT_OK;
}

int rrr_test_raft (
		const volatile int *main_running,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue
) {
	int ret = 0;

	struct rrr_raft_channel *channel;
	rrr_event_receiver_handle queue_handle;
	int socketpair[2];

	struct rrr_test_raft_callback_data callback_data = {0};

	callback_data.main_running = main_running;

	if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, "raft", socketpair)) != 0) {
		RRR_MSG_0("Failed to create sockets in %s: %s\n",
			rrr_strerror(errno));
		goto out;
	}

	if ((ret = rrr_raft_fork (
			&channel,
			fork_handler,
			queue,
			"test",
			socketpair,
			__rrr_test_raft_pong_callback,
			&callback_data
	)) != 0) {
		TEST_MSG("Failed to fork out raft process\n");
		ret = 1;
		goto out_close;
	}

	if ((ret = rrr_event_receiver_new (
			&queue_handle,
			queue,
			"raft test",
			&callback_data
	)) != 0) {
		goto out_cleanup;
	}

	if ((ret = rrr_event_function_periodic_set_and_dispatch (
			queue,
			queue_handle,
			250 * 1000, // 250 ms
			__rrr_test_raft_periodic
	)) != 0) {
		goto out_cleanup;
	}

	if (rrr_event_dispatch(queue) != RRR_EVENT_OK) {
		ret = 1;
		goto out_cleanup;
	}

	if (!callback_data.rrr_test_raft_pong_received) {
		TEST_MSG("No pong message received from fork\n");
		ret = 1;
	}

	goto out_cleanup;
	out_cleanup:
		rrr_raft_cleanup(channel);
	out_close:
		if (socketpair[0] > 0)
			rrr_socket_close(socketpair[0]);
		if (socketpair[1] > 0)
			rrr_socket_close(socketpair[1]);
	out:
		return ret;
}

#endif /* RRR_TEST_RAFT_H */
