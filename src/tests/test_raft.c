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

#define RRR_TEST_RAFT_SERVER_COUNT 3

static const char request_1[] = "Request number 1 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
static const char dir_base[] = "/tmp/rrr-test-raft";

struct rrr_test_raft_callback_data {
	struct rrr_raft_channel **channels;
	int rrr_test_raft_pong_received;
	const volatile int *main_running;
	unsigned int cmd_pos;
	unsigned int msg_pos;
	uint32_t req_index[RRR_TEST_RAFT_SERVER_COUNT];
	uint32_t ack_index[RRR_TEST_RAFT_SERVER_COUNT];
};

static void __rrr_test_raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	if (!callback_data->rrr_test_raft_pong_received) {
		TEST_MSG("Pong received server %i\n", server_id);
		callback_data->rrr_test_raft_pong_received = 1;
	}
}

static void __rrr_test_raft_ack_callback (RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_COUNT);

	uint32_t cb_req_index = callback_data->req_index[server_id - 1];
	uint32_t cb_ack_index = callback_data->ack_index[server_id - 1];

	assert(req_index <= cb_req_index);
	assert(req_index > cb_ack_index);

	TEST_MSG("%s %u received server %i (prev was %u)\n",
		(ok ? "ACK" : "NACK"), req_index, server_id, cb_ack_index);

	callback_data->ack_index[server_id - 1] = req_index;
}

static int __rrr_test_raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	char topic[16];

	TEST_MSG("Periodic step %i\n", callback_data->cmd_pos);

	if (callback_data->cmd_pos++ % 10 == 0) {
		for (int i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
			sprintf(topic, "topic/%c", '0' + (callback_data->msg_pos++) % 10);

			// TODO : Send only leader
			// TODO : Check return value
			rrr_raft_client_request_put (
					&callback_data->req_index[i],
					callback_data->channels[i],
					topic,
					request_1,
					sizeof(request_1)
			);
		}
	}
/*
	if (ret_tmp != 0) {
		TEST_MSG("A periodic command failed with error %i\n", ret_tmp);
		return RRR_EVENT_ERR;
	}
*/
	// TODO : Figure out correct end condition
	if (callback_data->rrr_test_raft_pong_received && 0) {
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

	struct rrr_raft_channel *channels[3] = {0};
	struct rrr_test_raft_callback_data callback_data = {0};
	rrr_event_receiver_handle queue_handle;
	int socketpair[2];
	char dir[sizeof(dir_base) + 32];

	callback_data.main_running = main_running;
	callback_data.channels = channels;

	for (int i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
		if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, "raft", socketpair)) != 0) {
			RRR_MSG_0("Failed to create sockets in %s: %s\n",
				rrr_strerror(errno));
			goto out_cleanup;
		}

		sprintf(dir, "%s/%d", dir_base, i + 1);

		if ((ret = rrr_raft_fork (
				&channels[i],
				fork_handler,
				queue,
				"test",
				socketpair,
				i + 1, /* server id */
				dir,
				__rrr_test_raft_pong_callback,
				__rrr_test_raft_ack_callback,
				&callback_data
		)) != 0) {
			TEST_MSG("Failed to fork out raft process\n");
			ret = 1;
			goto out_cleanup;
		}

		socketpair[0] = -1;
		socketpair[1] = -1;
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

	if (callback_data.req_index != callback_data.ack_index) {
		TEST_MSG("Mismatch between req and ack indexes\n");
		ret = 1;
	}

	out_cleanup:
	for (int i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
		if (channels[i] != NULL) {
			rrr_raft_cleanup(channels[i]);
		}
	}
	if (socketpair[0] > 0)
		rrr_socket_close(socketpair[0]);
	if (socketpair[1] > 0)
		rrr_socket_close(socketpair[1]);
	return ret;
}

#endif /* RRR_TEST_RAFT_H */
