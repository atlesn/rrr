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
#include "../lib/messages/msg_msg_struct.h"

#define RRR_TEST_RAFT_SERVER_COUNT 3
#define RRR_TEST_RAFT_IN_FLIGHT_MAX 64

static const struct rrr_raft_server servers[RRR_TEST_RAFT_SERVER_COUNT + 1] = {
	{.id = 1, .address = "127.0.0.1:9001"},
	{.id = 2, .address = "127.0.0.1:9002"},
	{.id = 3, .address = "127.0.0.1:9003"},
	{.id = 0, .address = ""}
};

static const char *requests[] = {
	"Request 0",
	"Request 1",
	"Request 2",
	"Request 3",
	"Request 4",
	"Request 5",
	"Request 6",
	"Request 7",
	"Request 8",
	"Request 9"
};

static const char dir_base[] = "/tmp/rrr-test-raft";

struct rrr_test_raft_callback_data {
	struct rrr_raft_channel **channels;
	int rrr_test_raft_pong_received;
	const volatile int *main_running;
	unsigned int cmd_pos;
	unsigned int msg_pos;
	uint32_t ack_expected[RRR_TEST_RAFT_SERVER_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	uint32_t nack_expected[RRR_TEST_RAFT_SERVER_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	uint32_t msg_expected[RRR_TEST_RAFT_SERVER_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	int leader_index;
	int all_ok;
};

static void __rrr_test_raft_register_expected (
		uint32_t *array,
		uint32_t req_index
) {
	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i] == 0) {
			array[i] = req_index;
			return;
		}
	}

	RRR_BUG("BUG: In flight max reached in %s\n", __func__);
}

static void __rrr_test_raft_register_expected_ack (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		int ok
) {
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_COUNT);
	__rrr_test_raft_register_expected((ok ? callback_data->ack_expected : callback_data->nack_expected)[server_id - 1], req_index);
}

static void __rrr_test_raft_register_expected_msg (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index
) {
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_COUNT);
	__rrr_test_raft_register_expected(callback_data->msg_expected[server_id - 1], req_index);
}

static void __rrr_test_raft_register_response (
		uint32_t *array,
		uint32_t req_index
) {
	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i] == req_index) {
			array[i] = 0;
			return;
		}
	}

	RRR_BUG("BUG: Expected response not found in %s\n", __func__);
}

static void __rrr_test_raft_register_response_ack (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		int ok
) {
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_COUNT);
	__rrr_test_raft_register_response((ok ? callback_data->ack_expected : callback_data->nack_expected)[server_id - 1], req_index);
}

static void __rrr_test_raft_register_response_msg (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index
) {
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_COUNT);
	__rrr_test_raft_register_response(callback_data->msg_expected[server_id - 1], req_index);
}

static int __rrr_test_raft_check_zero (
		uint8_t *data,
		size_t data_len
) {
	if (*data != 0)
		return 0;
	return 0 == memcmp(data, data + 1, data_len - 1);
}

static int __rrr_test_raft_check_all_ack_received (
		struct rrr_test_raft_callback_data *callback_data
) {
	return __rrr_test_raft_check_zero((uint8_t *) callback_data->ack_expected, sizeof(callback_data->ack_expected)) &&
	       __rrr_test_raft_check_zero((uint8_t *) callback_data->nack_expected, sizeof(callback_data->ack_expected)) &&
	       __rrr_test_raft_check_zero((uint8_t *) callback_data->msg_expected, sizeof(callback_data->ack_expected));
}

static void __rrr_test_raft_pong_callback (RRR_RAFT_CLIENT_PONG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	if (!callback_data->rrr_test_raft_pong_received) {
		TEST_MSG("Pong received server %i\n", server_id);
		callback_data->rrr_test_raft_pong_received = 1;
	}
}

static void __rrr_test_raft_ack_callback (RRR_RAFT_CLIENT_ACK_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	TEST_MSG("%s %u received server %i\n",
		(ok ? "ACK" : "NACK"), req_index, server_id);

	__rrr_test_raft_register_response_ack(callback_data, server_id, req_index, ok);
}

static void __rrr_test_raft_opt_callback (RRR_RAFT_CLIENT_OPT_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	int leader_index;

	TEST_MSG("OPT %u received server %i is leader: %" PRIu64 "\n",
		req_index, server_id, is_leader);

	if (is_leader) {
		leader_index = callback_data->leader_index = server_id - 1;
		assert(leader_index >= 0 && leader_index < RRR_TEST_RAFT_SERVER_COUNT);
	}

	__rrr_test_raft_register_response_msg(callback_data, server_id, req_index);
}

static void __rrr_test_raft_msg_callback (RRR_RAFT_CLIENT_MSG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	const char *topic_ptr;
	int msg_pos;

	TEST_MSG("MSG %u received server %i\n",
		req_index, server_id);

	assert(MSG_TOPIC_LENGTH(*msg) == strlen("topic/x"));
	topic_ptr = MSG_TOPIC_PTR(*msg);
	assert(strncmp(MSG_TOPIC_PTR(*msg), "topic/", strlen("topic/")) == 0);
	topic_ptr += strlen("topic/");
	assert(*topic_ptr >= '0' && *topic_ptr <= '9');
	msg_pos = *topic_ptr - '0';

	assert(MSG_DATA_LENGTH(*msg) == strlen(requests[msg_pos]));

	if (memcmp(requests[msg_pos], MSG_DATA_PTR(*msg), MSG_DATA_LENGTH(*msg)) != 0) {
		RRR_BUG("BUG: Unexpected responses '%.*s' (expected '%s')\n",
			MSG_DATA_LENGTH(*msg), MSG_DATA_PTR(*msg), requests[msg_pos]);
	}

	__rrr_test_raft_register_response_msg(callback_data, server_id, req_index);
}

static int __rrr_test_raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	char topic[16];
	int i;
	unsigned int msg_pos;
	uint32_t req_index;

	TEST_MSG("Periodic step %i\n", callback_data->cmd_pos);

	switch (callback_data->cmd_pos++) {
		case 0: {
			if (callback_data->leader_index >= 0) {
				// OK, async OPT response detected a leader
				TEST_MSG("- Leader found\n");
			}
			else {
				TEST_MSG("- Probing for leader...\n");
				for (i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
					rrr_raft_client_request_opt (
							&req_index,
							callback_data->channels[i]
					);
					assert(req_index > 0);
					__rrr_test_raft_register_expected_msg(callback_data, i + 1, req_index);
				}
				callback_data->cmd_pos--;
			}
		} break;
		case 1: {
			TEST_MSG("- Sending PUT messages...\n");

			for (msg_pos = callback_data->msg_pos; msg_pos < 10; msg_pos++) {
				sprintf(topic, "topic/%c", '0' + msg_pos % 10);

				rrr_raft_client_request_put (
						&req_index,
						callback_data->channels[callback_data->leader_index],
						topic,
						requests[msg_pos % 10],
						strlen(requests[msg_pos % 10])
				);
				assert(req_index > 0);
				__rrr_test_raft_register_expected_ack (
						callback_data,
						callback_data->leader_index + 1,
						req_index,
						1 /* ok expected */
				);
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 2: {
			if (!callback_data->rrr_test_raft_pong_received) {
				// Pong not received yet
				TEST_MSG("- Waiting for pong...\n");
				callback_data->cmd_pos--;
			}
			else {
				TEST_MSG("- A pong as been received\n");
			}
		} break;
		case 3: {
			TEST_MSG("- Sending GET messages...\n");

			for (msg_pos = callback_data->msg_pos; msg_pos < 20; msg_pos++) {
				sprintf(topic, "topic/%c", '0' + msg_pos % 10);

				for (i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
					rrr_raft_client_request_get (
							&req_index,
							callback_data->channels[i],
							topic
					);
					assert(req_index > 0);
					__rrr_test_raft_register_expected_msg (
							callback_data,
							i + 1,
							req_index
					);
				}
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 4: {
			TEST_MSG("- Checking for responses...\n");

			if (!__rrr_test_raft_check_all_ack_received(callback_data)) {
				TEST_MSG("- Waiting for ACKs, NACKs or MSGs\n");
				callback_data->cmd_pos--;
			}
			else {
				TEST_MSG("- All responses received\n");
			}
		} break;
		case 5: {
			TEST_MSG("- Sending GET messages (non-existent topics)...\n");

			for (msg_pos = callback_data->msg_pos; msg_pos < 30; msg_pos++) {
				sprintf(topic, "topic/%c", 'a' + msg_pos % 10);

				for (i = 0; i < RRR_TEST_RAFT_SERVER_COUNT; i++) {
					rrr_raft_client_request_get (
							&req_index,
							callback_data->channels[i],
							topic
					);
					assert(req_index > 0);
					__rrr_test_raft_register_expected_ack (
							callback_data,
							i + 1,
							req_index,
							0 /* expect not ok */
					);
				}
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 6: {
			TEST_MSG("- Checking for ACKs...\n");

			if (!__rrr_test_raft_check_all_ack_received(callback_data)) {
				TEST_MSG("- Waiting for ACKs, NACKs or MSGs\n");
				callback_data->cmd_pos--;
			}
			else {
				TEST_MSG("- All ACKs received\n");
			}
		} break;
		default: {

			TEST_MSG("- All tasks complete\n");

			callback_data->all_ok = 1;

			return RRR_EVENT_EXIT;
		} break;
	};
/*
	if (ret_tmp != 0) {
		TEST_MSG("A periodic command failed with error %i\n", ret_tmp);
		return RRR_EVENT_ERR;
	}
*/

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
	callback_data.leader_index = -1;

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
				servers, // All servers
				i,       // Index of self server
				dir,
				__rrr_test_raft_pong_callback,
				__rrr_test_raft_ack_callback,
				__rrr_test_raft_opt_callback,
				__rrr_test_raft_msg_callback,
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

	if (!callback_data.all_ok) {
		TEST_MSG("All OK not set, one or more tests failed or has not run\n");
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
