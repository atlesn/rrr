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
#include <sys/stat.h>

#include "test.h"
#include "test_raft.h"
#include "../lib/allocator.h"
#include "../lib/rrr_strerror.h"
#include "../lib/event/event.h"
#include "../lib/raft/channel.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/messages/msg_msg_struct.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/util/fs.h"

#define RRR_TEST_RAFT_SERVER_INITIAL_COUNT 3
#define RRR_TEST_RAFT_SERVER_INTERMEDIATE_COUNT 1
#define RRR_TEST_RAFT_SERVER_TOTAL_COUNT \
  (RRR_TEST_RAFT_SERVER_INITIAL_COUNT+RRR_TEST_RAFT_SERVER_INTERMEDIATE_COUNT)
#define RRR_TEST_RAFT_IN_FLIGHT_MAX 64

// NOTE : It is assumed that the ID of the server equals the
//        the array position with respect to total count + 1
//        disregarding end sentinels

static const struct rrr_raft_server servers_initial[RRR_TEST_RAFT_SERVER_INITIAL_COUNT + 1] = {
	{.id = 1, .address = "127.0.0.1:9001"},
	{.id = 2, .address = "127.0.0.1:9002"},
	{.id = 3, .address = "127.0.0.1:9003"},
	{.id = 0, .address = ""}
};

static const struct rrr_raft_server servers_intermediate[RRR_TEST_RAFT_SERVER_INTERMEDIATE_COUNT + 1] = {
	{.id = 4, .address = "127.0.0.1:9004"},
	{.id = 0, .address = ""}
};

static const char *requests[] = {
	"{'data': 0}",
	"{'data': 1}",
	"{'data': 2}",
	"{'data': 3}",
	"{'data': 4}",
	"{'data': 5}",
	"{'data': 6}",
	"{'data': 7}",
	"{'data': 8}",
	"{'data': 9}",
	"{'patch': 69}"
};

static const char *results[] = {
	"{'data': 0}",
	"{'data': 1}",
	"{'data': 2}",
	"{'data': 3}",
	"{'data': 4}",
	"{'data': 5}",
	"{'data': 6}",
	"{'data': 7}",
	"{'data': 8}",
	"{'data': 9}",
	"{'data':0,'patch':69}"
};

static const char base_dir[] = "/tmp/rrr-test-raft";

struct rrr_test_raft_data_expected {
	uint32_t req_index;
	uint32_t data_index;
};

struct rrr_test_raft_callback_data {
	struct rrr_raft_channel **channels;
	int rrr_test_raft_pong_received;
	const volatile int *main_running;
	unsigned int cmd_pos;
	unsigned int msg_pos;
	uint32_t ack_expected[RRR_TEST_RAFT_SERVER_TOTAL_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	uint32_t nack_expected[RRR_TEST_RAFT_SERVER_TOTAL_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	uint32_t msg_expected[RRR_TEST_RAFT_SERVER_TOTAL_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	struct rrr_test_raft_data_expected data_expected[RRR_TEST_RAFT_SERVER_TOTAL_COUNT][RRR_TEST_RAFT_IN_FLIGHT_MAX];
	struct rrr_raft_server servers_delete[RRR_TEST_RAFT_SERVER_INTERMEDIATE_COUNT + 1];
	struct rrr_raft_server **servers;
	int leader_index;
	int leader_index_new;
	int leader_index_old;
	int all_ok;
};

static int __rrr_test_raft_server_array_has (
		const struct rrr_raft_server *servers,
		const struct rrr_raft_server *server
) {
	for (; servers->id > 0; servers++) {
		if (servers->id == server->id) {
			return 1;
		}
	}
	return 0;
}

static void __rrr_test_raft_register_expected (
		uint32_t *array,
		uint32_t req_index
) {
	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i] == req_index) {
			RRR_BUG("BUG: Request already registered in %s\n", __func__);
		}
	}

	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i] == 0) {
			array[i] = req_index;
			return;
		}
	}

	RRR_BUG("BUG: In flight max reached in %s\n", __func__);
}

static void __rrr_test_raft_register_expected_data (
		struct rrr_test_raft_data_expected *array,
		uint32_t req_index,
		uint32_t data_index
) {
	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i].req_index == req_index) {
			RRR_BUG("BUG: Request already registered in %s\n", __func__);
		}
	}

	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i].req_index == 0) {
			array[i].req_index = req_index;
			array[i].data_index = data_index;
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
	// TEST_MSG("- Register expected ACK %u server: %i ok: %i\n", req_index, server_id, ok);
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_TOTAL_COUNT);
	__rrr_test_raft_register_expected((ok ? callback_data->ack_expected : callback_data->nack_expected)[server_id - 1], req_index);
}

static void __rrr_test_raft_register_expected_msg_data (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		uint32_t data_index
) {
	// TEST_MSG("- Register expected MSG %u server: %i data index: %u\n", req_index, server_id, data_index);
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_TOTAL_COUNT);
	__rrr_test_raft_register_expected(callback_data->msg_expected[server_id - 1], req_index);
	__rrr_test_raft_register_expected_data(callback_data->data_expected[server_id - 1], req_index, data_index);
}

static void __rrr_test_raft_register_expected_msg_no_data (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index
) {
	return __rrr_test_raft_register_expected_msg_data(callback_data, server_id, req_index, UINT32_MAX);
}

static void __rrr_test_raft_register_expected_pair_data (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		uint32_t data_index,
		int ok
) {
	__rrr_test_raft_register_expected_ack (
			callback_data,
			server_id,
			req_index,
			ok
	);

	if (ok) {
		__rrr_test_raft_register_expected_msg_data (
				callback_data,
				server_id,
				req_index,
				data_index
		);
	}
}

static void __rrr_test_raft_register_expected_pair_no_data (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		int ok
) {
	__rrr_test_raft_register_expected_pair_data(callback_data, server_id, req_index, UINT32_MAX, ok);
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

static void __rrr_test_raft_register_response_data (
		struct rrr_test_raft_data_expected *array,
		uint32_t req_index,
		const char *data,
		size_t data_len
) {
	for (size_t i = 0; i < RRR_TEST_RAFT_IN_FLIGHT_MAX; i++) {
		if (array[i].req_index == req_index) {
			if (data == NULL) {
				if (array[i].data_index != UINT32_MAX) {
					RRR_BUG("BUG: Expected response with data not to be checked but an index was given (%u)\n",
						array[i].data_index);
				}
				array[i].req_index = 0;
				return;
			}

			const char *data_cmp = results[array[i].data_index];

			if (strlen(data_cmp) != data_len) {
				RRR_BUG("BUG: Data length mismatch in %s: %u<>%u\n",
					__func__, strlen(data_cmp), data_len);
			}

			if (memcmp(data_cmp, data, data_len) != 0) {
				RRR_BUG("BUG: Data mismatch in %s: <<%s>> <> <<%.*s>>\n",
					__func__, data_cmp, data_len, data);
			}

			array[i].req_index = 0;
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
	TEST_MSG("- Register response ACK %u server: %i ok: %i\n", req_index, server_id, ok);
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_TOTAL_COUNT);
	__rrr_test_raft_register_response((ok ? callback_data->ack_expected : callback_data->nack_expected)[server_id - 1], req_index);
}

static void __rrr_test_raft_register_response_msg (
		struct rrr_test_raft_callback_data *callback_data,
		int server_id,
		uint32_t req_index,
		const char *data,
		size_t data_len
) {
	TEST_MSG("- Register response MSG %u server: %i\n", req_index, server_id);
	assert(server_id > 0 && server_id <= RRR_TEST_RAFT_SERVER_TOTAL_COUNT);
	__rrr_test_raft_register_response(callback_data->msg_expected[server_id - 1], req_index);
	__rrr_test_raft_register_response_data(callback_data->data_expected[server_id - 1], req_index, data, data_len);
}

static int __rrr_test_raft_check_all_ack_received (
		struct rrr_test_raft_callback_data *callback_data
) {
	int res = 1;

	for (int i = 0; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
		uint32_t *ack_expected = callback_data->ack_expected[i];
		uint32_t *nack_expected = callback_data->nack_expected[i];
		uint32_t *msg_expected = callback_data->msg_expected[i];
		struct rrr_test_raft_data_expected *data_expected = callback_data->data_expected[i];

		for (int j = 0; j < RRR_TEST_RAFT_IN_FLIGHT_MAX; j++) {
			if (ack_expected[j] != 0) {
				TEST_MSG("  - ACK not received for req %u server %i\n", ack_expected[j], j + 1);
				res = 0;
			}
			if (nack_expected[j] != 0) {
				TEST_MSG("  - NACK not received for req %u server %i\n", nack_expected[j], j + 1);
				res = 0;
			}
			if (msg_expected[j] != 0) {
				TEST_MSG("  - MSG not received for req %u server %i\n", msg_expected[j], j + 1);
				res = 0;
			}
			if (data_expected[j].req_index != 0) {
				TEST_MSG("  - Data not received for req %u server %i\n", data_expected[j].req_index, j + 1);
				res = 0;
			}
		}
	}

	return res;
}

static int __rrr_test_raft_check_all_servers_voting (
		int *count,
		struct rrr_test_raft_callback_data *callback_data
) {
	struct rrr_raft_server *server;

	int res = 1;

	*count = 0;

	if (*callback_data->servers == NULL) {
		res = 0;
		goto out;
	}

	for (server = *callback_data->servers; server->id > 0; server++) {
		if (server->status != RRR_RAFT_VOTER) {
			res = 0;
		}
		else {
			(*count)++;
		}
	}

	out:
	return res;
}

static int __rrr_test_raft_check_some_server_catched_up (
		struct rrr_test_raft_callback_data *callback_data
) {
	struct rrr_raft_server *server;

	if (*callback_data->servers == NULL)
		return 0;

	for (server = *callback_data->servers; server->id > 0; server++) {
		if (server->catch_up == RRR_RAFT_CATCH_UP_FINISHED) {
			return 1;
		}
	}

	return 0;
}

static void __rrr_test_raft_pong_callback (RRR_RAFT_PONG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	(void)(server_id);

	if (!callback_data->rrr_test_raft_pong_received) {
		// TEST_MSG("Pong received server %i\n", server_id);
		callback_data->rrr_test_raft_pong_received = 1;
	}
}

static void __rrr_test_raft_ack_callback (RRR_RAFT_ACK_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	TEST_MSG("%s %u received server %i\n",
		(code == 0 ? "ACK" : "NACK"), req_index, server_id);

	__rrr_test_raft_register_response_ack(callback_data, server_id, req_index, code == 0);
}

static void __rrr_test_raft_opt_callback (RRR_RAFT_OPT_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	(void)(leader_address);

	struct rrr_raft_server *server;
	size_t servers_delete_pos = 0;

	// TEST_MSG("OPT %u received server %i leader id %" PRIi64 " is leader %" PRIi64 "\n",
	//	req_index, server_id, leader_id, is_leader);

	if (leader_id > 0) {
		callback_data->leader_index = leader_id - 1;
		assert(callback_data->leader_index >= 0 && callback_data->leader_index < RRR_TEST_RAFT_SERVER_TOTAL_COUNT);
	}
	else {
		callback_data->leader_index = -1;
	}

	// Read servers only from leader to get correct catch-up status
	if (is_leader) {
		assert(leader_id == server_id);

		for (server = *servers; server->id > 0; server++) {
			TEST_MSG("- Found member %" PRIi64 " address %s status %s catch up %s\n",
				server->id,
				server->address,
				RRR_RAFT_STATUS_TO_STR(server->status),
				RRR_RAFT_CATCH_UP_TO_STR(server->catch_up)
			);

			if (__rrr_test_raft_server_array_has(servers_intermediate, server)) {
				TEST_MSG("- Scheduling intermediate cluster member %" PRIi64 " address %s for potential deletion\n",
					server->id, server->address);
				assert(servers_delete_pos < sizeof(callback_data->servers_delete)/sizeof(callback_data->servers_delete[0]) - 1);
				callback_data->servers_delete[servers_delete_pos++] = *server;
			}
		}

		RRR_FREE_IF_NOT_NULL(*callback_data->servers);
		*callback_data->servers = *servers;
		*servers = NULL;
	}
	else {
		if (*servers != NULL) {
			for (server = *servers; server->id > 0; server++) {
				TEST_MSG("- Found member %" PRIi64 " address %s status %s\n",
					server->id,
					server->address,
					RRR_RAFT_STATUS_TO_STR(server->status)
				);
			}
		}
		else {
			TEST_MSG("- No servers found\n");
		}
	}

	__rrr_test_raft_register_response_msg(callback_data, server_id, req_index, NULL, 0);
}

static void __rrr_test_raft_msg_callback (RRR_RAFT_MSG_CALLBACK_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	const char *topic_ptr;

	// TEST_MSG("MSG %u received server %i\n",
	//	req_index, server_id);

	assert(MSG_TOPIC_LENGTH(*msg) == strlen("topic/x"));
	topic_ptr = MSG_TOPIC_PTR(*msg);
	assert(strncmp(MSG_TOPIC_PTR(*msg), "topic/", strlen("topic/")) == 0);
	topic_ptr += strlen("topic/");
	assert(*topic_ptr >= '0' && *topic_ptr <= '9');

	__rrr_test_raft_register_response_msg(callback_data, server_id, req_index, MSG_DATA_PTR(*msg), MSG_DATA_LENGTH(*msg));
}

static int __rrr_test_raft_patch_callback (RRR_RAFT_PATCH_CB_ARGS) {
	int ret = 0;

	struct rrr_msg_msg *msg;

	if (strncmp(MSG_DATA_PTR(msg_orig), requests[0], strlen(requests[0])) != 0) {
		RRR_BUG("BUG: Data mismatch in %s: <<%s>> <> <<%.*s>>\n",
			__func__, requests[0], MSG_DATA_LENGTH(msg_orig), MSG_DATA_PTR(msg_orig));
	}

	if (strncmp(MSG_DATA_PTR(msg_patch), requests[10], strlen(requests[10])) != 0) {
		RRR_BUG("BUG: Patch data mismatch in %s\n", __func__);
	}

	if ((ret = rrr_msg_msg_new_with_data (
			&msg,
			MSG_TYPE_PUT,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			MSG_TOPIC_PTR(msg_orig),
			MSG_TOPIC_LENGTH(msg_orig),
			results[10],
			strlen(results[10])
	)) != 0 ) {
		RRR_MSG_0("Failed to allocate data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*msg_new = msg;

	out:
	return ret;
}

#define WAIT_ACK()                                                  \
    if (!__rrr_test_raft_check_all_ack_received(callback_data)) {   \
        TEST_MSG("- Waiting for ACKs, NACKs or MSGs\n");            \
        callback_data->cmd_pos--;                                   \
        break;                                                      \
    }                                                               \
    else {                                                          \
        TEST_MSG("- All ACKs received\n");                          \
    } do {} while(0)

#define PROBE(server_index)                                                                 \
    do {                                                                                    \
        RRR_FREE_IF_NOT_NULL(*callback_data->servers);                                      \
        req_index = 0;                                                                      \
        rrr_raft_channel_request_opt (&req_index, callback_data->channels[server_index]);   \
        assert(req_index > 0);                                                              \
        TEST_MSG("- Probed server %i req %u...\n", server_index, req_index);                \
        __rrr_test_raft_register_expected_msg_no_data(callback_data, server_index + 1, req_index); \
    } while(0)                                                                              \

#define GET(server_index,data_index,expect_ok)                                                    \
    do {                                                                                          \
        req_index = 0;                                                                            \
        rrr_raft_channel_request_get (                                                            \
                &req_index,                                                                       \
                callback_data->channels[server_index],                                            \
                topic,                                                                            \
                strlen(topic)                                                                     \
        );                                                                                        \
        assert(req_index > 0);                                                                    \
        __rrr_test_raft_register_expected_pair_data(callback_data, server_index + 1, req_index, data_index, expect_ok); \
    } while(0)

#define PUT(server_index,msg_index)                       \
    do {                                                  \
        req_index = 0;                                    \
        rrr_raft_channel_request_put (                    \
                &req_index,                               \
                callback_data->channels[server_index],    \
                topic,                                    \
                strlen(topic),                            \
                requests[msg_index],                      \
                strlen(requests[msg_index])               \
        );                                                \
        assert(req_index > 0);                            \
        __rrr_test_raft_register_expected_ack (           \
                callback_data,                            \
                server_index + 1,                         \
                req_index,                                \
                1 /* ok expected */                       \
        );                                                \
    } while(0)

#define PAT(server_index,msg_index)                       \
    do {                                                  \
        req_index = 0;                                    \
        rrr_raft_channel_request_patch (                  \
                &req_index,                               \
                callback_data->channels[server_index],    \
                topic,                                    \
                strlen(topic),                            \
                requests[msg_index],                      \
                strlen(requests[msg_index])               \
        );                                                \
        assert(req_index > 0);                            \
        __rrr_test_raft_register_expected_ack (           \
                callback_data,                            \
                server_index + 1,                         \
                req_index,                                \
                1 /* ok expected */                       \
        );                                                \
    } while(0)

#define DEL(server_index)                                 \
    do {                                                  \
        req_index = 0;                                    \
        rrr_raft_channel_request_delete (                 \
                &req_index,                               \
                callback_data->channels[server_index],    \
                topic,                                    \
                strlen(topic)                             \
        );                                                \
        assert(req_index > 0);                            \
        __rrr_test_raft_register_expected_ack (           \
                callback_data,                            \
                server_index + 1,                         \
                req_index,                                \
                1 /* ok expected */                       \
        );                                                \
    } while(0)

#define TRANSFER(server_index)                                        \
    do {                                                              \
         req_index = 0;                                               \
         rrr_raft_channel_leadership_transfer (                       \
             &req_index,                                              \
             callback_data->channels[callback_data->leader_index],    \
             server_index + 1                                         \
         );                                                           \
         assert(req_index > 0);                                       \
         __rrr_test_raft_register_expected_pair_no_data (             \
             callback_data,                                           \
             callback_data->leader_index + 1,                         \
             req_index,                                               \
             1 /* expect ok */                                        \
        );                                                            \
	callback_data->leader_index_old = callback_data->leader_index;\
        callback_data->leader_index_new = server_index;               \
    } while(0)

#define SNAPSHOT(server_index)                                        \
    do {                                                              \
         req_index = 0;                                               \
         rrr_raft_channel_snapshot (                                  \
             &req_index,                                              \
             callback_data->channels[callback_data->leader_index]     \
         );                                                           \
         assert(req_index > 0);                                       \
        __rrr_test_raft_register_expected_ack (                       \
                callback_data,                                        \
                server_index + 1,                                     \
                req_index,                                            \
                1 /* ok expected */                                   \
        );                                                            \
    } while(0)

static int __rrr_test_raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_test_raft_callback_data *callback_data = arg;

	char topic[16];
	int i, voting_count;
	unsigned int msg_pos;
	uint32_t req_index;
	struct rrr_raft_server servers_tmp[RRR_TEST_RAFT_SERVER_TOTAL_COUNT + 1];

	TEST_MSG("Periodic step %i\n", callback_data->cmd_pos);

	switch (callback_data->cmd_pos++) {
		case 0: {
			if (callback_data->leader_index >= 0) {
				// OK, async OPT response detected a leader
				TEST_MSG("- Leader found\n");

				__rrr_test_raft_check_all_servers_voting (&voting_count, callback_data);

				if (voting_count < 3) {
					TEST_MSG("- Initial servers not voting yet\n");
					PROBE(callback_data->leader_index);
					callback_data->cmd_pos--;
				}
				else if (callback_data->servers_delete[0].id > 0) {
					TEST_MSG("- Initial servers are voting and non-initial servers to delete found\n");

					// Only allowed to pass one server
					assert(callback_data->servers_delete[1].id == 0);

					// Not allowed to pass server with status field
					callback_data->servers_delete[0].status = 0;

					req_index = 0;
					rrr_raft_channel_servers_del (
							&req_index,
							callback_data->channels[callback_data->leader_index],
							callback_data->servers_delete
					);
					assert(req_index > 0);
					__rrr_test_raft_register_expected_pair_no_data (
							callback_data,
							callback_data->leader_index + 1,
							req_index,
							1 /* expect ok */
					);

					memset(callback_data->servers_delete, '\0', sizeof(callback_data->servers_delete));

					// It is possible that the leader is the one
					// getting deleted, run all steps again.
					callback_data->cmd_pos--;
				}
				else {
					TEST_MSG("- Initial servers are voting\n");
				}
			}
			else {
				for (i = 0; i < RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i++) {
					PROBE(i);
				}
				callback_data->cmd_pos--;
			}
		} break;
		case 1: {
			callback_data->cmd_pos--;
			TEST_MSG("Waiting indefinately\n");
		} break;
		case 1000: {
			TEST_MSG("- Sending PUT messages to %i...\n", callback_data->leader_index + 1);

			for (msg_pos = callback_data->msg_pos; msg_pos < 10; msg_pos++) {
				sprintf(topic, "topic/%c", '0' + msg_pos % 10);
				PUT(callback_data->leader_index, msg_pos % 10);
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 2: {
			if (!callback_data->rrr_test_raft_pong_received) {
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

				for (i = 0; i < RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i++) {
					GET(i, msg_pos % 10, 1 /* Expect ok */);
				}
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 4: {
			WAIT_ACK();

			TEST_MSG("- Sending GET messages (non-existent topics)...\n");

			for (msg_pos = callback_data->msg_pos; msg_pos < 30; msg_pos++) {
				sprintf(topic, "topic/%c", 'a' + msg_pos % 10);

				for (i = 0; i < RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i++) {
					GET(i, 0, 0 /* Expect not ok */);
				}
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 5: {
			WAIT_ACK();
		} break;
		case 6: {
			TEST_MSG("- Adding intermediate servers...\n");
			req_index = 0;
			rrr_raft_channel_servers_add (
					&req_index,
					callback_data->channels[callback_data->leader_index],
					servers_intermediate
			);
			assert(req_index > 0);
			__rrr_test_raft_register_expected_pair_no_data (
					callback_data,
					callback_data->leader_index + 1,
					req_index,
					1 /* Expect ok */
			);
		} break;
		case 7: {
			WAIT_ACK();
			PROBE(callback_data->leader_index);
		} break;
		case 8: {
			WAIT_ACK();

			TEST_MSG("- Assigning voter status to intermediate servers...\n");

			assert(sizeof(servers_intermediate) <= sizeof(servers_tmp));
			memcpy(servers_tmp, servers_intermediate, sizeof(servers_intermediate));

			servers_tmp[0].status = RRR_RAFT_VOTER;

			req_index = 0;
			rrr_raft_channel_servers_assign (
					&req_index,
					callback_data->channels[callback_data->leader_index],
					servers_tmp
			);
			assert(req_index > 0);
			__rrr_test_raft_register_expected_pair_no_data (
					callback_data,
					callback_data->leader_index + 1,
					req_index,
					1 /* Expect ok */
			);
		} break;
		case 9: {
			WAIT_ACK();

			if (!__rrr_test_raft_check_all_servers_voting(&voting_count, callback_data) ||
			    !__rrr_test_raft_check_some_server_catched_up(callback_data) ||
			     voting_count != 4
			) {
				TEST_MSG("- Waiting for all servers to become voters and catched up...\n");
				callback_data->cmd_pos--;
				PROBE(callback_data->leader_index);
			}
			else {
				TEST_MSG("- All servers are voters and the added server is catched up\n");
			}
		} break;
		case 10: {
			TEST_MSG("- Sending GET messages to added servers...\n");

			for (msg_pos = callback_data->msg_pos; msg_pos < 40; msg_pos++) {
				sprintf(topic, "topic/%c", '0' + msg_pos % 10);

				for (i = RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
					GET(i, msg_pos % 10, 1 /* Expect ok */);
				}
			}

			callback_data->msg_pos = msg_pos;
		} break;
		case 11: {
			WAIT_ACK();
		} break;
		case 12: {
			for (i = 0; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
				if (i == callback_data->leader_index) {
					continue;
				}

				TEST_MSG("- Transferring leadership from %i to %i\n",
					callback_data->leader_index + 1, i + 1);

				TRANSFER(i);

				break;
			}
		} break;
		case 13: {
			WAIT_ACK();
			PROBE(callback_data->leader_index_new);
		} break;
		case 14: {
			assert(callback_data->leader_index == callback_data->leader_index_new);
			TEST_MSG("- Leadership was transferred\n");
		} break;
		case 15: {
			for (i = 0; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
				if (i == callback_data->leader_index) {
					continue;
				}

				TEST_MSG("- Transferring leadership from %i to random voter\n",
					callback_data->leader_index + 1);

				TRANSFER(-1);

				break;
			}
		} break;
		case 16: {
			WAIT_ACK();
			for (i = 0; i < RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i++) {
				PROBE(i);
			}
		} break;
		case 17: {
			assert(callback_data->leader_index_old != callback_data->leader_index);
			TEST_MSG("- Leadership was transferred from %i to %i\n",
				callback_data->leader_index_old + 1, callback_data->leader_index + 1);
		} break;
		case 18: {
			TEST_MSG("- Sending PAT messages to %i...\n", callback_data->leader_index + 1);

			sprintf(topic, "topic/0");
			PAT(callback_data->leader_index, 10 /* Pass the patch data */);
		} break;
		case 19: {
			WAIT_ACK();

			TEST_MSG("- Sending GET messages to added servers...\n");

			sprintf(topic, "topic/0");

			for (i = RRR_TEST_RAFT_SERVER_INITIAL_COUNT; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
				GET(i, 10 /* Compare against expected patch outcome */, 1 /* Expect ok */);
			}
		} break;
		case 20: {
			WAIT_ACK();
		} break;
		case 21: {
			TEST_MSG("- Making snapshot suggestion...\n");

			SNAPSHOT(callback_data->leader_index);
		} break;
		case 22: {
			WAIT_ACK();

			TEST_MSG("- Sending DEL message to %i...\n", callback_data->leader_index + 1);

			sprintf(topic, "topic/0");
			DEL(callback_data->leader_index);
		} break;
		case 23: {
			WAIT_ACK();

			TEST_MSG("- Sending GET messages, expecting failure\n");

			sprintf(topic, "topic/0");
			GET(callback_data->leader_index, 0, 0 /* Expect not ok */);
		} break;
		case 24: {
			WAIT_ACK();

			TEST_MSG("- Making snapshot suggestion...\n");

			SNAPSHOT(callback_data->leader_index);
		} break;
		case 25: {
			WAIT_ACK();

			TEST_MSG("- Sending GET messages, expecting failure\n");

			sprintf(topic, "topic/0");
			GET(callback_data->leader_index, 0, 0 /* Expect not ok */);
		} break;
		default: {
			WAIT_ACK();

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

static int __rrr_test_raft_fork (
		int *i,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue,
		struct rrr_raft_channel **channels,
		const struct rrr_raft_server * const servers,
		struct rrr_test_raft_callback_data *callback_data
) {
	int ret = 0;

	int j;
	const struct rrr_raft_server *server;
	int socketpair[2];
	char dir[sizeof(base_dir) + 32];

	for (server = servers, j = 0; server->id > 0; server++, (*i)++, j++) {
		if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, "raft", socketpair)) != 0) {
			RRR_MSG_0("Failed to create sockets in %s: %s\n",
				rrr_strerror(errno));
			goto out;
		}

		sprintf(dir, "%s/%" PRIi64, base_dir, server->id);

		assert(channels[*i] == NULL);

		TEST_MSG("Start server %" PRIi64 " address %s\n", server->id, server->address);

		if ((ret = rrr_raft_channel_fork (
				&channels[*i],
				fork_handler,
				queue,
				"test",
				socketpair,
				servers, // All servers
				j,       // Index of self server
				dir,
				__rrr_test_raft_pong_callback,
				__rrr_test_raft_ack_callback,
				__rrr_test_raft_opt_callback,
				__rrr_test_raft_msg_callback,
				callback_data,
				__rrr_test_raft_patch_callback
		)) != 0) {
			TEST_MSG("Failed to fork out raft process\n");
			goto out;
		}

		socketpair[0] = -1;
		socketpair[1] = -1;
	}

	out:
	if (socketpair[0] > 0)
		rrr_socket_close(socketpair[0]);
	if (socketpair[1] > 0)
		rrr_socket_close(socketpair[1]);
	return ret;
}

static int __rrr_test_raft_server_dir_ensure(const char *dir) {
	int ret = 0;

	if ((ret = rrr_util_fs_dir_ensure(dir)) != 0) {
		RRR_MSG_0("Failed to ensure server directory %s: %s\n",
			dir, rrr_strerror(errno));
		goto out;
	}

	out:
	return ret;
}


static int __rrr_test_raft_server_dir_ensure_and_clean(const char *dir) {
	int ret = 0;

	if ((ret = rrr_util_fs_dir_ensure(dir)) != 0) {
		RRR_MSG_0("Failed to ensure server directory %s: %s\n",
			dir, rrr_strerror(errno));
		goto out;
	}

	if ((ret = rrr_util_fs_dir_clean(dir)) != 0) {
		RRR_MSG_0("Failed to clean server directory %s: %s\n",
			dir, rrr_strerror(errno));
	}

	out:
	return ret;
}

int rrr_test_raft (
		const volatile int *main_running,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *queue
) {
	int ret = 0;

	int i;
	struct rrr_raft_channel *channels[RRR_TEST_RAFT_SERVER_TOTAL_COUNT] = {0};
	struct rrr_test_raft_callback_data callback_data = {0};
	rrr_event_receiver_handle queue_handle;
	struct rrr_raft_server *servers = NULL;
	char dir[sizeof(base_dir) + 32];

	if ((ret = __rrr_test_raft_server_dir_ensure(base_dir)) != 0) {
		goto out;
	}

	for (i = 0; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
		sprintf(dir, "%s/%i", base_dir, i + 1);
		if ((ret = __rrr_test_raft_server_dir_ensure_and_clean(dir)) != 0) {
			goto out;
		}
	}

	callback_data.main_running = main_running;
	callback_data.channels = channels;
	callback_data.leader_index = -1;
	callback_data.servers = &servers;

	i = 0;
	if ((ret = __rrr_test_raft_fork (
			&i,
			fork_handler,
			queue,
			channels,
			servers_initial,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_test_raft_fork (
			&i,
			fork_handler,
			queue,
			channels,
			servers_intermediate,
			&callback_data
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_event_receiver_new (
			&queue_handle,
			queue,
			"raft test",
			&callback_data
	)) != 0) {
		goto out;
	}

	ret = rrr_event_function_periodic_set_and_dispatch (
			queue,
			queue_handle,
			250 * 1000, // 250 ms
			__rrr_test_raft_periodic
	);

	rrr_event_receiver_reset(queue, queue_handle);

	if (!callback_data.all_ok) {
		TEST_MSG("All OK not set, one or more tests failed or has not run\n");
		ret = 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(servers);
	for (i = 0; i < RRR_TEST_RAFT_SERVER_TOTAL_COUNT; i++) {
		if (channels[i] != NULL) {
			rrr_raft_channel_cleanup(channels[i]);
		}
		sprintf(dir, "%s/%i", base_dir, i + 1);
		__rrr_test_raft_server_dir_ensure_and_clean(dir);
		rmdir(dir);
	}
	rmdir(base_dir);
	return ret;
}

#endif /* RRR_TEST_RAFT_H */
