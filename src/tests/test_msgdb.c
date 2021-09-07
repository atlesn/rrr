/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/msgdb/msgdb_client.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/rrr_strerror.h"
#include "../lib/util/posix.h"
#include "../lib/util/rrr_time.h"
#include "../lib/fork.h"
#include "../lib/array.h"
#include "../lib/random.h"
#include "../lib/helpers/string_builder.h"
#include "test.h"

#define MSGDB_CMD        "../.libs/rrr_msgdb"
#define MSGDB_SOCKET     "/tmp/rrr_test_msgdb.sock"
#define MSGDB_DIRECTORY  "/tmp/rrr_test_msgdb/"

// #define RRR_TEST_MSGDB_SERVER_USE_VALGRIND

static int __rrr_test_msgdb_msg_create (struct rrr_msg_msg **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_msg_msg_new_empty (
		&msg,
		MSG_TYPE_MSG,
		MSG_CLASS_DATA,
		rrr_time_get_64(),
		0,
		0
	)) != 0) {
		goto out;
	}

	*result = msg;
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb_await_ack(int *positive_ack, struct rrr_msgdb_client_conn *conn) {
	int ret = 0;

	if ((ret = rrr_msgdb_client_await_ack(positive_ack, conn)) != 0) {
		TEST_MSG("Non-zero return %i from await ACK\n", ret);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_test_msgdb_await_positive_ack(struct rrr_msgdb_client_conn *conn) {
	int ret = 0;

	int positive_ack;
	if ((ret = __rrr_test_msgdb_await_ack(&positive_ack, conn)) != 0) {
		goto out;
	}

	if (positive_ack != 1) {
		TEST_MSG("Expected positive ACK, but negative was received\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_test_msgdb_await_negative_ack(struct rrr_msgdb_client_conn *conn) {
	int ret = 0;

	int positive_ack;
	if ((ret = __rrr_test_msgdb_await_ack(&positive_ack, conn)) != 0) {
		goto out;
	}

	if (positive_ack != 0) {
		TEST_MSG("Expected negative ACK, but positive was received\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_test_msgdb_await_and_check_msg (
		struct rrr_msgdb_client_conn *conn,
		const struct rrr_msg_msg *expected_msg
) {
	int ret = 0;

	struct rrr_msg_msg *result_msg = NULL;

	if ((ret = rrr_msgdb_client_await_msg(&result_msg, conn, NULL, NULL)) != 0) {
		TEST_MSG("Non-zero return %i from await msg\n", ret);
		ret = 1;
		goto out;
	}

	if (MSG_TOTAL_SIZE(result_msg) != MSG_TOTAL_SIZE(expected_msg)) {
		RRR_MSG_0("Message verification failed, size mismatch.\n");
		ret = 1;
	}
	else if (memcmp(result_msg, expected_msg, MSG_TOTAL_SIZE(result_msg)) != 0) {
		RRR_MSG_0("Message verification failed, the messages were not equal.\n");
		ret = 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(result_msg);
	return ret;
}

#define ACK_MODE_NOT_OK 0
#define ACK_MODE_OK     1
#define ACK_MODE_ANY    2

static int __rrr_test_msgdb_await_and_check_ack (
		struct rrr_msgdb_client_conn *conn,
		int ack_mode
) {
	int positive_ack_dummy = 0;
	switch (ack_mode) {
		case ACK_MODE_NOT_OK:
			return __rrr_test_msgdb_await_negative_ack(conn);
		case ACK_MODE_OK:
			return __rrr_test_msgdb_await_positive_ack(conn);
		default:
			return  __rrr_test_msgdb_await_ack(&positive_ack_dummy, conn);
	};
}

static int __rrr_test_msgdb_send_empty (
		struct rrr_msgdb_client_conn *conn,
		rrr_u8 type,
		const char *topic,
		int ack_mode
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = __rrr_test_msgdb_msg_create(&msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_set(&msg, topic, rrr_u16_from_biglength_bug_const (strlen(topic)))) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, type);

	if ((ret = rrr_msgdb_client_send(conn, msg, NULL, NULL)) != 0) {
		goto out;
	}

	ret = __rrr_test_msgdb_await_and_check_ack(conn, ack_mode);

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb_get_msg (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;
	struct rrr_msg_msg *result_msg = NULL;

	if ((ret = __rrr_test_msgdb_msg_create(&msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_set(&msg, topic, rrr_u16_from_biglength_bug_const (strlen(topic)))) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_GET);

	if ((ret = rrr_msgdb_client_send(conn, msg, NULL, NULL)) != 0) {
		goto out;
	}

	if ((ret = rrr_msgdb_client_await_msg(&result_msg, conn, NULL, NULL)) != 0) {
		TEST_MSG("Non-zero return %i from await msg\n", ret);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(result_msg);
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb_get_index (
		struct rrr_msgdb_client_conn *conn,
		uint32_t min_age_s,
		int expected_paths_length
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_string_builder value_tmp = {0};

	if ((ret = rrr_msgdb_client_cmd_idx(&array_tmp, conn, min_age_s, NULL, NULL)) != 0) {
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_array_dump(&array_tmp);
	}

	if (RRR_LL_COUNT(&array_tmp) != expected_paths_length) {
		TEST_MSG("Wrong number of paths returned from server\n");
		ret = 1;
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&array_tmp, const struct rrr_type_value);
		if (strcmp(node->tag, "dir") == 0) {
			RRR_LL_ITERATE_NEXT();
		}
		if ((ret = rrr_string_builder_append_raw(&value_tmp, node->data, node->total_stored_length)) != 0) {
			goto out;
		}
		if ((ret = __rrr_test_msgdb_get_msg (conn, rrr_string_builder_buf(&value_tmp))) != 0) {
			goto out;
		}
		rrr_string_builder_clear(&value_tmp);
	RRR_LL_ITERATE_END();

	out:
	rrr_string_builder_clear(&value_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_test_msgdb_get_and_check_msg (
		struct rrr_msgdb_client_conn *conn,
		const char *topic,
		const struct rrr_msg_msg *expected_msg
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = __rrr_test_msgdb_msg_create(&msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_set(&msg, topic, rrr_u16_from_biglength_bug_const (strlen(topic)))) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_GET);

	if ((ret = rrr_msgdb_client_send(conn, msg, NULL, NULL)) != 0) {
		goto out;
	}

	if (expected_msg != NULL) {
		if ((ret = __rrr_test_msgdb_await_and_check_msg(conn, expected_msg)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = __rrr_test_msgdb_await_negative_ack(conn)) != 0) {
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb_send_and_get_array (
		struct rrr_msgdb_client_conn *conn,
		const char *topic
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	struct rrr_array array_tmp = {0};

	if ((ret = rrr_array_push_value_u64_with_tag(&array_tmp, "oneone", 11)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag(&array_tmp, "twotwo", 22)) != 0) {
		goto out;
	}

	if ((ret = rrr_array_push_value_i64_with_tag(&array_tmp, "random", rrr_rand())) != 0) {
		goto out;
	}

	if ((ret = rrr_array_new_message_from_array (&msg, &array_tmp, rrr_time_get_64(), topic, (rrr_u16) strlen(topic))) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_PUT);

	if ((ret = rrr_msgdb_client_send(conn, msg, NULL, NULL)) != 0) {
		goto out;
	}

	if ((ret = __rrr_test_msgdb_await_and_check_ack(conn, ACK_MODE_OK)) != 0) {
		goto out;
	}

	MSG_SET_TYPE(msg, MSG_TYPE_GET);

	// Data is ignored for GET messages, we simply change the type
	if ((ret = rrr_msgdb_client_send(conn, msg, NULL, NULL)) != 0) {
		goto out;
	}

	// Reset type before comparing
	MSG_SET_TYPE(msg, MSG_TYPE_MSG);

	if ((ret = __rrr_test_msgdb_await_and_check_msg(conn, msg)) != 0) {
		goto out;
	}

	if ((ret = __rrr_test_msgdb_send_empty (
		conn,
		MSG_TYPE_DEL,
		topic,
		ACK_MODE_OK
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_test_msgdb(void) {
	int ret = 0;

	struct rrr_msgdb_client_conn conn = {0};

	if ((ret = rrr_msgdb_client_open_simple(&conn, MSGDB_SOCKET)) != 0) {
		goto out;
	}

	// Tidy everything
	if ((ret = rrr_msgdb_client_cmd_tidy(&conn, 0)) != 0) {
		goto out;
	}

	// Since filenames are hashed, any path is valid

	// Strange path
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "../b", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Strange path
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "/../.b", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Strange path
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "a/.b", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Invalid, not topic
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "", ACK_MODE_NOT_OK)) != 0) {
		goto out;
	}

	// Valid
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "a/b/c", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Valid
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "a/b/d", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Zero seconds min age, should return all messages stored by now
	if ((ret = __rrr_test_msgdb_get_index (&conn, 0, 5)) != 0) {
		goto out;
	}

	// Long minimum age, should return zero messages
	if ((ret = __rrr_test_msgdb_get_index (&conn, 0xffffffff, 0)) != 0) {
		goto out;
	}

	// Invalid GET
	if ((ret = __rrr_test_msgdb_get_and_check_msg (&conn, "a/b", NULL)) != 0) {
		goto out;
	}

	// Invalid DELETE, but returns OK
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_DEL, "a/b", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Valid, delete message
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_DEL, "a/b/c", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Valid, delete message
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_DEL, "a/b/d", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Valid
	if ((ret = __rrr_test_msgdb_send_empty(&conn, MSG_TYPE_PUT, "a/b", ACK_MODE_OK)) != 0) {
		goto out;
	}

	// Tidy everything older than 10 seconds (no messages should be tidied)
	if ((ret = rrr_msgdb_client_cmd_tidy(&conn, 10)) != 0) {
		goto out;
	}

	// Valid
	if ((ret = __rrr_test_msgdb_send_and_get_array (&conn, "a")) != 0) {
		goto out;
	}

	// Tidy everything
	if ((ret = rrr_msgdb_client_cmd_tidy(&conn, 0)) != 0) {
		goto out;
	}

	// Invalid GET, should be tidied
	if ((ret = __rrr_test_msgdb_get_and_check_msg (&conn, "a/b/c", NULL)) != 0) {
		goto out;
	}

	// Should return no messages, everything should be cleaned up
	if ((ret = __rrr_test_msgdb_get_index (&conn, 0, 0)) != 0) {
		goto out;
	}

	out:
	rrr_msgdb_client_close(&conn);
	return ret;
}

static void __rrr_test_msgdb_fork_exit_notify(pid_t pid, void *arg) {
	(void)(arg);
	(void)(pid);
	RRR_DBG_1("Message database server has exited\n");
}

int rrr_test_msgdb(struct rrr_fork_handler *fork_handler) {
	int ret = 0;

	pid_t msgserver_pid = 0;

	RRR_DBG_1("Forking to start message database service '" MSGDB_CMD "'...\n");

	if ((msgserver_pid = rrr_fork(fork_handler, __rrr_test_msgdb_fork_exit_notify, NULL)) < 0) {
		TEST_MSG("Could not fork: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	else if (msgserver_pid == 0) {
		// Child code
		char debuglevel[64];
		sprintf(debuglevel, "%llu", (long long unsigned) RRR_DEBUGLEVEL);
		setenv("LD_LIBRARY_PATH", "../lib/.libs/", 1);
#ifdef RRR_TEST_MSGDB_SERVER_USE_VALGRIND
		execl("/usr/bin/valgrind", "", MSGDB_CMD, MSGDB_DIRECTORY, "-s", MSGDB_SOCKET, "-d", debuglevel, (char *) NULL);
#else
		execl(MSGDB_CMD, "", MSGDB_DIRECTORY, "-s", MSGDB_SOCKET, "-d", debuglevel, (char *) NULL);
#endif
		TEST_MSG("Could not start message database sever " MSGDB_CMD ": %s\n", rrr_strerror(errno));
		exit(1);
	}

	// Wait for server to start listening on socket
#ifdef RRR_TEST_MSGDB_SERVER_USE_VALGRIND
	rrr_posix_usleep(2000000);
#else
	rrr_posix_usleep(500000);
#endif

	ret = __rrr_test_msgdb();

	out:
	if (msgserver_pid > 0) {
		rrr_fork_send_sigusr1_to_pid(msgserver_pid);
	}
	return ret;
}
