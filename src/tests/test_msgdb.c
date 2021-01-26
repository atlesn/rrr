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
#include "../lib/msgdb/msgdb_client.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/rrr_strerror.h"
#include "../lib/util/posix.h"
#include "../lib/fork.h"
#include "test.h"

#define MSGDB_CMD        "../.libs/rrr_msgdb"
#define MSGDB_SOCKET     "/tmp/rrr_test_msgdb.sock"
#define MSGDB_DIRECTORY  "/tmp/rrr_test_msgdb/"

static int __rrr_test_msgdb_msg_create (struct rrr_msg_msg **result) {
	int ret = 0;

	*result = NULL;

	const char msg_topic[] = "a/b/c";
	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_msg_msg_new_empty (
		&msg,
		MSG_TYPE_MSG,
		MSG_CLASS_DATA,
		rrr_time_get_64(),
		sizeof(msg_topic) - 1,
		0
	)) != 0) {
		goto out;
	}

	memcpy(MSG_TOPIC_PTR(msg), msg_topic, sizeof(msg_topic) - 1);

	*result = msg;
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb_await_ack(struct rrr_msgdb_client_conn *conn) {
	int ret = 0;

	int positive_ack = 0;
	if ((ret = rrr_msgdb_client_await_ack(&positive_ack, conn)) != 0) {
		TEST_MSG("Non-zero return %i from await ACK\n", ret);
		ret = 1;
		goto out;
	}

	if (!positive_ack) {
		TEST_MSG("Non-positive ack from message db server\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_test_msgdb_put(struct rrr_msgdb_client_conn *conn) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = __rrr_test_msgdb_msg_create(&msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_msgdb_client_put(conn, msg)) != 0) {
		goto out;
	}

	if ((ret = __rrr_test_msgdb_await_ack(conn)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int __rrr_test_msgdb(void) {
	int ret = 0;

	struct rrr_msgdb_client_conn conn = {0};

	if ((ret = rrr_msgdb_client_open(&conn, MSGDB_SOCKET)) != 0) {
		goto out;
	}

	if ((ret = __rrr_test_msgdb_put(&conn)) != 0) {
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
		execl(MSGDB_CMD, "", MSGDB_DIRECTORY, "-s", MSGDB_SOCKET, "-d", debuglevel, (char *) NULL);
		TEST_MSG("Could not start message database sever " MSGDB_CMD ": %s\n", rrr_strerror(errno));
		exit(1);
	}

	// Wait for server to start listening on socket
	rrr_posix_usleep(500000);

	ret = __rrr_test_msgdb();

	rrr_posix_usleep(500000);

	out:
	if (msgserver_pid > 0) {
		rrr_fork_send_sigusr1_to_pid(msgserver_pid);
	}
	return ret;
}
