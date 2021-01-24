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
#include "test.h"

#define MSGDB_CMD "../.libs/rrr_msgdb"

int rrr_test_msgdb(void) {
	int ret = 0;

	pid_t msgserver_pid = 0;
	struct rrr_msg_msg *msg = NULL;

	const char msg_topic[] = "a/b/c";

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

	RRR_DBG_1("Forking to start message database service '" MSGDB_CMD "'...\n");

	if ((msgserver_pid = fork()) < 0) {
		TEST_MSG("Could not fork: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	else if (msgserver_pid == 0) {
		// Child code
		execl(MSGDB_CMD, "", "-s", "/tmp/rrr_test_msgdb.sock", "-d", "/tmp/rrr_test_msgdb/", (char *) NULL);
		TEST_MSG("Could not execute message database command " MSGDB_CMD ": %s\n", rrr_strerror(errno));
		exit(1);
	}

	memcpy(MSG_TOPIC_PTR(msg), msg_topic, sizeof(msg_topic) - 1);

	if ((ret = rrr_msgdb_client_put(msg)) != 0) {
		goto out;
	}

	out:
	if (msgserver_pid > 0) {
		rrr_posix_usleep(500000);
		if (kill(msgserver_pid, SIGTERM) < 0) {
			TEST_MSG("Failed while sending SIGTERM to message database server: %s\n", rrr_strerror(errno));
			ret |= 1;
		}
		int status;
		if (waitpid(msgserver_pid, &status, 0) < 0) {
			TEST_MSG("Failed while waiting on message database server: %s\n", rrr_strerror(errno));
			ret |= 1;
		}
		else if (WEXITSTATUS(status) != 0) {
			TEST_MSG("Non-zero exit status %i from message database server\n", WEXITSTATUS(status));
			ret |= 1;
		}
	}
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}
