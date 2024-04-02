/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_RAFT_COMMON_H
#define RRR_RAFT_COMMON_H

#include <assert.h>
#include <stdint.h>

#define RRR_RAFT_STATUS_TO_STR(s)                      \
   ((s) == RRR_RAFT_STANDBY ? "STANDBY" :              \
   ((s) == RRR_RAFT_VOTER ? "VOTER" :                  \
   ((s) == RRR_RAFT_SPARE ? "SPARE" : "UNKNOWN")))

#define RRR_RAFT_CATCH_UP_TO_STR(s)                                  \
    ((s) == RRR_RAFT_CATCH_UP_NONE ? "NONE" :                        \
    ((s) == RRR_RAFT_CATCH_UP_RUNNING ? "RUNNING" :                  \
    ((s) == RRR_RAFT_CATCH_UP_ABORTED ? "ABORTED" :                  \
    ((s) == RRR_RAFT_CATCH_UP_FINISHED ? "FINISHED" : "UNKNOWN"))))

// I64 fields
#define RRR_RAFT_FIELD_CMD             "raft_cmd"
#define RRR_RAFT_FIELD_IS_LEADER       "raft_is_leader"
#define RRR_RAFT_FIELD_STATUS          "raft_status"
#define RRR_RAFT_FIELD_ID              "raft_id"
#define RRR_RAFT_FIELD_LEADER_ID       "raft_leader_id"

// String fields
#define RRR_RAFT_FIELD_LEADER_ADDRESS  "raft_leader_address"

// Blob fields
#define RRR_RAFT_FIELD_SERVER          "raft_server"

struct rrr_array;

// Maximum four bits
enum rrr_raft_code {
	RRR_RAFT_OK = 0,
	RRR_RAFT_ERROR,
	RRR_RAFT_NOT_LEADER,
	RRR_RAFT_ENOENT
};

enum rrr_raft_status {
	RRR_RAFT_STANDBY = 1,
	RRR_RAFT_VOTER,
	RRR_RAFT_SPARE
};

enum rrr_raft_catch_up {
	RRR_RAFT_CATCH_UP_NONE = 0,
	RRR_RAFT_CATCH_UP_RUNNING,
	RRR_RAFT_CATCH_UP_ABORTED,
	RRR_RAFT_CATCH_UP_FINISHED,
	RRR_RAFT_CATCH_UP_UNKNOWN
};

enum rrr_raft_cmd {
	RRR_RAFT_CMD_SERVER_ADD = 1,
	RRR_RAFT_CMD_SERVER_DEL,
	RRR_RAFT_CMD_SERVER_ASSIGN,
	RRR_RAFT_CMD_SERVER_LEADERSHIP_TRANSFER
};

struct rrr_raft_server {
	int64_t id;
	int64_t status;
	int64_t catch_up;
	char address[64];
} __attribute__((packed));

const char *rrr_raft_reason_to_str (
		enum rrr_raft_code code
);
int rrr_raft_opt_array_field_server_get (
		struct rrr_raft_server **result,
		const struct rrr_array *array
);
int rrr_raft_opt_array_field_server_push (
		struct rrr_array *array,
		const struct rrr_raft_server *server
);

#endif /* RRR_RAFT_COMMON_H */
