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

#include <libpq-fe.h>

#include "log.h"
#include "allocator.h"

#include "pg.h"

struct rrr_pg_conn {
	PGconn *conn;
};

int rrr_pg_new (
		struct rrr_pg_conn **result,
		const char *host,
		const char *port,
		const char *db,
		const char *user,
		const char *pass
) {
	const char *keywords[6] = {
		"host",
		"port",
		"dbname",
		"user",
		"password",
		NULL
	};

	const char *values[6] = {
		host,
		port,
		db,
		user,
		pass,
		NULL
	};

	int ret = 0;

	struct rrr_pg_conn *conn;
	ConnStatusType status;

	if ((conn = rrr_allocate (sizeof (*conn))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for pg connection in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((conn->conn = PQconnectdbParams (keywords, values, 0)) == NULL) {
		RRR_MSG_0("Failed to connect to PostgreSQL database in %s (connect returned NULL)\n", __func__);
		ret = 1;
		goto out;
	}

	if ((status = PQstatus (conn->conn)) != CONNECTION_OK) {
		RRR_MSG_0("Failed to connect to PostgreSQL database in %s: %s\n", __func__, PQerrorMessage (conn->conn));
		ret = 1;
		goto out_free;
	}

	*result = conn;

	goto out;
	out_free:
		rrr_free(conn);
	out:
		return ret;
}

void rrr_pg_destroy (
		struct rrr_pg_conn *conn
) {
	PQfinish (conn->conn);
	rrr_free (conn);
}

int rrr_pg_check (
		struct rrr_pg_conn *conn
) {
	ConnStatusType status;

	if ((status = PQstatus (conn->conn)) != CONNECTION_OK) {
		return 1;
	}

	return 0;
}
