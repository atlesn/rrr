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

#ifndef RRR_PG_H
#define RRR_PG_H

struct rrr_pg_conn;

int rrr_pg_new (
		struct rrr_pg_conn **result,
		const char *host,
		const char *port,
		const char *db,
		const char *user,
		const char *pass
);
void rrr_pg_destroy (
		struct rrr_pg_conn *conn
);
int rrr_pg_check (
		struct rrr_pg_conn *conn
);

#endif /* RRR_PG_H */
