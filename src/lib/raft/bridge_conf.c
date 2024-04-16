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

#include "bridge.h"
#include "bridge_conf.h"

#include "../allocator.h"

int rrr_raft_bridge_configuration_clone (
		struct raft_configuration *dest,
		const struct raft_configuration *src
) {
	int ret = 0;

	unsigned i, j;
	struct raft_configuration conf;

	assert(dest->servers == NULL && dest->n == 0);

	if ((conf.servers = rrr_allocate(sizeof(*conf.servers) * src->n)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for servers in %s\n", __func__);
		ret = 1;
		goto out;
	}

	for (i = 0; i < src->n; i++) {
		conf.servers[i].id = src->servers[i].id;
		conf.servers[i].role = src->servers[i].role;
		if ((conf.servers[i].address = rrr_strdup(src->servers[i].address)) == NULL) {
			RRR_MSG_0("Failed to allocate memory for server name in %s\n", __func__);
			ret = 1;
			goto out_free_servers;
		}
	}

	conf.n = src->n;

	*dest = conf;

	goto out;
	out_free_servers:
		for (j = 0; j < i; j++) {
			rrr_free(conf.servers[j].address);
		}
		rrr_free(conf.servers);
	out:
		return ret;
}
