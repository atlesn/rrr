/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SHM_H
#define RRR_SHM_H

#include <stddef.h>

typedef size_t rrr_shm_handle;

struct rrr_shm_collection_master;
struct rrr_shm_collection_slave;

int rrr_shm_collection_slave_new (
		struct rrr_shm_collection_slave **target,
		struct rrr_shm_collection_master *master
);
void rrr_shm_collection_slave_destroy (
		struct rrr_shm_collection_slave *slave
);
void rrr_shm_collection_master_destroy (
		struct rrr_shm_collection_master *collection
);
int rrr_shm_collection_master_allocate (
		rrr_shm_handle *handle,
		struct rrr_shm_collection_master *collection,
		size_t data_size
);
int rrr_shm_access (
		struct rrr_shm_collection_slave *slave,
		rrr_shm_handle handle,
		int (*callback)(void *ptr, void *arg),
		void *callback_arg
);

#endif /* RRR_SHM_H */
