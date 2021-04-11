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

#include <stdio.h>
#include <pthread.h>

#include "allocator.h"
#include "rrr_mmap.h"

#define RRR_DEFAULT_ALLOCATOR_MMAP_SIZE 512 * 1024 /* 512 kB */

static pthread_rwlock_t rrr_allocator_index_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t rrr_allocator_mmap_lock = PTHREAD_MUTEX_INITIALIZER;

static struct rrr_mmap_collection rrr_allocator_mmap_collection = {0};

void *rrr_allocate (size_t bytes) {
	void *ptr = rrr_mmap_collection_allocate (
			&rrr_allocator_mmap_collection,
			bytes,
			RRR_DEFAULT_ALLOCATOR_MMAP_SIZE,
			&rrr_allocator_index_lock,
			&rrr_allocator_mmap_lock,
			"rrr_allocate()"
	);

//	printf("Allocate %p\n", ptr);

	return ptr;
}

void rrr_free (void *ptr) {
//	printf("Free %p\n", ptr);
	rrr_mmap_collection_free (
			&rrr_allocator_mmap_collection,
			&rrr_allocator_index_lock,
			ptr
	);
}

void rrr_allocator_cleanup (void) {
	rrr_mmap_collection_clear(&rrr_allocator_mmap_collection);
}

void rrr_allocator_maintenance (void) {
	rrr_mmap_collection_maintenance(&rrr_allocator_mmap_collection, &rrr_allocator_index_lock);
}
