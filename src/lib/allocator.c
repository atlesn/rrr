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
#include <string.h>
#include <pthread.h>

#include "allocator.h"
#include "rrr_mmap.h"
#include "log.h"

#define RRR_DEFAULT_ALLOCATOR_MMAP_SIZE 256 * 1024 /* 256 kB */

struct rrr_allocator_group {
	pthread_rwlock_t index_lock;
	pthread_mutex_t mmap_lock;
	struct rrr_mmap_collection collection;
};

#define RRR_ALLOCATOR_GROUP_INIT {  \
	PTHREAD_RWLOCK_INITIALIZER, \
	PTHREAD_MUTEX_INITIALIZER,  \
	{0}                         \
	}                           \

static struct rrr_allocator_group rrr_allocator_groups[2] = {
	RRR_ALLOCATOR_GROUP_INIT,
	RRR_ALLOCATOR_GROUP_INIT
};

static void *__rrr_allocate (size_t bytes, int group_num) {
	struct rrr_allocator_group *group = &rrr_allocator_groups[group_num];

	void *ptr = rrr_mmap_collection_allocate (
			&group->collection,
			bytes,
			RRR_DEFAULT_ALLOCATOR_MMAP_SIZE,
			&group->index_lock,
			&group->mmap_lock,
			"rrr_allocate()",
			0 // Not shared
	);

//	printf("Allocate %p\n", ptr);

	return ptr;
}

void *rrr_allocate (size_t bytes) {
	return __rrr_allocate(bytes, RRR_ALLOCATOR_GROUP_DEFAULT);
}

void *rrr_allocate_group (size_t bytes, int group) {
	return __rrr_allocate(bytes, group);
}

void rrr_free (void *ptr) {
//	printf("Free %p\n", ptr);

	int ret = 0;

	ret = rrr_mmap_collection_free (
			&rrr_allocator_groups[0].collection,
			&rrr_allocator_groups[0].index_lock,
			ptr
	);

	if (ret == 0) {
		return;
	}

	ret = rrr_mmap_collection_free (
			&rrr_allocator_groups[1].collection,
			&rrr_allocator_groups[1].index_lock,
			ptr
	);

	if (ret != 0) {
		RRR_BUG("BUG: Invalid free of %p in rrr_free\n", ptr);
	}
}

static void *__rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new, int group_num) {
	struct rrr_allocator_group *group = &rrr_allocator_groups[group_num];

	void *ptr_new = NULL;

	if (bytes_new > 0) {
		ptr_new = rrr_mmap_collection_allocate (
				&group->collection,
				bytes_new,
				RRR_DEFAULT_ALLOCATOR_MMAP_SIZE,
				&group->index_lock,
				&group->mmap_lock,
				"rrr_allocate()",
				0 // Not shared
		);

		if (ptr_new == NULL) {
			return NULL;
		}
	}

	if (ptr_old != NULL) {
		memcpy(ptr_new, ptr_old, bytes_old);
		rrr_free(ptr_old);
	}

	return ptr_new;
}

void *rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new) {
	return __rrr_reallocate(ptr_old, bytes_old, bytes_new, RRR_ALLOCATOR_GROUP_DEFAULT);
}

void *rrr_reallocate_group (void *ptr_old, size_t bytes_old, size_t bytes_new, int group) {
	return __rrr_reallocate(ptr_old, bytes_old, bytes_new, group);
}

char *rrr_strdup (const char *str) {
	size_t size = strlen(str) + 1;

	char *result = rrr_allocate(size);

	if (result == NULL) {
		return result;
	}

	memcpy(result, str, size);

	return result;
}

void rrr_allocator_cleanup (void) {
	rrr_mmap_collection_clear(&rrr_allocator_groups[0].collection, &rrr_allocator_groups[0].index_lock);
	rrr_mmap_collection_clear(&rrr_allocator_groups[1].collection, &rrr_allocator_groups[1].index_lock);
}

void rrr_allocator_maintenance (void) {
	rrr_mmap_collection_maintenance(&rrr_allocator_groups[0].collection, &rrr_allocator_groups[0].index_lock);
	rrr_mmap_collection_maintenance(&rrr_allocator_groups[1].collection, &rrr_allocator_groups[1].index_lock);
}
