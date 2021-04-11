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

#include "../../config.h"
#include "allocator.h"

#define RRR_WITH_MMAP_ALLOCATOR

#ifdef RRR_WITH_MMAP_ALLOCATOR

/*

The RRR Experimental and Very Slow Allocator (RRRVSA)

   The goal is to separate message
   message allocations from other allocations, increasing the chance of
   having pages only containing messages thus allowing pages to be returned
   to the OS as messages are done
 
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "log.h"
#include "rrr_mmap.h"

#define RRR_DEFAULT_ALLOCATOR_MMAP_SIZE 16 * 1024 * 1024 /* 16 MB */

struct rrr_allocator_group {
	pthread_rwlock_t index_lock;
};

#define RRR_ALLOCATOR_GROUP_INIT {  \
	PTHREAD_RWLOCK_INITIALIZER, \
	}                           \

static struct rrr_allocator_group rrr_allocator_groups[2] = {
	RRR_ALLOCATOR_GROUP_INIT,
	RRR_ALLOCATOR_GROUP_INIT
};

static struct rrr_mmap_collection rrr_allocator_collections[2] = {0};

static void *__rrr_allocate (size_t bytes, int group_num) {
	void *ptr = rrr_mmap_collection_allocate (
			&rrr_allocator_collections[group_num],
			bytes,
			RRR_DEFAULT_ALLOCATOR_MMAP_SIZE,
			&rrr_allocator_groups[group_num].index_lock,
			0 // Not shared
	);

//	printf("Allocate %p\n", ptr);

	return ptr;
}

void *rrr_allocate (size_t bytes) {
	return malloc(bytes);
//	return __rrr_allocate(bytes, RRR_ALLOCATOR_GROUP_DEFAULT);
}

void *rrr_allocate_group (size_t bytes, int group) {
	return __rrr_allocate(bytes, group);
}

void rrr_free (void *ptr) {
//	printf("Free %p\n", ptr);

	int ret = 0;

	ret = rrr_mmap_collection_free (
			&rrr_allocator_collections[0],
			&rrr_allocator_groups[0].index_lock,
			ptr
	);

	if (ret == 0) {
		return;
	}

	ret = rrr_mmap_collection_free (
			&rrr_allocator_collections[1],
			&rrr_allocator_groups[1].index_lock,
			ptr
	);

	if (ret == 0) {
		return; //RRR_BUG("BUG: Invalid free of %p in rrr_free\n", ptr);
	}

	free(ptr);
}

static void *__rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new, int group_num) {
	void *ptr_new = NULL;

	if (bytes_new > 0) {
		ptr_new = rrr_mmap_collection_allocate (
				&rrr_allocator_collections[group_num],
				bytes_new,
				RRR_DEFAULT_ALLOCATOR_MMAP_SIZE,
				&rrr_allocator_groups[group_num].index_lock,
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
	(void)(bytes_old);
	return realloc(ptr_old, bytes_new);
	//return __rrr_reallocate(ptr_old, bytes_old, bytes_new, RRR_ALLOCATOR_GROUP_DEFAULT);
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
	rrr_mmap_collection_clear(&rrr_allocator_collections[0], &rrr_allocator_groups[0].index_lock);
	rrr_mmap_collection_clear(&rrr_allocator_collections[1], &rrr_allocator_groups[1].index_lock);
}

void rrr_allocator_maintenance (void) {
	rrr_mmap_collection_maintenance(&rrr_allocator_collections[0], &rrr_allocator_groups[0].index_lock);
	rrr_mmap_collection_maintenance(&rrr_allocator_collections[1], &rrr_allocator_groups[1].index_lock);
}

#else

#ifdef RRR_HAVE_JEMALLOC
#	include <jemalloc/jemalloc.h>
#else
#	include <stdlib.h>
#endif

#include <string.h>

void *rrr_allocate (size_t bytes) {
	return malloc(bytes);
}

void *rrr_allocate_group (size_t bytes, int group) {
	(void)(group);
	return rrr_allocate(bytes);
}

void rrr_free (void *ptr) {
	free(ptr);
}

void *rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new) {
	(void)(bytes_old);
	return realloc(ptr_old, bytes_new);
}

void *rrr_reallocate_group (void *ptr_old, size_t bytes_old, size_t bytes_new, int group) {
	(void)(group);
	return rrr_reallocate(ptr_old, bytes_old, bytes_new);
}

char *rrr_strdup (const char *str) {
	return strdup(str);
}

void rrr_allocator_cleanup (void) {
	// Nothing to do
}

void rrr_allocator_maintenance (void) {
	// Nothing to do
}

#endif /* RRR_WITH_MMAP_ALLOCATOR */
