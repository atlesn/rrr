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

#include "allocator.h"

#define RRR_WITH_MMAP_ALLOCATOR

#ifdef RRR_WITH_MMAP_ALLOCATOR

/*

The RRR Allocator (RRRA)

   The goal is to separate message allocations from other allocations,
   increasing the chance of having pages containing only messages thus
   allowing them to be returned to the OS as messages are done.

   The allocator may be disabled by commenting out the #define above. This
   may increase program speed, but memory usage may grow over time.

   For messages, different allocation groups exist for different allocation
   types. Allocations are not put into different groups according to size.

   The function rrr_free() is used for all frees, regardless of how memory
   was allocated. The correct method of freeing will be detected.

   A limited amount of memory is available for message. The program will
   restart if this limit is reached.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "log.h"
#include "rrr_mmap.h"
#include "rrr_mmap_stats.h"
#include "rrr_shm_struct.h"

/* Size for new MMAPs. A collection contains multiple MMAPs. */
#define RRR_DEFAULT_ALLOCATOR_MMAP_SIZE 16 * 1024 * 1024 /* 16 MB */

static struct rrr_mmap_collection *rrr_allocator_collections = NULL;
static struct rrr_mmap_collection_private_data rrr_allocator_private_datas[RRR_ALLOCATOR_GROUP_MAX + 1];

static void *__rrr_allocate (size_t bytes, size_t group_num) {
	void *ptr = rrr_mmap_collections_allocate (
			rrr_allocator_collections,
			group_num,
			bytes,
			bytes > RRR_DEFAULT_ALLOCATOR_MMAP_SIZE
				? bytes
				: RRR_DEFAULT_ALLOCATOR_MMAP_SIZE
	);

	return ptr;
}

/* Allocate memory from OS allocator */
void *rrr_allocate (size_t bytes) {
	return malloc(bytes);
}

/* Allocate zeroed memory from OS allocator */
void *rrr_allocate_zero (size_t bytes) {
	void *ret = malloc(bytes);
	if (ret) {
		memset(ret, '\0', bytes);
	}
	return ret;
}

/* Allocate memory from group allocator */
void *rrr_allocate_group (size_t bytes, size_t group) {
	return __rrr_allocate(bytes, group);
}

/* Frees both allocations done by OS allocator and group allocator */
void rrr_free (void *ptr) {
	if (rrr_mmap_collections_free (
			rrr_allocator_private_datas,
			RRR_ALLOCATOR_GROUP_MAX + 1,
			ptr
	) == 0) {
		return;
	}

	// Not part of any mmap, use libc free
	free(ptr);
}

static void *__rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new, size_t group_num) {
	void *ptr_new = NULL;

	if (bytes_new > 0) {
		ptr_new = rrr_mmap_collections_allocate (
				rrr_allocator_collections,
				group_num,
				bytes_new,
				RRR_DEFAULT_ALLOCATOR_MMAP_SIZE
		);
	}

	if (ptr_old != NULL && ptr_new != NULL) {
		memcpy(ptr_new, ptr_old, bytes_old);
		rrr_free(ptr_old);
	}

	return ptr_new;
}

/* Caller must ensure that old allocation is done by OS allocator */
void *rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new) {
	(void)(bytes_old);
	return realloc(ptr_old, bytes_new);
}

/* Caller must ensure that old allocation is done by group allocator */
void *rrr_reallocate_group (void *ptr_old, size_t bytes_old, size_t bytes_new, size_t group) {
	return __rrr_reallocate(ptr_old, bytes_old, bytes_new, group);
}

/* Duplicate string using OS allocator */
char *rrr_strdup (const char *str) {
	size_t size = strlen(str) + 1;

	char *result = rrr_allocate(size);

	if (result == NULL) {
		return result;
	}

	memcpy(result, str, size);

	return result;
}

int rrr_allocator_init (void) {
	if (rrr_mmap_collections_new (
			&rrr_allocator_collections,
			RRR_ALLOCATOR_GROUP_MAX + 1,
			0 /* Not pshared */,
			"allocator"
	) != 0) {
		return 1;
	}
	rrr_mmap_collection_private_datas_init (
			rrr_allocator_private_datas,
			rrr_allocator_collections,
			RRR_ALLOCATOR_GROUP_MAX + 1
	);
	return 0;
}

/* Free all mmaps, caller must ensure that users are no longer active */
void rrr_allocator_cleanup (void) {
	rrr_mmap_collections_destroy (
			rrr_allocator_collections,
			RRR_ALLOCATOR_GROUP_MAX + 1
	);
	rrr_allocator_collections = NULL;
}

/* Free unused mmaps */
void rrr_allocator_maintenance (struct rrr_mmap_stats *stats) {
	rrr_mmap_collections_maintenance (
			stats,
			rrr_allocator_collections,
			RRR_ALLOCATOR_GROUP_MAX + 1
	);
}

void rrr_allocator_maintenance_nostats (void) {
	struct rrr_mmap_stats stats_dummy;
	rrr_allocator_maintenance(&stats_dummy);
}

#else

#include <stdlib.h>
#include <string.h>

void *rrr_allocate (size_t bytes) {
	return malloc(bytes);
}

void *rrr_allocate_group (size_t bytes, size_t group) {
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

void *rrr_reallocate_group (void *ptr_old, size_t bytes_old, size_t bytes_new, size_t group) {
	(void)(group);
	return rrr_reallocate(ptr_old, bytes_old, bytes_new);
}

char *rrr_strdup (const char *str) {
	return strdup(str);
}

int rrr_allocator_init (void) {
	// Nothing to do
	return 0;
}

void rrr_allocator_cleanup (void) {
	// Nothing to do
}

void rrr_allocator_maintenance (struct rrr_mmap_stats *stats) {
	(void)(stats);
	// Nothing to do
}

void rrr_allocator_maintenance_nostats (void) {
	// Nothing to do
}

#endif /* RRR_WITH_MMAP_ALLOCATOR */
