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

#ifndef RRR_ALLOCATOR_H
#define RRR_ALLOCATOR_H

#include "rrr_types.h"
#include "../../config.h"

#define RRR_ALLOCATOR_GROUP_MSG_HOLDER  0
#define RRR_ALLOCATOR_GROUP_MSG         1
#define RRR_ALLOCATOR_GROUP_MAX         1

#define RRR_ARENA_SIZE_STEP_MIN (1 * 1024 * 1024) // 1 MB
#define RRR_ARENA_ALIGNMENT     (sizeof(long double))
#define RRR_ARENA_DEBUG

#define RRR_ALLOCATOR_FREE_IF_NOT_NULL(arg) do{if((arg) != NULL){rrr_free(arg);(arg)=NULL;}}while(0)

struct rrr_mmap_stats;

static void *__rrr_allocate_failure (rrr_biglength size) {
	RRR_MSG_0("Cannot allocate memory, too many bytes requested (%llu)\n",
		(unsigned long long) size);
	return NULL;
}

#define VERIFY_SIZE(b)                                            \
	do {if (sizeof(b) > sizeof(size_t) && b > SIZE_MAX) {     \
		return __rrr_allocate_failure(b);                 \
	}} while (0)

#ifdef RRR_WITH_JEMALLOC

#include <stdio.h>
#include <string.h>
#include <jemalloc/jemalloc.h>

#include "log.h"

/* Allocate memory from OS allocator */
static inline void *__rrr_allocate (rrr_biglength bytes) {
	VERIFY_SIZE(bytes);
	return mallocx((size_t) bytes, 0);
}

/* Allocate zeroed memory from OS allocator */
static inline void *__rrr_allocate_zero (rrr_biglength bytes) {
	VERIFY_SIZE(bytes);
	return mallocx((size_t) bytes, MALLOCX_ZERO);
}

/* Allocate memory from group allocator */
static inline void *__rrr_allocate_group (rrr_biglength bytes, size_t group) {
	(void)(group);
	VERIFY_SIZE(bytes);
	return mallocx((size_t) bytes, 0);
}

/* Frees both allocations done by OS allocator and group allocator */
static inline void __rrr_free (void *ptr) {
	free(ptr);
}

static void *__rrr_reallocate_final (void *ptr_old, size_t bytes_old, size_t bytes_new, size_t group_num) {
	(void)(bytes_old);
	(void)(group_num);

	if (ptr_old == NULL) {
		return __rrr_allocate(bytes_new);
	}

	if (bytes_new > 0) {
		return rallocx (ptr_old, bytes_new, 0);
	}

	return ptr_old;
}

/* Caller must ensure that old allocation is done by OS allocator */
static inline void *__rrr_reallocate (void *ptr_old, rrr_biglength bytes_old, rrr_biglength bytes_new) {
	VERIFY_SIZE(bytes_new);
	VERIFY_SIZE(bytes_old);
	return __rrr_reallocate_final(ptr_old, (size_t) bytes_old, (size_t) bytes_new, 0);
}

/* Caller must ensure that old allocation is done by group allocator */
static inline void *__rrr_reallocate_group (void *ptr_old, rrr_biglength bytes_old, rrr_biglength bytes_new, size_t group) {
	VERIFY_SIZE(bytes_new);
	VERIFY_SIZE(bytes_old);
	return __rrr_reallocate_final(ptr_old, (size_t) bytes_old, (size_t) bytes_new, group);
}

/* Duplicate string using OS allocator */
static inline char *__rrr_strdup (const char *str) {
	size_t size = strlen(str) + 1;

	if (size == 0) {
		RRR_MSG_0("Overflow in rrr_strdup\n");
		return NULL;
	}	

	char *result = (char *) __rrr_allocate(size);

	if (result == NULL) {
		return result;
	}

	memcpy(result, str, size);

	return result;
}

#define rrr_allocate(bytes)                                          \
    __rrr_allocate(bytes)

#define rrr_allocate_zero(bytes)                                     \
    __rrr_allocate_zero(bytes)

#define rrr_allocate_group(bytes, group)                             \
    __rrr_allocate_group(bytes, group)

#define rrr_free(ptr)                                                \
    __rrr_free(ptr)

#define rrr_reallocate(ptr_old, bytes_old, bytes_new)                \
    __rrr_reallocate(ptr_old, bytes_old, bytes_new)

#define rrr_reallocate_group(ptr_old, bytes_old, bytes_new, group)   \
    __rrr_reallocate_group(ptr_old, bytes_old, bytes_new, group)

#define rrr_strdup(str)                                              \
    __rrr_strdup(str)

static inline int rrr_allocator_init (void) {
	// Ensure linking with jemalloc is performed in binaries
	free(mallocx(1,0));
	return 0;
}

/* Free all mmaps, caller must ensure that users are no longer active */
static inline void rrr_allocator_cleanup (void) {
	// Nothing to do
}

/* Free unused mmaps */
static inline void rrr_allocator_maintenance (struct rrr_mmap_stats *stats) {
	(void)(stats);
	// Nothing to do
}

static inline void rrr_allocator_maintenance_nostats (void) {
	// Nothing to do
}

#else

#include <stdlib.h>
#include <string.h>

static inline void *rrr_allocate (rrr_biglength bytes) {
	VERIFY_SIZE(bytes);
	return malloc((size_t) bytes);
}

static inline void *rrr_allocate_zero (rrr_biglength bytes) {
	VERIFY_SIZE(bytes);
	void *ptr;
	if ((ptr = malloc((size_t) bytes)) == NULL) {
		return ptr;
	}
	memset(ptr, '\0', (size_t) bytes);
	return ptr;
}

static inline void *rrr_allocate_group (rrr_biglength bytes, size_t group) {
	(void)(group);
	VERIFY_SIZE(bytes);
	return rrr_allocate(bytes);
}

static inline void rrr_free (void *ptr) {
	free(ptr);
}

static inline void *rrr_reallocate (void *ptr_old, rrr_biglength bytes_old, rrr_biglength bytes_new) {
	(void)(bytes_old);
	VERIFY_SIZE(bytes_new);
	return realloc(ptr_old, bytes_new);
}

static inline void *rrr_reallocate_group (void *ptr_old, rrr_biglength bytes_old, rrr_biglength bytes_new, size_t group) {
	(void)(group);
	VERIFY_SIZE(bytes_new);
	VERIFY_SIZE(bytes_old);
	return rrr_reallocate(ptr_old, bytes_old, bytes_new);
}

static inline char *rrr_strdup (const char *str) {
	return strdup(str);
}

static inline int rrr_allocator_init (void) {
	// Nothing to do
	return 0;
}

static inline void rrr_allocator_cleanup (void) {
	// Nothing to do
}

static inline void rrr_allocator_maintenance (struct rrr_mmap_stats *stats) {
	(void)(stats);
	// Nothing to do
}

static inline void rrr_allocator_maintenance_nostats (void) {
	// Nothing to do
}

#endif /* RRR_WITH_JEMALLOC */

struct rrr_arena {
	void *ptr;
	size_t size;
	size_t pos;
	char name[32];
};

int rrr_arena_expand (
		struct rrr_arena *arena,
		size_t size,
		const char *name
);

static inline void *rrr_arena_allocate (
		struct rrr_arena *arena,
		size_t size,
		const char *name
) {
	void *ptr;

	size = (size + RRR_ARENA_ALIGNMENT - 1) & ~(RRR_ARENA_ALIGNMENT - 1);

	if (arena->pos + size > arena->size) {
#ifdef RRR_ARENA_DEBUG
		RRR_MSG_1("Expanding arena %s from %llu to %llu bytes\n",
			arena->name,
			(unsigned long long) arena->size,
			(unsigned long long) arena->size + size);
#endif
		if (rrr_arena_expand(arena, arena->size + size, name) != 0) {
			return NULL;
		}
	}

	ptr = (char *) arena->ptr + arena->pos;
	arena->pos += size;

	return ptr;
}

static inline void rrr_arena_free (
		struct rrr_arena *arena
) {
#ifdef RRR_ARENA_DEBUG
	RRR_MSG_1("Freeing arena %s currently using %llu bytes\n",
		arena->name, (unsigned long long) arena->pos);
#endif
	rrr_free(arena->ptr);
	arena->ptr = NULL;
	arena->size = 0;
	arena->pos = 0;
}

#endif /* RRR_ALLOCATOR_H */
