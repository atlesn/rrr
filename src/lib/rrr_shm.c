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

#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>

#include "log.h"
#include "rrr_shm_struct.h"
#include "util/posix.h"
#include "util/linked_list.h"
#include "allocator.h"
#include "rrr_strerror.h"
#include "rrr_shm.h"
#include "rrr_mmap.h"
#include "random.h"

// printf debugging
// #define RRR_SHM_DEBUG 1

struct rrr_shm_holder {
	RRR_LL_NODE(struct rrr_shm_holder);
	char filename[32];
};

struct rrr_shm_holder_collection {
	RRR_LL_HEAD(struct rrr_shm_holder);
};

static pthread_mutex_t shm_holders_lock = PTHREAD_MUTEX_INITIALIZER;
static struct rrr_shm_holder_collection shm_holders = {0};

static void __rrr_shm_holder_destroy (
		struct rrr_shm_holder *holder
) {
	shm_unlink(holder->filename);
	free(holder);
}

static void __rrr_shm_holder_unregister_and_unlink (
		const char *filename
) {
	pthread_mutex_lock(&shm_holders_lock);
	RRR_LL_ITERATE_BEGIN(&shm_holders, struct rrr_shm_holder);
		if (strcmp(node->filename, filename) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&shm_holders, 0; __rrr_shm_holder_destroy(node));
	pthread_mutex_unlock(&shm_holders_lock);
}

// Call in child after forking
void rrr_shm_holders_reset (void) {
	pthread_mutex_lock(&shm_holders_lock);
	RRR_LL_ITERATE_BEGIN(&shm_holders, struct rrr_shm_holder);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&shm_holders, 0; free(node) /* Don't use destroy, free only */ );
	pthread_mutex_unlock(&shm_holders_lock);
}

static int __rrr_shm_holder_register (
		const char *filename
) {
	// Use only raw malloc/free in the holder functions to avoid
	// that rrr_freecalls back into the SHM framework causing deadlock

	struct rrr_shm_holder *holder = malloc(sizeof(*holder));
	if (holder == NULL) {
		RRR_MSG_0("Failed to allocate memory in __rrr_shm_holder_register\n");
		return 1;
	}

	memset(holder, '\0', sizeof(*holder));

	if (strlen(filename) > sizeof(holder->filename) - 1) {
		RRR_BUG("BUG: Filename exceeds maximum length in rrr_shm_holder_register\rrr_shm_collection_slave_new");
	}

	strcpy(holder->filename, filename);

	pthread_mutex_lock(&shm_holders_lock);
	RRR_LL_APPEND(&shm_holders, holder);
	pthread_mutex_unlock(&shm_holders_lock);

	return 0;
}

void rrr_shm_holders_cleanup (void) {
	pthread_mutex_lock(&shm_holders_lock);
	RRR_LL_ITERATE_BEGIN(&shm_holders, struct rrr_shm_holder);
		RRR_MSG_0("Warning: SHM %s late cleanup\n", node->filename);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&shm_holders, 0; __rrr_shm_holder_destroy(node));
	pthread_mutex_unlock(&shm_holders_lock);
}

static int __rrr_shm_open (
		int *fd,
		const char *name
) {
	int fd_tmp;

	*fd = 0;

	if ((fd_tmp = shm_open(name, O_RDWR, S_IRUSR|S_IWUSR)) < 0) {
		RRR_MSG_0("shm_open failed in __rrr_shm_open: %s\n", rrr_strerror(errno));
		return 1;
	}

	*fd = fd_tmp;

	return 0;
}

static int __rrr_shm_open_create (
		int *fd,
		char *name,
		size_t name_size,
		size_t size
) {
	int ret = 0;

	*fd = 0;

	int fd_tmp = 0;
	do {
		rrr_random_string(name, name_size);

		name[0] = '/';

		if ((fd_tmp = shm_open(name, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) < 0) {
			if (errno != EEXIST) {
				RRR_MSG_0("shm_open failed in __rrr_shm_open_create: %s\n", rrr_strerror(errno));
				ret = 1;
				goto out;
			}
			// Try another name
		}

	} while(fd_tmp <= 0);

	if (ftruncate (fd_tmp, (off_t) size) != 0) {
		RRR_MSG_0("ftruncate size %llu failed in __rrr_shm_open_create: %s\n", (long long unsigned) size, rrr_strerror(errno));
		goto out_close;
	}

	if ((ret = __rrr_shm_holder_register (name)) != 0) {
		RRR_MSG_0("Failed to register SHM in __rrr_shm_open_create\n");
		goto out_close;
	}

	*fd = fd_tmp;

	goto out;
	out_close:
		close(fd_tmp);
		shm_unlink(name);
	out:
		return ret;
}

static int __rrr_shm_create (struct rrr_shm *shm, size_t data_size) {
	int ret = 0;

	int fd_tmp = 0;
	if ((ret = __rrr_shm_open_create (&fd_tmp, shm->name, sizeof(shm->name), data_size)) != 0) {
		goto out;
	}

	shm->data_size = data_size;
	shm->version_ptr++;

	close(fd_tmp);

	out:
	return ret;
}

static void *__rrr_shm_mmap (const struct rrr_shm *shm) {
	void *ptr = NULL;

	int fd_tmp = 0;
	if (__rrr_shm_open (&fd_tmp, shm->name) != 0) {
		goto out;
	}

	if ((ptr = rrr_posix_mmap_with_fd(fd_tmp, shm->data_size)) == NULL) {
		RRR_MSG_0("mmap failed in rrr_shm_mmap: %s\n", rrr_strerror(errno));
		goto out_close;
	}

	close(fd_tmp);

	goto out;
	out_close:
		close(fd_tmp);
	out:
		return ptr;
}

static void __rrr_shm_cleanup (struct rrr_shm *shm) {
	__rrr_shm_holder_unregister_and_unlink(shm->name);

	shm->name[0] = '\0';
	shm->data_size = 0;

	shm->version_ptr++;
}

static void __rrr_shm_ptr_cleanup_if_not_null (
		struct rrr_shm_ptr *ptr
) {
	if (ptr->ptr != NULL) {
		munmap(ptr->ptr, ptr->data_size);
		ptr->data_size = 0;
		ptr->ptr = NULL;
	}
}

static int __rrr_shm_ptr_update (
		struct rrr_shm_ptr *target,
		const struct rrr_shm *source
) {
	__rrr_shm_ptr_cleanup_if_not_null(target);

	if (source->data_size != 0) {
		if ((target->ptr = __rrr_shm_mmap(source)) == NULL) {
			return 1;
		}
		target->data_size = source->data_size;
	}

	target->version_ptr = source->version_ptr;

	return 0;
}

void rrr_shm_collection_slave_reset (
		struct rrr_shm_collection_slave *slave,
		struct rrr_shm_collection_master *master
) {
	memset(slave, '\0', sizeof(*slave));

	slave->master = master;

	pthread_rwlock_rdlock(&master->lock);
	slave->version_master = master->version_master - 1;
	pthread_rwlock_unlock(&master->lock);
}

void rrr_shm_collection_slave_cleanup (
		struct rrr_shm_collection_slave *slave
) {
	for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {
		__rrr_shm_ptr_cleanup_if_not_null (&slave->ptrs[i]);
	}
}

int rrr_shm_collection_slave_new (
		struct rrr_shm_collection_slave **target,
		struct rrr_shm_collection_master *master
) {
	int ret = 0;

	struct rrr_shm_collection_slave *slave = rrr_allocate_zero (sizeof(*slave));
	if (slave == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_shm_collection_slave_new\n");
		ret = 1;
		goto out;
	}

	slave->master = master;

	pthread_rwlock_rdlock(&slave->master->lock);
	slave->version_master = master->version_master - 1;
	pthread_rwlock_unlock(&slave->master->lock);

	*target = slave;

	out:
	return ret;
}

void rrr_shm_collection_slave_destroy (
		struct rrr_shm_collection_slave *slave
) {
	rrr_shm_collection_slave_cleanup(slave);
	rrr_free(slave);
}

int rrr_shm_collection_master_new (
		struct rrr_shm_collection_master **target
) {
	int ret = 0;

	struct rrr_shm_collection_master *collection;

	if ((collection = rrr_posix_mmap(sizeof(*collection), 1 /* Is shared */)) == NULL) {
		RRR_MSG_0("mmap failed in rrr_shm_collection_master_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_posix_rwlock_init (&collection->lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Failed to initialize mutex in rrr_shm_collection_master_new\n");
		goto out_munmap;
	}

	memset(collection, '\0', sizeof(*collection));

	*target = collection;

	goto out;
	out_munmap:
		munmap(collection, sizeof(*collection));
	out:
		return ret;
}

#define RRR_SHM_COLLECTION_MASTER_ITERATE_BEGIN()                            \
	do {for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {            \
		struct rrr_shm *shm = &collection->elements[i]; (void)(shm) 

#define RRR_SHM_COLLECTION_MASTER_ITERATE_END()                              \
	}} while(0)
	
#define RRR_SHM_COLLECTION_MASTER_ITERATE_ACTIVE_BEGIN()                     \
	RRR_SHM_COLLECTION_MASTER_ITERATE_BEGIN();                           \
		if (shm->data_size != 0) { (void)(shm)

#define RRR_SHM_COLLECTION_MASTER_ITERATE_ACTIVE_END()                       \
	} RRR_SHM_COLLECTION_MASTER_ITERATE_END()

#define RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_BEGIN()                   \
	RRR_SHM_COLLECTION_MASTER_ITERATE_BEGIN();                           \
		if (shm->data_size == 0) { (void)(shm)

#define RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_END()                     \
	} RRR_SHM_COLLECTION_MASTER_ITERATE_END()

void rrr_shm_collection_master_destroy (
		struct rrr_shm_collection_master *collection
) {
	RRR_SHM_COLLECTION_MASTER_ITERATE_ACTIVE_BEGIN();
		__rrr_shm_cleanup(shm);
	RRR_SHM_COLLECTION_MASTER_ITERATE_ACTIVE_END();
	pthread_rwlock_destroy(&collection->lock);
	munmap(collection, sizeof(*collection));
}

void rrr_shm_collection_master_free (
		struct rrr_shm_collection_master *collection,
		rrr_shm_handle handle
) {
	pthread_rwlock_wrlock(&collection->lock);

	if (collection->elements[handle].data_size == 0) {
		RRR_BUG("BUG: Double free in rrr_shm_collection_master_free\n");
	}
	__rrr_shm_cleanup(&collection->elements[handle]);

	collection->version_master++;

	pthread_rwlock_unlock(&collection->lock);
}

int rrr_shm_collection_master_allocate (
		rrr_shm_handle *handle,
		struct rrr_shm_collection_master *collection,
		size_t data_size
) {
	int ret = 1; /* Allocation failed */

	pthread_rwlock_wrlock(&collection->lock);

	RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_BEGIN();
		if ((ret = __rrr_shm_create(shm, data_size)) != 0) {
			goto out;
		}
	
#ifdef RRR_SHM_DEBUG
		printf("shm %lu %p allocate\n", i, collection);
#endif

		*handle = i;
		collection->version_master++;

		ret = 0;

		break;
	RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_END();

	out:
	pthread_rwlock_unlock(&collection->lock);
	return ret;
}

static int __rrr_shm_slave_refresh_if_needed (
		struct rrr_shm_collection_slave *slave
) {
	int ret = 0;

	pthread_rwlock_rdlock(&slave->master->lock);

	if (slave->version_master == slave->master->version_master) {
		goto out;
	}

	for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {
		if (slave->ptrs[i].version_ptr != slave->master->elements[i].version_ptr) {
#ifdef RRR_SHM_DEBUG
			printf("shm %lu update\n", i);
#endif
			if ((ret = __rrr_shm_ptr_update(&slave->ptrs[i], &slave->master->elements[i])) != 0) {
				goto out;
			}
		}
	}

	slave->version_master = slave->master->version_master;

	out:
	pthread_rwlock_unlock(&slave->master->lock);
	return ret;
}

int rrr_shm_access (
		struct rrr_shm_collection_slave *slave,
		rrr_shm_handle handle,
		int (*callback)(void *ptr, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if ((ret = __rrr_shm_slave_refresh_if_needed(slave)) != 0) {
		goto out;
	}

	if (slave->ptrs[handle].ptr == NULL) {
		RRR_MSG_0("Invalid handle %llu in rrr_shm_access, not allocated by master\n",
				(long long unsigned) handle);
		ret = 1;
		goto out;
	}

#ifdef RRR_SHM_DEBUG
	printf("shm %lu %p resolve %p\n", handle, slave->master, slave->ptrs[handle].ptr);
#endif

	ret = callback(slave->ptrs[handle].ptr, callback_arg);

	out:
	return ret;
}

void *rrr_shm_resolve (
		struct rrr_shm_collection_slave *slave,
		rrr_shm_handle handle
) {
	int ret = 0;

	if ((ret = __rrr_shm_slave_refresh_if_needed(slave)) != 0) {
		return NULL;
	}

	if (slave->ptrs[handle].ptr == NULL) {
		RRR_MSG_0("Invalid handle %llu in rrr_shm_resolve, not allocated by master\n",
				(long long unsigned) handle);
		return NULL;
	}

#ifdef RRR_SHM_DEBUG
	printf("shm %lu %p resolve %p\n", handle, slave->master, slave->ptrs[handle].ptr);
#endif

	return slave->ptrs[handle].ptr;
}

int rrr_shm_resolve_reverse (
		rrr_shm_handle *handle,
		struct rrr_shm_collection_slave *slave,
		const void *ptr
) {
	if (__rrr_shm_slave_refresh_if_needed(slave) != 0) {
		return 1;
	}
	for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {
		if (slave->ptrs[i].ptr == ptr) {
			*handle = i;
			return 0;
		}
	}
	return 1;
}
