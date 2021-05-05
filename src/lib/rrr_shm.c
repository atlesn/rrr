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
#include "util/posix.h"
#include "allocator.h"
#include "rrr_strerror.h"
#include "rrr_shm.h"
#include "rrr_mmap.h"
#include "random.h"

#define RRR_SHM_COLLECTION_MAX 192

struct rrr_shm {
	char name[8];
	size_t data_size;
};

struct rrr_shm_ptr {
	void *ptr;
	size_t data_size;
};

struct rrr_shm_collection_master {
	unsigned int version;
	struct rrr_shm elements[RRR_SHM_COLLECTION_MAX];
	pthread_mutex_t lock;
};

struct rrr_shm_collection_slave {
	struct rrr_shm_collection_master *master;
	unsigned int version;
	struct rrr_shm_ptr ptrs[RRR_SHM_COLLECTION_MAX];
};

static int __rrr_shm_open (
		int *fd,
		const char *name
) {
	int fd_tmp;

	*fd = 0;

	if ((fd_tmp = shm_open(name, O_RDWR, S_IRUSR|S_IWUSR)) != 0) {
		RRR_MSG_0("shm_open failed in __rrr_shm_open: %s\n", rrr_strerror(errno));
		return 1;
	}

	*fd = fd_tmp;

	return 0;
}

static int __rrr_shm_open_create (
		int *fd,
		char *name,
		size_t name_size
) {
	int fd_tmp = 0;

	*fd = 0;

	do {
		rrr_random_string(name, name_size);

		name[0] = '/';

		if ((fd_tmp = shm_open(name, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) != 0) {
			if (errno != EEXIST) {
				RRR_MSG_0("shm_open failed in __rrr_shm_open_create: %s\n", rrr_strerror(errno));
				return 1;
			}
			// Try another name
		}

	} while(fd_tmp <= 0);

	*fd = fd_tmp;

	return 0;
}

static void *__rrr_shm_create_and_mmap (struct rrr_shm *shm, size_t data_size) {
	void *ptr = NULL;

	int fd_tmp = 0;
	if (__rrr_shm_open_create (&fd_tmp, shm->name, sizeof(shm->name)) != 0) {
		goto out;
	}

	if ((ptr = rrr_posix_mmap_with_fd(fd_tmp, data_size)) == NULL) {
		RRR_MSG_0("mmap failed in rrr_shm_create_and_mmap: %s\n", rrr_strerror(errno));
		goto out_close;
	}

	shm->data_size = data_size;

	close(fd_tmp);

	goto out;
	out_close:
		close(fd_tmp);
		shm_unlink(shm->name);
	out:
		return ptr;
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
	shm_unlink(shm->name);
	memset(shm, '\0', sizeof(*shm));
}

static void __rrr_shm_ptr_cleanup_if_not_null (
		struct rrr_shm_ptr *ptr
) {
	if (ptr->ptr != NULL) {
		munmap(ptr->ptr, ptr->data_size);
	}
	ptr->ptr = 0;
	ptr->data_size = 0;
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

	return 0;
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

	pthread_mutex_lock(&slave->master->lock);
	slave->version = master->version - 1;
	pthread_mutex_unlock(&slave->master->lock);

	*target = slave;

	out:
	return ret;
}

void rrr_shm_collection_slave_destroy (
		struct rrr_shm_collection_slave *slave
) {
	for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {
		__rrr_shm_ptr_cleanup_if_not_null (&slave->ptrs[i]);
	}
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

	if ((ret = rrr_posix_mutex_init (&collection->lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
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
	pthread_mutex_destroy(&collection->lock);
	munmap(collection, sizeof(*collection));
}

int rrr_shm_collection_master_allocate (
		rrr_shm_handle *handle,
		struct rrr_shm_collection_master *collection,
		size_t data_size
) {
	int ret = 1; /* Allocation failed */

	pthread_mutex_lock(&collection->lock);

	RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_BEGIN();
		void *ptr;
		if ((ptr = __rrr_shm_create_and_mmap(shm, data_size)) == NULL) {
			goto out;
		}

		*handle = i;
		collection->version++;

		ret = 0;

		break;
	RRR_SHM_COLLECTION_MASTER_ITERATE_INACTIVE_END();

	out:
	pthread_mutex_unlock(&collection->lock);
	return ret;
}

static int __rrr_shm_slave_refresh_if_needed (
		struct rrr_shm_collection_slave *slave
) {
	int ret = 0;

	pthread_mutex_lock(&slave->master->lock);

	if (slave->version == slave->master->version) {
		goto out;
	}

	for (size_t i = 0; i < RRR_SHM_COLLECTION_MAX; i++) {
		if ((ret = __rrr_shm_ptr_update(&slave->ptrs[i], &slave->master->elements[i])) != 0) {
			goto out;
		}
	}

	slave->version = slave->master->version;

	out:
	pthread_mutex_unlock(&slave->master->lock);
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

	ret = callback(slave->ptrs[handle].ptr, callback_arg);

	out:
	return ret;
}
