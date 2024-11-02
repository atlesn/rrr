/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <string.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/rrr_shm.h"
#include "../lib/rrr_shm_struct.h"
#include "../lib/fork.h"
#include "../lib/util/posix.h"
#include "test.h"
#include "test_allocator.h"

static void __rrr_test_allocator_shm_child_exit_notify (pid_t pid, void *arg) {
	(void)(arg);
	(void)(pid);
	RRR_DBG_1("SHM test fork has exited\n");
}

static int __rrr_test_allocator_shm(struct rrr_fork_handler *fork_handler) {
	int ret = 0;

	struct rrr_shm_collection_master *master_parent = NULL;
	struct rrr_shm_collection_slave *slave_parent = NULL;

	if ((ret = rrr_shm_collection_master_new(&master_parent, "test_allocator")) != 0) {
		TEST_MSG("Could not allocate SHM master in __rrr_test_allocator_shm\n");
		goto out;
	}
	if ((ret = rrr_shm_collection_slave_new(&slave_parent, master_parent)) != 0) {
		TEST_MSG("Could not allocate SHM slave in __rrr_test_allocator_shm\n");
		goto out_destroy_master;
	}

	RRR_DBG_1("SHM test fork starting\n");

	pid_t pid = rrr_fork(fork_handler, __rrr_test_allocator_shm_child_exit_notify, NULL);

	const char test_data[] = "abcdef";
	const char test_data_success[] = "123456";

	if (pid < 0) {
		TEST_MSG("Fork failed in __rrr_test_allocator_shm\n");
		ret = 1;
		goto out_destroy_slave;
	}
	else if (pid == 0) {
		// Slave code
		ret = 1; // Default error

		// Use new slave to verify that resolve works
		struct rrr_shm_collection_slave slave_child = RRR_SHM_COLLECTION_SLAVE_INIT(master_parent);

		void *ptr;

		for (int i = 0; i < 40; i++) {
			rrr_posix_usleep(25000); // 25ms
			ptr = rrr_shm_resolve(&slave_child, 0 /* Handle is expected to be 0 since we only have one allocation */);
			if (ptr && strcmp (ptr, test_data) == 0) {
				break;
			}
		}

		if (ptr == NULL) {
			TEST_MSG("SHM resolve failed in slave in __rrr_test_allocator_shm\n");
		}
		else {
			strcpy(ptr, test_data_success);
			ret = 0;
		}
	
		RRR_DBG_1("SHM test fork complete\n");

		exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	// Parent code
	rrr_shm_handle shm_handle;
	if ((ret = rrr_shm_collection_master_allocate(&shm_handle, master_parent, sizeof(test_data))) != 0) {
		TEST_MSG("SHM allocation failed in __rrr_test_allocator_shm\n");
		goto out_send_signal;
	}

	void *ptr = rrr_shm_resolve(slave_parent, shm_handle);
	if (ptr == NULL) {
		TEST_MSG("SHM resolve failed in parent in __rrr_test_allocator_shm\n");
		ret = 1;
		goto out_send_signal;
	}
	strcpy(ptr, test_data);

	const char *test_data_result = ptr;

	ret = 1; // Default error
	for (int i = 0; i < 20; i++) {
		if (strcmp(test_data_result, test_data_success) == 0) {
			ret = 0;
			break;
		}
		rrr_posix_usleep(50000); // 50ms
	}

	if (ret != 0) {
		TEST_MSG("SHM test failed, data mismatch %s!=%s\n", test_data_success, test_data_result);
	}

	RRR_DBG_1("SHM test parent complete\n");

	out_send_signal:
		rrr_fork_send_sigusr1_to_pid(pid);
	out_destroy_slave:
		rrr_shm_collection_slave_destroy(slave_parent);
	out_destroy_master:
		rrr_shm_collection_master_destroy(master_parent);
	out:
		return ret;
}

int rrr_test_allocator (struct rrr_fork_handler *fork_handler) {
	int ret = 0;

	ret |= __rrr_test_allocator_shm(fork_handler);

	return ret;
}
