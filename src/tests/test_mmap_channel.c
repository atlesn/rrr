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
#include "../lib/mmap_channel.h"
#include "../lib/rrr_shm.h"
#include "../lib/rrr_shm_struct.h"
#include "../lib/fork.h"
#include "../lib/util/posix.h"
#include "test.h"
#include "test_mmap_channel.h"

static void __rrr_test_mmap_channel_child_exit_notify (pid_t pid, void *arg) {
	(void)(arg);
	(void)(pid);
	RRR_DBG_1("SHM test fork has exited\n");
}
		
static int __rrr_test_mmap_channel_read_callback (const void *data, size_t data_size, void *arg) {
	memcpy(arg, data, data_size);
	return 0;
}

static int __rrr_test_mmap_channel(struct rrr_fork_handler *fork_handler) {
	int ret = 0;

	struct rrr_shm_collection_master *master_parent = NULL;
	struct rrr_mmap_channel *mmap_channel_to_fork = NULL;
	struct rrr_mmap_channel *mmap_channel_to_parent = NULL;

	// After forking, the parent and the fork will have their
	// own copy of this SHM slave.
	struct rrr_shm_collection_slave slave_common;

	if ((ret = rrr_shm_collection_master_new(&master_parent)) != 0) {
		TEST_MSG("Could not allocate SHM master in __rrr_test_mmap_channel\n");
		goto out;
	}

	rrr_shm_collection_slave_reset (&slave_common, master_parent);

	if ((ret = rrr_mmap_channel_new (&mmap_channel_to_fork, master_parent, &slave_common, "to fork")) != 0) {
		TEST_MSG("Failed to create mmap channel in __rrr_test_mmap_channel\n");
		goto out_destroy_master;
	}

	if ((ret = rrr_mmap_channel_new (&mmap_channel_to_parent, master_parent, &slave_common, "to parent")) != 0) {
		TEST_MSG("Failed to create mmap channel in __rrr_test_mmap_channel\n");
		goto out_destroy_mmap_channel_to_fork;
	}

	RRR_DBG_1("SHM test fork starting\n");

	pid_t pid = rrr_fork(fork_handler, __rrr_test_mmap_channel_child_exit_notify, NULL);

	const char *test_data = "abcdef";
	const char *test_data_success = "123456";
	char test_data_result[sizeof(test_data)] = "";

	if (pid < 0) {
		TEST_MSG("Fork failed in __rrr_test_mmap_channel\n");
		ret = 1;
		goto out_destroy_mmap_channel_to_parent;
	}
	else if (pid == 0) {
		// Slave code
		ret = 1; // Default error

		for (int i = 0; i < 20; i++) {
			rrr_posix_usleep(50000); // 50ms
			int read_count = 0;
			if (rrr_mmap_channel_read_with_callback (
					&read_count,
					mmap_channel_to_fork,
					__rrr_test_mmap_channel_read_callback,
					test_data_result
			) == 0 && read_count == 1) {
				if (strcmp(test_data_result, test_data) == 0) {
					ret = 0;
					break;
				}
			}
		}

		if (ret != 0) {
			TEST_MSG("Incorrect data or no data received in fork in __rrr_test_mmap_channel '%s'!='%s'\n", test_data_result, test_data);
		}
		else {
			if ((ret = rrr_mmap_channel_write (
					mmap_channel_to_parent,
					NULL,
					test_data_success,
					sizeof(test_data_success),
					NULL,
					NULL
			)) != 0) {
				TEST_MSG("Failed to send message to parent in __rrr_test_mmap_channel\n");
			}
		}

		rrr_posix_usleep(100000); // 100 ms

		rrr_mmap_channel_writer_free_blocks(mmap_channel_to_parent);

		exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	if ((ret = rrr_mmap_channel_write (
			mmap_channel_to_fork,
			NULL,
			test_data,
			sizeof(test_data),
			NULL,
			NULL
	)) != 0) {
		TEST_MSG("Failed to send message to fork in __rrr_test_mmap_channel\n");
		goto out_send_signal;
	}

	ret = 1; // Default error
	for (int i = 0; i < 20; i++) {
		int read_count = 0;
		if (rrr_mmap_channel_read_with_callback (
				&read_count,
				mmap_channel_to_parent,
				__rrr_test_mmap_channel_read_callback,
				test_data_result
		) == 0 && read_count == 1) {
			if (strcmp(test_data_result, test_data_success) == 0) {
				ret = 0;
				break;
			}
		}

		rrr_posix_usleep(50000); // 50ms
	}

	if (ret != 0) {
		TEST_MSG("MMAP test failed, data mismatch '%s'!='%s'\n", test_data_success, test_data_result);
	}

	rrr_posix_usleep(100000); // 100ms

	rrr_mmap_channel_writer_free_blocks(mmap_channel_to_fork);

	out_send_signal:
		rrr_fork_send_sigusr1_to_pid(pid);
	out_destroy_mmap_channel_to_parent:
		rrr_mmap_channel_destroy_by_reader(mmap_channel_to_parent);
	out_destroy_mmap_channel_to_fork:
		rrr_mmap_channel_destroy_by_writer(mmap_channel_to_fork);
	out_destroy_master:
		rrr_shm_collection_master_destroy(master_parent);
	out:
		return ret;
}

int rrr_test_mmap_channel (struct rrr_fork_handler *fork_handler) {
	int ret = 0;

	ret |= __rrr_test_mmap_channel(fork_handler);

	return ret;
}
