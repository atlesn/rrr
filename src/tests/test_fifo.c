
/*

Read Route Record

Copyright (C) 2025 Atle Solbakken atle@goliathdns.no

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

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "test.h"
#include "test_linked_list.h"
#include "../lib/fifo.h"
#include "../lib/allocator.h"
#include "../lib/log.h"

struct test_data {
	char text[32];
	int refcount;
	uint32_t index;
	uint64_t order_pos;
};

struct callback_args {
	uint32_t seq;
	uint64_t order_pos;
};

static struct test_data *allocations[64];
static uint32_t allocation_count = 0;

static struct test_data *__rrr_test_fifo_allocate(void) {
	struct test_data *test_data;

	test_data = allocations[allocation_count] = rrr_allocate_zero(sizeof(*test_data));
	test_data->index = allocation_count;
	*test_data->text = '\0';

	allocation_count++;

	return test_data;
}

static int __rrr_test_fifo_write_callback(char **data, unsigned long int *size, uint64_t *order, void *arg) {
	struct callback_args *args = arg;

	struct test_data *test_data = __rrr_test_fifo_allocate();

	*data = (char *) test_data;
	*size = sizeof(*test_data);
	*order = test_data->order_pos = args->order_pos--;

	switch (args->seq++) {
		case 0:
		case 1:
		case 2:
		case 3:
			return RRR_FIFO_WRITE_AGAIN | RRR_FIFO_WRITE_ORDERED;
			break;
		case 4:
			return RRR_FIFO_WRITE_AGAIN | RRR_FIFO_WRITE_DROP;
			break;
		default:
			break;
	};

	return RRR_FIFO_WRITE_DROP;
}

static int __rrr_test_fifo_read_callback(void *arg, char *data, unsigned long int size) {
	struct callback_args *args = arg;
	struct test_data *test_data = (struct test_data *) data;

	assert(size == sizeof(*test_data) && "Write function must save correct struct size");
	assert(test_data->order_pos > args->order_pos && "Entries were not sorted correctly");

	args->order_pos = test_data->order_pos;

	return RRR_FIFO_OK;
}

static int __rrr_test_fifo_search_and_replace_callback(char **data, unsigned long int *size, uint64_t *order, void *arg) {
	struct callback_args *args = arg;
	struct test_data *test_data = (struct test_data *) *data;

	(void)(order);

	switch (args->seq) {
		case 0:
		case 1:
		case 2:
			args->seq++;
			if (test_data->index == 1) {
				struct test_data *test_data = __rrr_test_fifo_allocate();
				sprintf(test_data->text, "REPLACED");
				*data = (char *) test_data;
				return RRR_FIFO_SEARCH_REPLACE | RRR_FIFO_SEARCH_FREE;
			}
			else if (test_data->index == 2) {
				sprintf(test_data->text, "MODIFIED");
				return RRR_FIFO_SEARCH_KEEP;
			}
			else if (test_data->index == 3) {
				return RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
			}
			break;
		case 3:
			args->seq++;
			return RRR_FIFO_OK;
		case 4:
			assert(*data == NULL);
			struct test_data *test_data = __rrr_test_fifo_allocate();
			sprintf(test_data->text, "ADDED");
			*data = (char *) test_data;
			*size = sizeof(*test_data);
			args->seq++;
			return RRR_FIFO_OK;
		default:
			assert(args->seq == 5);
	}

	return RRR_FIFO_SEARCH_STOP | RRR_FIFO_WRITE_DROP;
}

static void __rrr_test_fifo_incref(void *ptr) {
	struct test_data *test_data = ptr;
	test_data->refcount++;
}

static void __rrr_test_fifo_decref(void *ptr) {
	struct test_data *test_data = ptr;
	assert((--test_data->refcount) >= 0);
}

int rrr_test_fifo(void) {
	int ret = 0;

	struct rrr_fifo fifo = {0};
	struct callback_args args = {0};

	TEST_MSG("Initializing FIFO buffer...\n");

	rrr_fifo_init_custom_refcount(&fifo, __rrr_test_fifo_incref, __rrr_test_fifo_decref);

	assert(rrr_fifo_get_entry_count(&fifo) == 0 && "New FIFO buffer must be empty");

	TEST_MSG("Testing writes...\n");

	args.seq = 0;
	args.order_pos = 10;

	if ((ret = rrr_fifo_write(&fifo, __rrr_test_fifo_write_callback, &args)) != 0) {
		TEST_MSG("FIFO write failed with error %i\n", ret);
		goto out;
	}

	assert(rrr_fifo_get_entry_count(&fifo) == 4 && "Incorrect number of entries in FIFO after write");

	TEST_MSG("Testing reads...\n");

	args.seq = 0;
	args.order_pos = 0;

	if ((ret = rrr_fifo_read(&fifo, __rrr_test_fifo_read_callback, &args)) != 0) {
		TEST_MSG("FIFO read failed with error %i\n", ret);
		goto out;
	}

	assert(rrr_fifo_get_entry_count(&fifo) == 4 && "Incorrect number of entries in FIFO after read");

	args.seq = 0;
	args.order_pos = 0;

	const uint32_t allocation_count_keep = allocation_count;

	TEST_MSG("Testing search and replace...\n");

	if ((ret = rrr_fifo_search_and_replace(&fifo, __rrr_test_fifo_search_and_replace_callback, &args, 1 /* Do call again after looping */)) != 0) {
		TEST_MSG("FIFO search and replace failed with error %i\n", ret);
		goto out;
	}

	assert(args.seq == 5 && "Callback did not set seq to 5");

	// Check replaced entry
	assert(allocations[allocation_count_keep]->index == allocation_count_keep && "Unexpected index for replaced entry");
	assert(strcmp(allocations[allocation_count_keep]->text, "REPLACED") == 0 && "Unexpected text for replaced entry");
	assert(allocations[1]->refcount == 0 && "Unexpected refcount for replaced entry");

	// Check modified entry
	assert(strcmp(allocations[2]->text, "MODIFIED") == 0 && "Unexpected text for modified entry");

	// Check removed entry
	assert(allocations[3]->refcount == 0 && "Unexpected refcount for removed entry");

	// Check added entry
	assert(allocations[allocation_count_keep + 1]->index == allocation_count_keep + 1 && "Unexpected index for added entry");
	assert(strcmp(allocations[allocation_count_keep + 1]->text, "ADDED") == 0 && "Unexpected text for added entry");

	assert(rrr_fifo_get_entry_count(&fifo) == 4 && "Incorrect number of entries in FIFO after search and replace");

	rrr_fifo_destroy(&fifo);

	assert(rrr_fifo_get_entry_count(&fifo) == 0 && "Incorrect number of entries in FIFO after destroy");

	for (uint32_t i = 0; i < allocation_count; i++) {
		struct test_data *test_data = allocations[i];
		assert(test_data->refcount == 0);
		free(test_data);
	}

	out:
	rrr_fifo_destroy(&fifo);
	return ret;
}

