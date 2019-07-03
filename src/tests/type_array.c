/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <inttypes.h>

#include "test.h"
#include "../global.h"
#include "../lib/instances.h"
#include "../lib/modules.h"
#include "../lib/types.h"
#include "../lib/buffer.h"
#include "../lib/ip.h"

struct test_result {
	int result;
};

/* udpr_input_types=be,4,be,3,be,2,be,1,le,4,le,3,le,2,le,1,array,2,blob,8 */

struct test_data {
	char be4[4];
	char be3[3];
	uint16_t be2;
	char be1;

	char le4[4];
	char le3[3];
	uint16_t le2;
	char le1;

	char blob_a[8];
	char blob_b[8];
};

struct test_final_data {
	uint64_t be4;
	uint64_t be3;
	uint64_t be2;
	uint64_t be1;

	uint64_t le4;
	uint64_t le3;
	uint64_t le2;
	uint64_t le1;

	char blob_a[8];
	char blob_b[8];
};

#define TEST_DATA_ELEMENTS 9

int test_type_array_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;
	struct test_result *result = poll_data->private_data;

	result->result = 1;

	if (size > sizeof(struct vl_message)) {
		TEST_MSG("Size of message in test_type_array_callback exceeds struct vl_message size\n");
		ret = 1;
		goto out;
	}

	struct vl_message *message = (struct vl_message *) data;
	struct rrr_data_collection *collection = NULL;

	if (rrr_types_message_to_collection(&collection, message) != 0) {
		TEST_MSG("Error while parsing message from output function in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (collection->definitions.count != TEST_DATA_ELEMENTS) {
		TEST_MSG("Wrong number of elements in result from output in test_type_array_callback\n");
		ret = 1;
		goto out_free_collection;
	}

	rrr_type_length final_length = rrr_get_raw_length(collection);

	if (!RRR_TYPE_IS_64(collection->definitions.definitions[0].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[1].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[2].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[3].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[4].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[5].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[6].type) ||
		!RRR_TYPE_IS_64(collection->definitions.definitions[7].type) ||
		!RRR_TYPE_IS_BLOB(collection->definitions.definitions[8].type)
	) {
		TEST_MSG("Wrong types in collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_collection;
	}

	struct test_final_data *final_data = malloc(sizeof(*final_data));
	if (sizeof(*final_data) != final_length) {
		TEST_MSG("Wrong size of type collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (rrr_types_extract_raw_from_collection((char*) final_data, sizeof(*final_data), collection) != 0) {
		TEST_MSG("Error while extracting data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (final_data->be1 != final_data->le1 ||
		final_data->be3 != final_data->le3 ||
		final_data->be4 != final_data->le4
	) {
		TEST_MSG("Error with endianess conversion in collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (final_data->be1 == 0 ||
		final_data->be3 == 0 ||
		final_data->be4 == 0
	) {
		TEST_MSG("Received zero data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (final_data->be2 != 33 ||
		final_data->le2 != 33
	) {
		TEST_MSG("Received wrong data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	result->result = 2;

	out_free_final_data:
	free(final_data);

	out_free_collection:
	rrr_types_destroy_data(collection);

	out:
	free(data);
	return ret;
}

int test_type_array (
		struct instance_metadata_collection *instances,
		const char *input_name,
		const char *output_name
) {
	int ret = 0;

	struct instance_metadata *input = instance_find(instances, input_name);
	struct instance_metadata *output = instance_find(instances, output_name);

	if (input == NULL || output == NULL) {
		TEST_MSG("Could not find input and output instances %s and %s in test_type_array\n",
				input_name, output_name);
		return 1;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);

	inject = input->dynamic_data->operations.inject;
	poll_delete = output->dynamic_data->operations.poll_delete;

	if (inject == NULL || poll_delete == NULL) {
		TEST_MSG("Could not find inject and/or poll_delete in modules in test_type_array\n");
		return 1;
	}

	// Allocate more bytes as we cast to vl_message later (although we are actually not a vl_message)
	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	memset(entry, '\0', sizeof(*entry));

	struct test_data *data = (struct test_data *) entry->data.data;
	entry->data_length = sizeof(*data);

	data->be1 = 1;
	data->le1 = 1;

	data->be3[1] = 1;
	data->be3[2] = 2;

	data->le3[2] = 1;
	data->le3[3] = 2;

	data->be4[0] = 1;
	data->be4[2] = 2;

	data->le4[1] = 1;
	data->le4[3] = 3;

	data->be2 = htobe16(33);
	data->le2 = htole16(33);

	sprintf(data->blob_a, "abcdefg");
	sprintf(data->blob_b, "gfedcba");

	ret = inject(input->thread_data, entry);
	if (ret != 0) {
		TEST_MSG("Error from inject function in test_type_array\n");
		free(entry);
		return 1;
	}

	usleep(200000);

	struct test_result result = {0};
	struct fifo_callback_args poll_data = {NULL, &result, 0};
	ret = poll_delete(output->thread_data, test_type_array_callback, &poll_data);
	if (ret != 0) {
		TEST_MSG("Error from poll_delete function in test_type_array\n");
		return 1;
	}

	TEST_MSG("Result of test_type_array, should be 2: %i\n", result.result);

	return (result.result != 2);
}
