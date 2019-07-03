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

#include "type_array.h"
#include "../test.h"
#include "../../global.h"
#include "../../lib/instances.h"
#include "../../lib/modules.h"
#include "../../lib/types.h"
#include "../../lib/buffer.h"
#include "../../lib/ip.h"

struct test_result {
	int result;
};

/* udpr_input_types=be,4,be,3,be,2,be,1,le,4,le,3,le,2,le,1,array,2,blob,8 */

/* Remember to disable compiler alignment */
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
} __attribute__((packed));

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

	struct test_final_data *final_data_raw = malloc(sizeof(*final_data_raw));
	struct test_final_data *final_data_converted = malloc(sizeof(*final_data_converted));

	if (sizeof(*final_data_raw) != final_length) {
		TEST_MSG("Wrong size of type collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	rrr_size final_data_raw_length;
	if (rrr_types_extract_raw_from_collection_static((char*) final_data_raw, sizeof(*final_data_raw), &final_data_raw_length, collection) != 0) {
		TEST_MSG("Error while extracting data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	ret |= rrr_types_extract_host_64(&final_data_converted->be4, collection, 0, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->be3, collection, 1, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->be2, collection, 2, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->be1, collection, 3, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->le4, collection, 4, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->le3, collection, 5, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->le2, collection, 6, 0);
	ret |= rrr_types_extract_host_64(&final_data_converted->le1, collection, 7, 0);

	if (ret != 0) {
		VL_MSG_ERR("Error while extracting ints in test_type_array_callback\n");
		goto out_free_final_data;
	}

	char *blob_a = NULL;
	char *blob_b = NULL;

	rrr_size blob_a_length = 0;
	rrr_size blob_b_length = 0;

	ret |= rrr_types_extract_blob(&blob_a, &blob_a_length, collection, 8, 0, 0);
	ret |= rrr_types_extract_blob(&blob_b, &blob_b_length, collection, 8, 1, 0);

	if (ret != 0) {
		VL_MSG_ERR("Error while extracting blobs in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (blob_a_length != sizeof(final_data_converted->blob_a)) {
		VL_MSG_ERR("Blob sizes not equal in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (blob_a[blob_a_length - 1] != '\0' || blob_b[blob_b_length - 1] != '\0') {
		VL_MSG_ERR("Returned blobs were not zero terminated in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (strcmp(blob_a, "abcdefg") != 0 || strcmp(blob_b, "gfedcba") != 0) {
		VL_MSG_ERR("Returned blobs did not match input in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (strcmp(blob_a, final_data_raw->blob_a) != 0 || strcmp(blob_b, final_data_raw->blob_b) != 0) {
		VL_MSG_ERR("Returned blobs from different extractor functions did not match in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("dump final_data_raw: 0x");
		for (unsigned int i = 0; i < sizeof(*final_data_raw); i++) {
			char c = ((char*)final_data_raw)[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	if (be64toh(final_data_raw->be1) != le64toh(final_data_raw->le1) ||
		be64toh(final_data_raw->be2) != le64toh(final_data_raw->le2) ||
		be64toh(final_data_raw->be3) != le64toh(final_data_raw->le3) ||
		be64toh(final_data_raw->be4) != le64toh(final_data_raw->le4)
	) {
		TEST_MSG("Error with endianess conversion in collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (final_data_raw->be1 == 0 ||
		final_data_raw->be2 == 0 ||
		final_data_raw->be3 == 0 ||
		final_data_raw->be4 == 0
	) {
		TEST_MSG("Received zero data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (be64toh(final_data_raw->be2) != 33 ||
		le64toh(final_data_raw->le2) != 33
	) {
		TEST_MSG("Received wrong data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (be64toh(final_data_raw->be4) != final_data_converted->be4 ||
		be64toh(final_data_raw->be3) != final_data_converted->be3 ||
		be64toh(final_data_raw->be2) != final_data_converted->be2 ||
		be64toh(final_data_raw->be1) != final_data_converted->be1 ||
		le64toh(final_data_raw->le4) != final_data_converted->le4 ||
		le64toh(final_data_raw->le3) != final_data_converted->le3 ||
		le64toh(final_data_raw->le2) != final_data_converted->le2 ||
		le64toh(final_data_raw->le1) != final_data_converted->le1
	) {
		TEST_MSG("Retrieved ints from different extractor functions did not match\n");
		ret = 1;
		goto out_free_final_data;
	}

	result->result = 2;

	out_free_final_data:
	RRR_FREE_IF_NOT_NULL(blob_a);
	RRR_FREE_IF_NOT_NULL(blob_b);
	RRR_FREE_IF_NOT_NULL(final_data_raw);
	RRR_FREE_IF_NOT_NULL(final_data_converted);

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

	data->be4[0] = 1;
	data->be4[2] = 2;

	data->be3[0] = 1;
	data->be3[1] = 2;

	data->be2 = htobe16(33);

	data->be1 = 1;

	data->le4[1] = 2;
	data->le4[3] = 1;

	data->le3[1] = 2;
	data->le3[2] = 1;

	data->le2 = htole16(33);

	data->le1 = 1;

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
