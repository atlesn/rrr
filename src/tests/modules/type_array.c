/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include <sys/socket.h>
#include <sys/un.h>
#ifdef RRR_WITH_MYSQL
#include <mysql/mysql.h>
#endif

#include "type_array.h"
#include "../test.h"
#include "../../global.h"
#include "../../lib/array.h"
#ifdef RRR_WITH_MYSQL
#include "../../lib/rrr_mysql.h"
#endif
#include "../../lib/rrr_socket.h"
#include "../../lib/instances.h"
#include "../../lib/modules.h"
#include "../../lib/buffer.h"
#include "../../lib/ip.h"
#include "../../lib/ip_buffer_entry.h"
#include "../../lib/messages.h"
#include "../../lib/rrr_endian.h"
#include "../../lib/rrr_strerror.h"
#include "../../lib/message_broker.h"

struct test_result {
	int result;
	struct rrr_message *message;
};

/* udpr_input_types=be4,be3,be2,be1,sep1,le4,le3,le2,le1,sep2,array2@blob8 */

/* Remember to disable compiler alignment */
struct test_data {
	char be4[4];
	char be3[3];
	int16_t be2;
	char be1;

	char sep1;

	char le4[4];
	char le3[3];
	int16_t le2;
	char le1;

	char sep2[2];

	char blob_a[8];
	char blob_b[8];

	struct rrr_message msg;
} __attribute__((packed));

struct test_final_data {
	uint64_t be4;
	uint64_t be3;
	int64_t be2;
	uint64_t be1;

	char sep1;

	uint64_t le4;
	uint64_t le3;
	int64_t le2;
	uint64_t le1;

	char sep2[2];

	char blob_a[8];
	char blob_b[8];

	struct rrr_message msg;
};

#define TEST_DATA_ELEMENTS 12


/*
 *  The main output receives an identical message_1 as the one we sent in,
 *  we check for correct endianess among other things
 */
int test_type_array_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	// This cast is really weird, only done in test module. Our caller
	// does not send thread_data struct but test_data struct.
	struct test_result *result = (struct test_result *) thread_data;

	result->message = NULL;
	result->result = 1;

	struct rrr_message *message = (struct rrr_message *) entry->message;
	struct rrr_array collection = {0};

	TEST_MSG("Received a message in test_type_array_callback of class %" PRIu32 "\n", MSG_CLASS(message));

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("dump message: 0x");
		for (unsigned int i = 0; i < MSG_TOTAL_SIZE(message); i++) {
			char c = ((char*)message)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}

	if (!MSG_IS_ARRAY(message)) {
		TEST_MSG("Message received in test_type_array_callback was not an array\n");
		ret = 1;
		goto out;
	}

	if (rrr_array_message_to_collection(&collection, message) != 0) {
		TEST_MSG("Error while parsing message from output function in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (collection.node_count < TEST_DATA_ELEMENTS) {
		TEST_MSG("Not enough elements in result from output in test_type_array_callback\n");
		ret = 1;
		goto out_free_collection;
	}

	rrr_type_length final_length = 0;
	RRR_LL_ITERATE_BEGIN(&collection,struct rrr_type_value);
		final_length += node->total_stored_length;
	RRR_LL_ITERATE_END();

	struct rrr_type_value *types[12];

	// After the array has been assembled and then disassembled again, all numbers
	// become be64
	types[0] = rrr_array_value_get_by_index(&collection, 0);
	types[1] = rrr_array_value_get_by_index(&collection, 1);
	types[2] = rrr_array_value_get_by_index(&collection, 2);
	types[3] = rrr_array_value_get_by_index(&collection, 3);

	types[4] = rrr_array_value_get_by_index(&collection, 4);

	types[5] = rrr_array_value_get_by_index(&collection, 5);
	types[6] = rrr_array_value_get_by_index(&collection, 6);
	types[7] = rrr_array_value_get_by_index(&collection, 7);
	types[8] = rrr_array_value_get_by_index(&collection, 8);

	types[9] = rrr_array_value_get_by_index(&collection, 9);

	types[10] = rrr_array_value_get_by_index(&collection, 10);

	types[11] = rrr_array_value_get_by_index(&collection, 11);

	for (int i = 0; i < 4; i++) {
		TEST_MSG("Type %i: %u (%s)\n", i, types[i]->definition->type, (RRR_TYPE_IS_64(types[i]->definition->type) ? "OK" : "NOT OK"));
	}
	TEST_MSG("Type 4: %u\n", types[4]->definition->type);
	for (int i = 5; i < 9; i++) {
		TEST_MSG("Type %i: %u (%s)\n", i, types[i]->definition->type, (RRR_TYPE_IS_64(types[i]->definition->type) ? "OK" : "NOT OK"));
	}
	TEST_MSG("Type 9: %u\n", types[4]->definition->type);
	for (int i = 10; i < 11; i++) {
		TEST_MSG("Type %i: %u (%s)\n", i, types[i]->definition->type, (RRR_TYPE_IS_BLOB(types[i]->definition->type) ? "OK" : "NOT OK"));
	}
	for (int i = 11; i < 12; i++) {
		TEST_MSG("Type %i: %u (%s)\n", i, types[i]->definition->type, (types[i]->definition->type == RRR_TYPE_MSG ? "OK" : "NOT OK"));
	}

	if (!RRR_TYPE_IS_64(types[0]->definition->type) ||
		!RRR_TYPE_IS_64(types[1]->definition->type) ||
		!RRR_TYPE_IS_64(types[2]->definition->type) ||
		!RRR_TYPE_IS_64(types[3]->definition->type) ||

		!RRR_TYPE_IS_64(types[5]->definition->type) ||
		!RRR_TYPE_IS_64(types[6]->definition->type) ||
		!RRR_TYPE_IS_64(types[7]->definition->type) ||
		!RRR_TYPE_IS_64(types[8]->definition->type) ||

		!RRR_TYPE_IS_BLOB(types[10]->definition->type) ||
		types[11]->definition->type != RRR_TYPE_MSG
	) {
		TEST_MSG("Wrong types in collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_collection;
	}

	struct test_final_data *final_data_raw = malloc(sizeof(*final_data_raw));

	memset(final_data_raw, '\0', sizeof(*final_data_raw));

	final_data_raw->be4 = *((uint64_t*) (types[0]->data));
	final_data_raw->be3 = *((uint64_t*) (types[1]->data));
	final_data_raw->be2 = *((int64_t*) (types[2]->data));
	final_data_raw->be1 = *((uint64_t*) (types[3]->data));

	final_data_raw->le4 = *((uint64_t*) (types[5]->data));
	final_data_raw->le3 = *((uint64_t*) (types[6]->data));
	final_data_raw->le2 = *((int64_t*) (types[7]->data));
	final_data_raw->le1 = *((uint64_t*) (types[8]->data));

	rrr_size blob_a_length = types[10]->total_stored_length / types[10]->element_count;
	rrr_size blob_b_length = types[10]->total_stored_length / types[10]->element_count;

	if (types[10]->element_count != 2) {
		RRR_MSG_ERR("Error while extracting blobs in test_type_array_callback, array size was not 2\n");
		ret = 1;
		goto out_free_final_data;
	}

	const char *blob_a = types[10]->data;
	const char *blob_b = types[10]->data + types[10]->total_stored_length / types[10]->element_count;

	if (blob_a_length != sizeof(final_data_raw->blob_a)) {
		RRR_MSG_ERR("Blob sizes not equal in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (blob_a[blob_a_length - 1] != '\0' || blob_b[blob_b_length - 1] != '\0') {
		RRR_MSG_ERR("Returned blobs were not zero terminated in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (strcmp(blob_a, "abcdefg") != 0 || strcmp(blob_b, "gfedcba") != 0) {
		RRR_MSG_ERR("Returned blobs did not match input in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	strcpy(final_data_raw->blob_a, blob_a);
	strcpy(final_data_raw->blob_b, blob_b);

	memcpy (&final_data_raw->msg, types[11]->data, types[11]->total_stored_length);

	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("dump final_data_raw: 0x");
		for (unsigned int i = 0; i < sizeof(*final_data_raw); i++) {
			char c = ((char*)final_data_raw)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}

	if (final_data_raw->be1 != final_data_raw->le1 ||
		final_data_raw->be2 != final_data_raw->le2 ||
		final_data_raw->be3 != final_data_raw->le3 ||
		final_data_raw->be4 != final_data_raw->le4
	) {
		TEST_MSG("Mismatch of data, possible corruption in test_type_array_callback\n");
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

	if (final_data_raw->be2 != -33 ||
		final_data_raw->le2 != -33
	) {
		TEST_MSG("Received wrong data from collection in test_type_array_callback, expects -33 but got 0x%" PRIx64 " and 0x%" PRIx64 "\n",
				final_data_raw->be2, final_data_raw->le2);
		ret = 1;
		goto out_free_final_data;
	}

	result->result = 2;

	out_free_final_data:
	RRR_FREE_IF_NOT_NULL(final_data_raw);

	out_free_collection:
	rrr_array_clear(&collection);

	out:
	if (ret != 0) {
	}
	else {
		result->message = message;
		entry->message = NULL;
	}

	rrr_ip_buffer_entry_unlock_(entry);

	return ret;
}

int test_do_poll_loop (
		struct test_result *test_result,
		struct rrr_instance_thread_data *thread_data,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE)
) {
	int ret = 0;

	// Poll from output
	for (int i = 1; i <= 200 && test_result->message == NULL; i++) {
		TEST_MSG("Test result polling from %s try: %i of 200\n",
				INSTANCE_D_NAME(thread_data), i);

		ret = rrr_message_broker_poll_delete (
				INSTANCE_D_BROKER_ARGS(thread_data),
				callback,
				test_result,
				150
		);

		if (ret != 0) {
			TEST_MSG("Error from poll_delete function in test_type_array\n");
			ret = 1;
			goto out;
		}

		TEST_MSG("Result of polling from %s: %i\n",
				INSTANCE_D_NAME(thread_data), test_result->result);
	}

	out:
	return ret;
}

int test_type_array_write_to_socket (struct test_data *data, struct instance_metadata *socket_metadata) {
	char *socket_path = NULL;
	int ret = 0;
	int socket_fd = 0;

	ret = rrr_instance_config_get_string_noconvert (&socket_path, socket_metadata->config, "socket_path");
	if (ret != 0) {
		TEST_MSG("Could not get configuration parameter from socket module\n");
		goto out;
	}

	if (rrr_socket_unix_create_and_connect (
			&socket_fd,
			"test_type_array_write_to_socket",
			socket_path,
			1
	) != RRR_SOCKET_OK) {
		TEST_MSG("Could not connect to socket %s in test_type_array_write_to_socket\n", socket_path);
		ret = 1;
		goto out;
	}

	if ((ret = write (socket_fd, data, sizeof(*data) - 1)) == -1) {
		TEST_MSG("Error while writing to socket in test_type_array_write_to_socket: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	else if (ret >= 0 && ret != sizeof(*data) - 1) {
		TEST_MSG("Only %i of %lu bytes written in test_type_array_write_to_socket\n",
				ret, sizeof(*data) - 1);
		ret = 1;
		goto out;
	}
	else {
		ret = 0;
	}

	out:
	if (socket_fd > 0) {
		rrr_socket_close(socket_fd);
	}
	RRR_FREE_IF_NOT_NULL(socket_path);
	return ret;
}

int test_averager_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	// This cast is really weird, only done in test module. Our caller
	// does not send thread_data struct but test_data struct.
	struct test_result *result = (struct test_result *) thread_data;

	struct rrr_message *message = (struct rrr_message *) entry->message;

	int ret = 0;

	struct rrr_array array_tmp = {0};

	if (MSG_IS_ARRAY(message)) {
		if (rrr_array_message_to_collection(&array_tmp, message) != 0) {
			TEST_MSG("Could not create array collection in test_averager_callback\n");
			ret = 1;
			goto out;
		}

		if (rrr_array_value_get_by_tag(&array_tmp, "measurement") != NULL) {
			// Copies of the original four point measurements should arrive first
			result->result++;
		}
		else {
			// Average message arrives later
			if (result->result != 4) {
				TEST_MSG("Received average result in test_averager_callback but not all four point measurements were received prior to that\n");
				ret = 1;
				goto out;
			}

			uint64_t value_average;
			uint64_t value_max;
			uint64_t value_min;

			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_average, &array_tmp, "average", 0);
			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_max, &array_tmp, "max", 0);
			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_min, &array_tmp, "min", 0);

			if (ret != 0) {
				TEST_MSG("Could not retrieve 64-values from array in test_averager_callback\n");
				ret = 1;
				goto out;
			}

			if (value_average != 5 || value_min != 2 || value_max != 8) {
				TEST_MSG("Received wrong values %" PRIu64 ", %" PRIu64 ", %" PRIu64 " in test_averager_callback\n",
						value_average, value_max, value_min	);
				ret = 1;
				goto out;
			}

			result->message = message;
			result->result = 2;
			entry->message = NULL;
		}
	}
	else {
		TEST_MSG("Unknown non-array message received in test_averager_callback\n");
		ret = 1;
		goto out;
	}

	out:
	rrr_ip_buffer_entry_unlock_(entry);
	rrr_array_clear(&array_tmp);
	return ret;
}

int test_averager (
		struct rrr_message **result_message,
		struct instance_metadata_collection *instances,
		const char *input_name_voltmonitor,
		const char *output_name_averager
) {
	struct instance_metadata *input = rrr_instance_find(instances, input_name_voltmonitor);
	struct instance_metadata *output = rrr_instance_find(instances, output_name_averager);
	struct rrr_message *message = NULL;
	struct rrr_ip_buffer_entry *entry = NULL;
	struct rrr_array array_tmp = {0};

	int ret = 0;

	if (input == NULL || output == NULL) {
		TEST_MSG("Could not find input and output instances %s and %s in test_averager\n",
				input_name_voltmonitor, output_name_averager);
		ret = 1;
		goto out;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);

	inject = input->dynamic_data->operations.inject;

	// Inject four messages to be averaged
	for (int i = 2; i <= 8; i += 2) {
		if (rrr_array_push_value_64_with_tag(&array_tmp, "measurement", i) != 0) {
			TEST_MSG("Could not push value to array in test_averager\n");
			ret = 1;
			goto out;
		}


		RRR_FREE_IF_NOT_NULL(message);
		if (rrr_array_new_message_from_collection(
				&message,
				&array_tmp,
				rrr_time_get_64(),
				"test/measurement",
				strlen("test/measurement"
		)) != 0) {
			TEST_MSG("Could not create message in test_averager\n");
			ret = 1;
			goto out;
		}

		if (rrr_ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, 0, message) != 0) {
			TEST_MSG("Could not create ip buffer entry in test_averager\n");
			ret = 1;
			goto out;
		}
		message = NULL;
		rrr_ip_buffer_entry_lock_(entry);

		// Inject should not decref, but must unlock
		if (inject(input->thread_data, entry)) {
			TEST_MSG("Error from inject function in test_averager\n");
			ret = 1;
			goto out;
		}
		rrr_ip_buffer_entry_decref(entry);
		entry = NULL;
	}

	// Poll from first output
	TEST_MSG("Polling from %s\n", INSTANCE_D_NAME(output->thread_data));
	struct test_result test_result = {0, NULL};
	ret |= test_do_poll_loop(&test_result, output->thread_data, test_averager_callback);
	TEST_MSG("Result of test_averager, should be 2: %i\n", test_result.result);
	*result_message = test_result.message;

	out:
	if (entry != NULL) {
		rrr_ip_buffer_entry_decref(entry);
	}
	rrr_array_clear(&array_tmp);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int test_type_array (
		struct rrr_message **result_message_1,
		struct rrr_message **result_message_2,
		struct rrr_message **result_message_3,
		struct instance_metadata_collection *instances,
		const char *input_name,
		const char *input_socket_name,
		const char *output_name_1,
		const char *output_name_2,
		const char *output_name_3
) {
	int ret = 0;
	*result_message_1 = NULL;
	*result_message_2 = NULL;
	*result_message_3 = NULL;

	struct rrr_ip_buffer_entry *entry = NULL;
	struct test_data *data = NULL;

	struct instance_metadata *input = rrr_instance_find(instances, input_name);
	struct instance_metadata *input_buffer_socket = rrr_instance_find(instances, input_socket_name);
	struct instance_metadata *output_1 = rrr_instance_find(instances, output_name_1);
	struct instance_metadata *output_2 = rrr_instance_find(instances, output_name_2);
	struct instance_metadata *output_3 = rrr_instance_find(instances, output_name_3);

	if (input == NULL || input_buffer_socket == NULL || output_1 == NULL || output_2 == NULL || output_3 == NULL) {
		TEST_MSG("Could not find input and output instances %s and %s in test_type_array\n",
				input_name, output_name_1);
		return 1;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE) = input->dynamic_data->operations.inject;

	// Allocate more bytes as we need to pass ip_buffer_entry around (although we are actually not an rrr_message)

	data = malloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	data->be4[0] = 1;
	data->be4[2] = 2;

	data->be3[0] = 1;
	data->be3[1] = 2;

	data->be2 = htobe16(-33);

	data->be1 = 1;

	data->sep1 = ';';

	data->le4[1] = 2;
	data->le4[3] = 1;

	data->le3[1] = 2;
	data->le3[2] = 1;

	data->le2 = htole16(-33);

	data->le1 = 1;

	data->sep2[0] = '|';
	data->sep2[1] = '|';

	sprintf(data->blob_a, "abcdefg");
	sprintf(data->blob_b, "gfedcba");

	data->msg.msg_size = sizeof(struct rrr_message) - 1;
	data->msg.msg_type = RRR_SOCKET_MSG_TYPE_MESSAGE;
	data->msg.topic_length = 0;
	MSG_SET_TYPE(&data->msg, MSG_TYPE_MSG);
	MSG_SET_CLASS(&data->msg, MSG_CLASS_DATA);

	rrr_message_prepare_for_network(&data->msg);
	rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) &data->msg);

	ret = test_type_array_write_to_socket(data, input_buffer_socket);
	if (ret != 0) {
		TEST_MSG("Could not write to socket in test_type_array\n");
		ret = 1;
		goto out;
	}

	if (rrr_ip_buffer_entry_new(&entry, sizeof(struct test_data) - 1, NULL, 0, 0, data) != 0) {
		TEST_MSG("Could not create ip buffer entry in test_type_array\n");
		ret = 1;
		goto out;
	}
	data = NULL;

	rrr_ip_buffer_entry_lock_(entry);

	ret = inject(input->thread_data, entry);
	if (ret != 0) {
		TEST_MSG("Error from inject function in test_type_array\n");
		ret = 1;
		goto out;
	}

	// Poll from first output
	TEST_MSG("Polling from %s\n", INSTANCE_D_NAME(output_1->thread_data));
	struct test_result test_result_1 = {1, NULL};
	ret |= test_do_poll_loop(&test_result_1, output_1->thread_data, test_type_array_callback);
	if (ret != 0) {
		goto out;
	}
	TEST_MSG("Result of test_type_array 1/3, should be 2: %i\n", test_result_1.result);
	*result_message_1 = test_result_1.message;

	// Poll from second output
	TEST_MSG("Polling from %s\n", INSTANCE_D_NAME(output_2->thread_data));
	struct test_result test_result_2 = {1, NULL};
	ret |= test_do_poll_loop(&test_result_2, output_2->thread_data, test_type_array_callback);
	if (ret != 0) {
		goto out;
	}
	TEST_MSG("Result of test_type_array 2/3, should be 2: %i\n", test_result_2.result);
	*result_message_2 = test_result_2.message;

	// Poll from third output
	TEST_MSG("Polling from %s\n", INSTANCE_D_NAME(output_3->thread_data));
	struct test_result test_result_3 = {1, NULL};
	ret |= test_do_poll_loop(&test_result_3, output_3->thread_data, test_type_array_callback);
	if (ret != 0) {
		goto out;
	}
	TEST_MSG("Result of test_type_array 3/3, should be 2: %i\n", test_result_3.result);
	*result_message_3 = test_result_3.message;

	// Error if result is not two from both polls
	ret |= (test_result_1.result != 2) | (test_result_2.result != 2) | (test_result_3.result != 2);

	out:
	RRR_FREE_IF_NOT_NULL(data);
	if (entry != NULL) {
		rrr_ip_buffer_entry_decref(entry);
	}
	return ret;
}

#ifdef RRR_WITH_MYSQL
int test_type_array_mysql_and_network_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	RRR_DBG_4("Received message_1 in test_type_array_mysql_and_network_callback\n");

	/* We actually receive an ip_buffer_entry but we don't need IP-stuff */
	struct rrr_message *message = (struct rrr_message *) entry->message;
	struct test_result *test_result = (struct test_result *) thread_data;

	test_result->message = message;
	test_result->result = 0;
	entry->message = NULL;

	rrr_ip_buffer_entry_unlock_(entry);
	return ret;
}

struct test_type_array_mysql_data {
	char *mysql_server;
	char *mysql_user;
	char *mysql_password;
	char *mysql_db;
	unsigned int mysql_port;
};

int test_type_array_setup_mysql (struct test_type_array_mysql_data *mysql_data) {
	int ret = 0;
	rrr_mysql_library_init();
	mysql_thread_init();

	static const char *create_table_sql =
	"CREATE TABLE IF NOT EXISTS `rrr-test-array-types-2` ("
		"`int1` bigint(20) NOT NULL,"
		"`int2` bigint(20) NOT NULL,"
		"`int3` bigint(20) NOT NULL,"
		"`int4` bigint(20) NOT NULL,"
		"`int5` bigint(20) NOT NULL,"
		"`int6` bigint(20) NOT NULL,"
		"`int7` bigint(20) NOT NULL,"
		"`int8` bigint(20) NOT NULL,"
		"`rrr_message` blob NOT NULL,"
		"`blob_combined` blob NOT NULL,"
		"`timestamp` bigint(20) NOT NULL"
	") ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	void *ptr;
	MYSQL mysql;

	ptr = mysql_init(&mysql);
	if (ptr == NULL) {
		RRR_MSG_ERR ("Could not initialize MySQL\n");
		ret = 1;
		goto out;
	}

	ptr = mysql_real_connect (
			&mysql,
			mysql_data->mysql_server,
			mysql_data->mysql_user,
			mysql_data->mysql_password,
			mysql_data->mysql_db,
			mysql_data->mysql_port,
			NULL,
			0
	);

	if (ptr == NULL) {
		RRR_MSG_ERR ("mysql_type_array_setup_mysql: Failed to connect to database: Error: %s\n",
				mysql_error(&mysql));
		ret = 1;
		goto out;
	}

	TEST_MSG("%s\n", create_table_sql);

	if (mysql_query(&mysql, create_table_sql)) {
		RRR_MSG_ERR ("mysql_type_array_setup_mysql: Failed to create table: Error: %s\n",
				mysql_error(&mysql));
		ret = 1;
		goto out_close;
	}

	TEST_MSG("Connected to MySQL and test table created\n");

	out_close:
	mysql_close(&mysql);

	out:
	mysql_thread_end();
	rrr_mysql_library_end();
	return ret;
}

int test_type_array_mysql_steal_config(struct test_type_array_mysql_data *data, struct instance_metadata *mysql) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	ret |= rrr_instance_config_get_string_noconvert (&data->mysql_server, mysql->config, "mysql_server");
	ret |= rrr_instance_config_get_string_noconvert (&data->mysql_user, mysql->config, "mysql_user");
	ret |= rrr_instance_config_get_string_noconvert (&data->mysql_password, mysql->config, "mysql_password");
	ret |= rrr_instance_config_get_string_noconvert (&data->mysql_db, mysql->config, "mysql_db");

	rrr_setting_uint port;
	if (rrr_instance_config_read_port_number (&port, mysql->config, "mysql_port") == RRR_SETTING_ERROR) {
		ret |= 1;
	}
	else if (data->mysql_port == 0) {
		data->mysql_port = 5506;
	}

	return ret;
}

void test_type_array_mysql_data_cleanup(void *arg) {
	struct test_type_array_mysql_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->mysql_server);
	RRR_FREE_IF_NOT_NULL(data->mysql_user);
	RRR_FREE_IF_NOT_NULL(data->mysql_password);
	RRR_FREE_IF_NOT_NULL(data->mysql_db);
}

int test_type_array_mysql_and_network (
		struct instance_metadata_collection *instances,
		const char *input_buffer_name,
		const char *tag_buffer_name,
		const char *mysql_name,
		const struct rrr_message *message
) {
	int ret = 0;

	struct test_result test_result = {1, NULL};
	struct test_type_array_mysql_data mysql_data = {NULL, NULL, NULL, NULL, 0};
	struct rrr_message *new_message = NULL;
	struct rrr_ip_buffer_entry *entry = NULL;
	uint64_t expected_ack_timestamp = message->timestamp;

	new_message = rrr_message_duplicate(message);
	if (new_message == NULL) {
		RRR_MSG_ERR("Could not duplicate message in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	if (rrr_ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(new_message), NULL, 0, 0, new_message) != 0) {
		TEST_MSG("Could not allocate ip buffer entry in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}
	new_message = NULL;

	struct instance_metadata *input_buffer = rrr_instance_find(instances, input_buffer_name);
	struct instance_metadata *tag_buffer = rrr_instance_find(instances, tag_buffer_name);
	struct instance_metadata *mysql = rrr_instance_find(instances, mysql_name);

	if (input_buffer == NULL || tag_buffer == NULL || mysql == NULL) {
		TEST_MSG("Could not find input, tag and mysql instances %s, %s and %s in test_type_array_mysql_and_network\n",
				input_buffer_name, tag_buffer_name, mysql_name);
		ret = 1;
		goto out;
	}

	ret = test_type_array_mysql_steal_config(&mysql_data, mysql);
	if (ret != 0) {
		RRR_MSG_ERR("Failed to get configuration from MySQL in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("The error message_1 'Failed to prepare statement' is fine, it might show up before the table is created\n");
	ret = test_type_array_setup_mysql (&mysql_data);
	if (ret != 0) {
		RRR_MSG_ERR("Failed to setup MySQL test environment\n");
		ret = 1;
		goto out;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);

	inject = input_buffer->dynamic_data->operations.inject;

	if (inject == NULL) {
		TEST_MSG("Could not find inject in modules in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	rrr_ip_buffer_entry_lock_(entry);
	ret = inject(input_buffer->thread_data, entry);
	if (ret != 0) {
		RRR_MSG_ERR("Error from inject function in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Polling MySQL\n");
	ret |= test_do_poll_loop(&test_result, tag_buffer->thread_data, test_type_array_mysql_and_network_callback);
	TEST_MSG("Result from MySQL buffer callback: %i\n", test_result.result);

	ret = test_result.result;
	if (ret != 0) {
		RRR_MSG_ERR("Result was not OK from test_type_array_mysql_and_network_callback\n");
		ret = 1;
		goto out;
	}

	struct rrr_message *result_message = test_result.message;
	if (!MSG_IS_TAG(result_message)) {
		RRR_MSG_ERR("Message from MySQL was not a TAG message_1\n");
		ret = 1;
		goto out;
	};

	if (result_message->timestamp != expected_ack_timestamp) {
		RRR_MSG_ERR("Timestamp of TAG message_1 from MySQL did not match original message_1 (%" PRIu64 " vs %" PRIu64 ")\n",
				result_message->timestamp, expected_ack_timestamp);
		ret = 1;
		goto out;
	}

	out:
	test_type_array_mysql_data_cleanup(&mysql_data);
	RRR_FREE_IF_NOT_NULL(new_message);
	if (entry != NULL) {
		rrr_ip_buffer_entry_decref_while_locked_and_unlock(entry);
	}
	RRR_FREE_IF_NOT_NULL(test_result.message);

	return ret;
}

#endif
