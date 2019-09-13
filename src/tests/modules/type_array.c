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
#include <mysql/mysql.h>

#include "type_array.h"
#include "../test.h"
#include "../../global.h"
#include "../../lib/array.h"
#include "../../lib/rrr_mysql.h"
#include "../../lib/instances.h"
#include "../../lib/modules.h"
#include "../../lib/buffer.h"
#include "../../lib/ip.h"
#include "../../lib/messages.h"

struct test_result {
	int result;
	struct vl_message *message;
};

/* udpr_input_types=be4,be3,be2,be1,sep1,le4,le3,le2,le1,sep2,array2@blob8 */

/* Remember to disable compiler alignment */
struct test_data {
	char be4[4];
	char be3[3];
	uint16_t be2;
	char be1;

	char sep1;

	char le4[4];
	char le3[3];
	uint16_t le2;
	char le1;

	char sep2[2];

	char blob_a[8];
	char blob_b[8];

	struct vl_message msg;
} __attribute__((packed));

struct test_final_data {
	uint64_t be4;
	uint64_t be3;
	uint64_t be2;
	uint64_t be1;

	char sep1;

	uint64_t le4;
	uint64_t le3;
	uint64_t le2;
	uint64_t le1;

	char sep2[2];

	char blob_a[8];
	char blob_b[8];

	struct vl_message msg;
};

#define TEST_DATA_ELEMENTS 12


/*
 *  The main output receives an identical message_1 as the one we sent in,
 *  we check for correct endianess among other things
 */
int test_type_array_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;
	struct test_result *result = poll_data->private_data;

	result->message = NULL;
	result->result = 1;

	(void)(size);

	struct vl_message *message = (struct vl_message *) data;
	struct rrr_array collection = {0};

	TEST_MSG("Received a message in test_type_array_callback of class %" PRIu32 "\n", message->class);

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("dump message: 0x");
		for (unsigned int i = 0; i < sizeof(*message) + message->length - 1; i++) {
			char c = ((char*)message)[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
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

	if (collection.node_count != TEST_DATA_ELEMENTS) {
		TEST_MSG("Wrong number of elements in result from output in test_type_array_callback\n");
		ret = 1;
		goto out_free_collection;
	}

	rrr_type_length final_length = 0;
	RRR_LINKED_LIST_ITERATE_BEGIN(&collection,struct rrr_type_value);
		final_length += node->total_stored_length;
	RRR_LINKED_LIST_ITERATE_END(&collection);

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

	final_data_raw->be4 = *((uint64_t*) (types[0]->data));
	final_data_raw->be3 = *((uint64_t*) (types[1]->data));
	final_data_raw->be2 = *((uint64_t*) (types[2]->data));
	final_data_raw->be1 = *((uint64_t*) (types[3]->data));

	final_data_raw->le4 = *((uint64_t*) (types[5]->data));
	final_data_raw->le3 = *((uint64_t*) (types[6]->data));
	final_data_raw->le2 = *((uint64_t*) (types[7]->data));
	final_data_raw->le1 = *((uint64_t*) (types[8]->data));

	rrr_size blob_a_length = types[10]->total_stored_length / types[10]->element_count;
	rrr_size blob_b_length = types[10]->total_stored_length / types[10]->element_count;

	if (types[10]->element_count != 2) {
		VL_MSG_ERR("Error while extracting blobs in test_type_array_callback, array size was not 2\n");
		ret = 1;
		goto out_free_final_data;
	}

	const char *blob_a = types[10]->data;
	const char *blob_b = types[10]->data + types[10]->total_stored_length / types[10]->element_count;

	if (blob_a_length != sizeof(final_data_raw->blob_a)) {
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

	strcpy(final_data_raw->blob_a, blob_a);
	strcpy(final_data_raw->blob_b, blob_b);

	final_data_raw->msg = *((struct vl_message *) types[11]->data);

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

	if (final_data_raw->be2 != 33 ||
		final_data_raw->le2 != 33
	) {
		TEST_MSG("Received wrong data from collection in test_type_array_callback\n");
		ret = 1;
		goto out_free_final_data;
	}

	if (final_data_raw->msg.data_numeric != 33) {
		TEST_MSG("Received wrong value %" PRIu64 " in message of array in test_type_array_callback\n",
				final_data_raw->msg.data_numeric);
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
		RRR_FREE_IF_NOT_NULL(data);
	}
	else {
		result->message = message;
	}

	return ret;
}

int test_do_poll_loop (
		struct test_result *test_result,
		struct instance_thread_data *thread_data,
		int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE),
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE)
) {
	int ret = 0;

	// Poll from output
	for (int i = 1; i <= 10 && test_result->message == NULL; i++) {
		TEST_MSG("Test result polling try: %i of 10\n", i);

		struct fifo_callback_args poll_data = {NULL, test_result, 0};
		ret = poll_delete(thread_data, callback, &poll_data, 150);
		if (ret != 0) {
			TEST_MSG("Error from poll_delete function in test_type_array\n");
			ret = 1;
			goto out;
		}

		TEST_MSG("Result of polling: %i\n", test_result->result);
	}

	out:
	return ret;
}

int test_type_array (
		struct vl_message **result_message_1,
		struct vl_message **result_message_2,
		struct instance_metadata_collection *instances,
		const char *input_name,
		const char *output_name_1,
		const char *output_name_2
) {
	int ret = 0;
	*result_message_1 = NULL;
	*result_message_2 = NULL;

	struct ip_buffer_entry *entry = NULL;
	struct test_data *data = NULL;

	struct instance_metadata *input = instance_find(instances, input_name);
	struct instance_metadata *output_1 = instance_find(instances, output_name_1);
	struct instance_metadata *output_2 = instance_find(instances, output_name_2);

	if (input == NULL || output_1 == NULL || output_2 == NULL) {
		TEST_MSG("Could not find input and output instances %s and %s in test_type_array\n",
				input_name, output_name_1);
		return 1;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);
	int (*poll_delete_1)(RRR_MODULE_POLL_SIGNATURE);
	int (*poll_delete_2)(RRR_MODULE_POLL_SIGNATURE);

	inject = input->dynamic_data->operations.inject;
	poll_delete_1 = output_1->dynamic_data->operations.poll_delete;
	poll_delete_2 = output_2->dynamic_data->operations.poll_delete;

	if (inject == NULL || poll_delete_1 == NULL || poll_delete_2 == NULL) {
		TEST_MSG("Could not find inject and/or poll_delete in modules in test_type_array\n");
		return 1;
	}

	// Allocate more bytes as we need to pass ip_buffer_entry around (although we are actually not a vl_message)

	data = malloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	data->be4[0] = 1;
	data->be4[2] = 2;

	data->be3[0] = 1;
	data->be3[1] = 2;

	data->be2 = htobe16(33);

	data->be1 = 1;

	data->sep1 = ';';

	data->le4[1] = 2;
	data->le4[3] = 1;

	data->le3[1] = 2;
	data->le3[2] = 1;

	data->le2 = htole16(33);

	data->le1 = 1;

	data->sep2[0] = '|';
	data->sep2[1] = '|';

	sprintf(data->blob_a, "abcdefg");
	sprintf(data->blob_b, "gfedcba");

	data->msg.network_size = sizeof(struct vl_message) - 1;
	data->msg.msg_size = sizeof(struct vl_message) - 1;
	data->msg.msg_type = RRR_SOCKET_MSG_TYPE_VL_MESSAGE;
	data->msg.length = 0;
	data->msg.data_numeric = 33;
	data->msg.type = MSG_TYPE_MSG;
	data->msg.class = MSG_CLASS_POINT;

	message_prepare_for_network(&data->msg);
	rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) &data->msg);

	if (ip_buffer_entry_new(&entry, sizeof(struct test_data) - 1, NULL, 0, data) != 0) {
		TEST_MSG("Could not create ip buffer entry in test_type_array\n");
		ret = 1;
		goto out;
	}
	data = NULL;

	ret = inject(input->thread_data, entry);
	if (ret != 0) {
		TEST_MSG("Error from inject function in test_type_array\n");
		ret = 1;
		goto out;
	}
	entry = NULL;

	// Poll from first output
	struct test_result test_result_1 = {1, NULL};
	ret |= test_do_poll_loop(&test_result_1, output_1->thread_data, poll_delete_1, test_type_array_callback);
	TEST_MSG("Result of test_type_array 1/2, should be 2: %i\n", test_result_1.result);
	*result_message_1 = test_result_1.message;

	// Poll from second output
	struct test_result test_result_2 = {1, NULL};
	ret |= test_do_poll_loop(&test_result_2, output_2->thread_data, poll_delete_2, test_type_array_callback);
	TEST_MSG("Result of test_type_array 2/2, should be 2: %i\n", test_result_2.result);
	*result_message_2 = test_result_2.message;

	// Error if result is not two from both polls
	ret |= (test_result_1.result != 2) | (test_result_2.result != 2);

	out:
	RRR_FREE_IF_NOT_NULL(data);
	if (entry != NULL) {
		ip_buffer_entry_destroy(entry);
	}
	return ret;
}

int test_type_array_mysql_and_network_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	VL_DEBUG_MSG_4("Received message_1 of size %lu in test_type_array_mysql_and_network_callback\n", size);

	/* We actually receive an ip_buffer_entry but we don't need IP-stuff */
	struct test_result *test_result = poll_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	test_result->message = message;
	test_result->result = 0;

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
	"CREATE TABLE IF NOT EXISTS `rrr-test-array-types` ("
		"`int1` bigint(20) NOT NULL,"
		"`int2` bigint(20) NOT NULL,"
		"`int3` bigint(20) NOT NULL,"
		"`int4` bigint(20) NOT NULL,"
		"`int5` bigint(20) NOT NULL,"
		"`int6` bigint(20) NOT NULL,"
		"`int7` bigint(20) NOT NULL,"
		"`int8` bigint(20) NOT NULL,"
		"`vl_message` blob NOT NULL,"
		"`blob_combined` blob NOT NULL,"
		"`timestamp` bigint(20) NOT NULL"
	") ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	void *ptr;
	MYSQL mysql;

	ptr = mysql_init(&mysql);
	if (ptr == NULL) {
		VL_MSG_ERR ("Could not initialize MySQL\n");
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
		VL_MSG_ERR ("mysql_type_array_setup_mysql: Failed to connect to database: Error: %s\n",
				mysql_error(&mysql));
		ret = 1;
		goto out;
	}

	if (mysql_query(&mysql, create_table_sql)) {
		VL_MSG_ERR ("mysql_type_array_setup_mysql: Failed to create table: Error: %s\n",
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
		const struct vl_message *message
) {
	int ret = 0;

	struct test_result test_result = {1, NULL};
	struct test_type_array_mysql_data mysql_data = {NULL, NULL, NULL, NULL, 0};
	struct vl_message *new_message = NULL;
	struct ip_buffer_entry *entry = NULL;
	uint64_t expected_ack_timestamp = message->timestamp_from;

	pthread_cleanup_push(test_type_array_mysql_data_cleanup, &mysql_data);
	VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(new_message, new_message);
	VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(entry, entry);
	VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(test_result, test_result.message);

	new_message = message_duplicate(message);
	if (new_message == NULL) {
		VL_MSG_ERR("Could not duplicate message in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	if (ip_buffer_entry_new(&entry, message->length, NULL, 0, new_message) != 0) {
		TEST_MSG("Could not allocate ip buffer entry in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}
	new_message = NULL;

	struct instance_metadata *input_buffer = instance_find(instances, input_buffer_name);
	struct instance_metadata *tag_buffer = instance_find(instances, tag_buffer_name);
	struct instance_metadata *mysql = instance_find(instances, mysql_name);

	if (input_buffer == NULL || tag_buffer == NULL || mysql == NULL) {
		TEST_MSG("Could not find input, tag and mysql instances %s, %s and %s in test_type_array_mysql_and_network\n",
				input_buffer_name, tag_buffer_name, mysql_name);
		ret = 1;
		goto out;
	}

	ret = test_type_array_mysql_steal_config(&mysql_data, mysql);
	if (ret != 0) {
		VL_MSG_ERR("Failed to get configuration from MySQL in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("The error message_1 'Failed to prepare statement' is fine, it might show up before the table is created\n");
	ret = test_type_array_setup_mysql (&mysql_data);
	if (ret != 0) {
		VL_MSG_ERR("Failed to setup MySQL test environment\n");
		ret = 1;
		goto out;
	}

	int (*inject)(RRR_MODULE_INJECT_SIGNATURE);
	int (*poll_delete)(RRR_MODULE_POLL_SIGNATURE);

	inject = input_buffer->dynamic_data->operations.inject;
	poll_delete = tag_buffer->dynamic_data->operations.poll_delete;

	if (inject == NULL || poll_delete == NULL) {
		TEST_MSG("Could not find inject/poll_delete in modules in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	ret = inject(input_buffer->thread_data, entry);
	if (ret == 0) {
		entry = NULL;
	}
	else {
		VL_MSG_ERR("Error from inject function in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Polling MySQL\n");
	ret |= test_do_poll_loop(&test_result, tag_buffer->thread_data, poll_delete, test_type_array_mysql_and_network_callback);
	TEST_MSG("Result from MySQL buffer callback: %i\n", test_result.result);

	ret = test_result.result;
	if (ret != 0) {
		VL_MSG_ERR("Result was not OK from test_type_array_mysql_and_network_callback\n");
		ret = 1;
		goto out;
	}

	struct vl_message *result_message = test_result.message;
	if (!MSG_IS_TAG(result_message)) {
		VL_MSG_ERR("Message from MySQL was not a TAG message_1\n");
		ret = 1;
		goto out;
	};

	if (result_message->timestamp_from != expected_ack_timestamp) {
		VL_MSG_ERR("Timestamp of TAG message_1 from MySQL did not match original message_1 (%" PRIu64 " vs %" PRIu64 ")\n",
				result_message->timestamp_from, expected_ack_timestamp);
		ret = 1;
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}
