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

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef RRR_WITH_MYSQL
#include <mysql/mysql.h>
#endif

#include "../../lib/log.h"

#include "type_array.h"
#include "../test.h"
#include "../../lib/array.h"
#ifdef RRR_WITH_MYSQL
#include "../../lib/rrr_mysql.h"
#endif

#include "../../lib/instances.h"
#include "../../lib/instance_config.h"
#include "../../lib/modules.h"
#include "../../lib/buffer.h"
#include "../../lib/message_holder/message_holder.h"
#include "../../lib/message_holder/message_holder_struct.h"
#include "../../lib/messages/msg_msg.h"
#include "../../lib/rrr_strerror.h"
#include "../../lib/message_broker.h"
#include "../../lib/ip/ip.h"
#include "../../lib/socket/rrr_socket.h"
#include "../../lib/util/rrr_endian.h"

// Set high to stop test from exiting. Set back to 200 when work is done.
#define RRR_TEST_TYPE_ARRAY_LOOP_COUNT 200

struct rrr_test_result {
	int result;
};

struct rrr_test_callback_data {
	struct rrr_test_result *test_result;
	void *private_data;
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

	struct rrr_msg_msg msg;
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

	struct rrr_msg_msg msg;
};

int test_anything_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	// This cast is really weird, only done in test module. Our caller
	// does not send thread_data struct but test_data struct.
	struct rrr_test_callback_data *callback_data = arg;
	struct rrr_test_result *result = callback_data->test_result;
	struct rrr_msg_msg *message = (struct rrr_msg_msg *) entry->message;

	TEST_MSG("Received a message in test_anything_callback of class %" PRIu32 "\n", MSG_CLASS(message));

	result->result = 2;

	rrr_msg_holder_unlock(entry);

	return 0;
}

int test_do_poll_loop (
		struct rrr_instance *self,
		struct rrr_instance *output,
		struct rrr_message_broker *broker,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		struct rrr_test_callback_data *callback_data
) {
	int ret = 0;

	struct rrr_test_result *test_result = callback_data->test_result;

	rrr_message_broker_costumer_handle *handle_self = NULL;
	rrr_message_broker_costumer_handle *handle_output = NULL;

	uint64_t limit = rrr_time_get_64() + 2000000; // 2 seconds (6 zeros)

	while (rrr_time_get_64() < limit && (handle_output == NULL || handle_self == NULL)) {
		handle_output = rrr_message_broker_costumer_find_by_name(broker, INSTANCE_M_NAME(output));
		handle_self = rrr_message_broker_costumer_find_by_name(broker, INSTANCE_M_NAME(self));
		rrr_posix_usleep(50000);
	}

	if (handle_output == NULL || handle_self == NULL) {
		TEST_MSG("Could not find message broker handle for output '%s' or self after 2 seconds in test_do_poll_loop\n",
				INSTANCE_M_NAME(output));
		ret = 1;
		goto out;
	}

	// Poll from output
	for (int i = 1; i <= RRR_TEST_TYPE_ARRAY_LOOP_COUNT && test_result->result != 2; i++) {
		if (rrr_thread_signal_encourage_stop_check(self->thread) == 1) {
			break;
		}

		rrr_thread_watchdog_time_update(self->thread);

		TEST_MSG("Test result polling from %s try: %i of %i\n",
				INSTANCE_M_NAME(output), i, RRR_TEST_TYPE_ARRAY_LOOP_COUNT);

		ret = rrr_message_broker_poll_delete (
				broker,
				handle_output,
				handle_self,
				0,
				callback,
				callback_data,
				150
		);

		if (ret != 0) {
			TEST_MSG("Error from poll_delete function in test_type_array\n");
			ret = 1;
			goto out;
		}

		if (test_result->result == 3) {
			// Ignore this message
			ret = 0;
			test_result->result = 1;
		}
		else {
			TEST_MSG("Result of polling from %s: %i\n",
					INSTANCE_M_NAME(output), test_result->result);
		}
	}

	out:
	return ret;
}

int test_type_array_write_to_socket (struct test_data *data, struct rrr_instance *socket_metadata) {
	char *socket_path = NULL;
	int ret = 0;
	int socket_fd = 0;

	ret = rrr_instance_config_get_string_noconvert (&socket_path, socket_metadata->config, "socket_path");
	if (ret != 0) {
		TEST_MSG("Could not get configuration parameter from socket module\n");
		goto out;
	}

	if (rrr_socket_unix_connect (
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
		TEST_MSG("Only %i of %llu bytes written in test_type_array_write_to_socket\n",
				ret, (long long unsigned) sizeof(*data) - 1);
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
	struct rrr_test_callback_data *callback_data = arg;
	struct rrr_test_result *result = callback_data->test_result;

	struct rrr_msg_msg *message = (struct rrr_msg_msg *) entry->message;

	int ret = 0;

	struct rrr_array array_tmp = {0};

	if (MSG_IS_ARRAY(message)) {
		uint16_t array_version_dummy;
		if (rrr_array_message_append_to_collection(&array_version_dummy, &array_tmp, message) != 0) {
			TEST_MSG("Could not create array collection in test_averager_callback\n");
			ret = 1;
			goto out;
		}

//		printf ("== Averager test dump received array ========================================\n");
//		rrr_array_dump(&array_tmp);

		const struct rrr_type_value *value = NULL;
		if ((value = rrr_array_value_get_by_tag(&array_tmp, "measurement")) != NULL) {
			// Copies of the original four point measurements should arrive first
			result->result++;
		}
		else {
			uint64_t value_average;
			uint64_t value_max;
			uint64_t value_min;

			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_average, &array_tmp, "average", 0);
			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_max, &array_tmp, "max", 0);
			ret |= rrr_array_get_value_unsigned_64_by_tag(&value_min, &array_tmp, "min", 0);

			// Average message arrives later
			if (result->result != 4) {
				TEST_MSG("Received average result in test_averager_callback but not all four point measurements were received prior to that\n");
				ret = 1;
				goto out;
			}

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

			result->result = 2;
		}
	}
	else {
		TEST_MSG("Unknown non-array message received in test_averager_callback\n");
		ret = 1;
		goto out;
	}

	out:
	rrr_msg_holder_unlock(entry);
	rrr_array_clear(&array_tmp);
	return ret;
}

int test_averager (
		RRR_TEST_FUNCTION_ARGS
) {
	(void)(test_function_data);

	// Preconditions for this test:
	// - Sender of the averager module is a voltmonitor module with configuration
	//   parameter vm_do_spawn_test_messages

	int ret = 0;

	struct rrr_test_result test_result = {0};

	struct rrr_instance *output = rrr_instance_find(instances, output_name);
	if (output == NULL) {
		TEST_MSG("Could not find output instances %s in test_averager\n",
				output_name);
		ret = 1;
		goto out;
	}

	struct rrr_test_callback_data callback_data = { &test_result, NULL };

	// Poll from first output
	TEST_MSG("Polling from %s\n", INSTANCE_M_NAME(output));
	ret |= test_do_poll_loop(
			INSTANCE_D_INSTANCE(self_thread_data),
			output,
			INSTANCE_D_BROKER(self_thread_data),
			test_averager_callback,
			&callback_data
	);
	TEST_MSG("Result of test_averager, should be 2: %i\n", test_result.result);

	out:
	return ret;
}

#define TEST_DATA_ELEMENTS 13

struct rrr_test_type_array_callback_data {
	const struct rrr_test_function_data *config;
};

/*
 *  The main output receives an identical message_1 as the one we sent in,
 *  we check for correct endianess among other things
 */
int test_type_array_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	// This cast is really weird, only done in test module. Our caller
	// does not send thread_data struct but test_data struct.
	struct rrr_test_callback_data *callback_data = arg;
	struct rrr_test_result *result = callback_data->test_result;
	struct rrr_test_type_array_callback_data *array_callback_data = callback_data->private_data;
	const struct rrr_test_function_data *config = array_callback_data->config;

	result->result = 1;

	struct rrr_msg_msg *message = (struct rrr_msg_msg *) entry->message;

	char *str_to_h_tmp = NULL;

	struct rrr_array collection = {0};
	struct rrr_array collection_converted = {0};

	struct test_final_data *final_data_raw = NULL;

	TEST_MSG("Received a message in test_type_array_callback of class %" PRIu32 "\n", MSG_CLASS(message));

	if (RRR_DEBUGLEVEL_3) {
// TODO : Needs to be put in a buffer then written out
/*		RRR_DBG("dump message: 0x");
		for (unsigned int i = 0; i < MSG_TOTAL_SIZE(message); i++) {
			char c = ((char*)message)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");*/
	}

	if (!MSG_IS_ARRAY(message)) {
		// Ignore non-array messages
		TEST_MSG("Message received in test_type_array_callback was not an array, ignoring\n");
		result->result = 3;
		ret = 0;
		goto out;
	}

	uint16_t array_version_dummy;
	if (rrr_array_message_append_to_collection(&array_version_dummy, &collection, message) != 0) {
		TEST_MSG("Error while parsing message from output function in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (collection.node_count < TEST_DATA_ELEMENTS) {
		TEST_MSG("Not enough elements in result from output in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	rrr_length final_length = 0;
	RRR_LL_ITERATE_BEGIN(&collection,struct rrr_type_value);
		final_length += node->total_stored_length;
	RRR_LL_ITERATE_END();

	const struct rrr_type_value *types[13];

	// After the array has been assembled and then disassembled again, all
	// short numbers become full length 8 bytes numbers
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

	types[12] = rrr_array_value_get_by_index(&collection, 12);

	// In some tests chains, the integers become text strings
	if (config->do_array_str_to_h_conversion) {
		for (int i = 0; i < 9; i++) {
			if (i == 4) {
				// Skip separator
				i++;
			}

			if (RRR_TYPE_IS_BLOB(types[i]->definition->type)) {
				RRR_FREE_IF_NOT_NULL(str_to_h_tmp);
				if (types[i]->definition->to_str(&str_to_h_tmp, types[i]) != 0) {
					TEST_MSG("Error while converting blob to string in test_type_array_callback\n");
					ret = 1;
					goto out;
				}

				TEST_MSG("Doing str to h conversion for value at position %i string is '%s'\n", i, str_to_h_tmp);

				if (*str_to_h_tmp == '-') {
					char *tail = NULL;
					int64_t num = strtoll(str_to_h_tmp, &tail, 10);
					if (rrr_array_push_value_i64_with_tag(&collection_converted, "", num) != 0) {
						TEST_MSG("Error while pushing temporary signed value to array in test_type_array_callback\n");
						ret = 1;
						goto out;
					}
				}
				else {
					char *tail = NULL;
					uint64_t num = strtoull(str_to_h_tmp, &tail, 10);
					if (rrr_array_push_value_u64_with_tag(&collection_converted, "", num) != 0) {
						TEST_MSG("Error while pushing temporary unsigned value to array in test_type_array_callback\n");
						ret = 1;
						goto out;
					}
				}

				// types[] is not responsible for memory, safe to replace pointer
				types[i] = RRR_LL_LAST(&collection_converted);
			}
		}
	}

	// In some tests chains, the blob field is merged into one single value
	if (config->do_blob_field_divide) {
		const struct rrr_type_value *value_blob = types[10];
		if (RRR_TYPE_IS_BLOB(value_blob->definition->type)) {
			if (value_blob->element_count == 1) {
				rrr_length length_new = value_blob->total_stored_length / 2;

				if (length_new * 2 != value_blob->total_stored_length) {
					TEST_MSG("Could not split blob field, stored length was not divisible by 2\n");
					ret = 1;
					goto out;
				}

				struct rrr_type_value *value_new;
				if (rrr_type_value_allocate_and_import_raw (
						&value_new,
						&rrr_type_definition_blob, // Has to be blob to support two values
						value_blob->data,
						value_blob->data + value_blob->total_stored_length,
						0,
						NULL,
						length_new,
						2
				) != 0) {
					TEST_MSG("Could not import blob when splitting\n");
					ret = 1;
					goto out;
				}

				RRR_LL_APPEND(&collection_converted, value_new);

				// types[] is not responsible for memory, safe to replace pointer
				types[10] = value_new;
			}
		}
	}

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
	for (int i = 12; i < 13; i++) {
		TEST_MSG("Type %i: %u (%s)\n", i, types[i]->definition->type, (types[i]->definition->type == RRR_TYPE_STR ? "OK" : "NOT OK"));
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
		types[11]->definition->type != RRR_TYPE_MSG ||
		types[12]->definition->type != RRR_TYPE_STR
	) {
		TEST_MSG("Wrong types in collection in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	final_data_raw = malloc(sizeof(*final_data_raw));

	memset(final_data_raw, '\0', sizeof(*final_data_raw));

	final_data_raw->be4 = *((uint64_t*) (types[0]->data));
	final_data_raw->be3 = *((uint64_t*) (types[1]->data));
	final_data_raw->be2 = *((int64_t*) (types[2]->data));
	final_data_raw->be1 = *((uint64_t*) (types[3]->data));

	TEST_MSG("Result for BE fields: %" PRIu64 ", %" PRIu64 ", %" PRIi64 ", %" PRIu64 "\n",
			final_data_raw->be4, final_data_raw->be3, final_data_raw->be2, final_data_raw->be1);

	final_data_raw->le4 = *((uint64_t*) (types[5]->data));
	final_data_raw->le3 = *((uint64_t*) (types[6]->data));
	final_data_raw->le2 = *((int64_t*) (types[7]->data));
	final_data_raw->le1 = *((uint64_t*) (types[8]->data));

	TEST_MSG("Result for LE fields: %" PRIu64 ", %" PRIu64 ", %" PRIi64 ", %" PRIu64 "\n",
			final_data_raw->le4, final_data_raw->le3, final_data_raw->le2, final_data_raw->le1);

	rrr_length blob_a_length = types[10]->total_stored_length / types[10]->element_count;
	rrr_length blob_b_length = types[10]->total_stored_length / types[10]->element_count;

	if (types[10]->element_count != 2) {
		RRR_MSG_0("Error while extracting blobs in test_type_array_callback, array size was not 2\n");
		ret = 1;
		goto out;
	}

	const char *blob_a = types[10]->data;
	const char *blob_b = types[10]->data + types[10]->total_stored_length / types[10]->element_count;

	if (blob_a_length != sizeof(final_data_raw->blob_a)) {
		RRR_MSG_0("Blob sizes not equal in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (blob_a[blob_a_length - 1] != '\0' || blob_b[blob_b_length - 1] != '\0') {
		RRR_MSG_0("Returned blobs were not zero terminated in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (strcmp(blob_a, "abcdefg") != 0 || strcmp(blob_b, "gfedcba") != 0) {
		RRR_MSG_0("Returned blobs did not match input in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (types[12]->total_stored_length != 0) {
		char *tmp = NULL;
		types[12]->definition->to_str(&tmp, types[12]);
		RRR_MSG_0("Returned empty string was not empty, value was '%s'\n",
			(tmp != NULL ? tmp : "(conversion failed)")
		);
		ret = 1;
		goto out;
	}

	strcpy(final_data_raw->blob_a, blob_a);
	strcpy(final_data_raw->blob_b, blob_b);

	memcpy (&final_data_raw->msg, types[11]->data, types[11]->total_stored_length);

	if (final_data_raw->le1 == final_data_raw->le3 ||
		final_data_raw->le3 == final_data_raw->le4 ||
		final_data_raw->le4 == final_data_raw->le1
	) {
		TEST_MSG("Values did not differ in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (final_data_raw->be1 != final_data_raw->le1 ||
		final_data_raw->be2 != final_data_raw->le2 ||
		final_data_raw->be3 != final_data_raw->le3 ||
		final_data_raw->be4 != final_data_raw->le4
	) {
		TEST_MSG("Mismatch of data, possible corruption in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (final_data_raw->be1 == 0 ||
		final_data_raw->be2 == 0 ||
		final_data_raw->be3 == 0 ||
		final_data_raw->be4 == 0
	) {
		TEST_MSG("Received zero data from collection in test_type_array_callback\n");
		ret = 1;
		goto out;
	}

	if (final_data_raw->be2 != -33 ||
		final_data_raw->le2 != -33
	) {
		TEST_MSG("Received wrong data from collection in test_type_array_callback, expects -33 but got 0x%" PRIx64 " and 0x%" PRIx64 "\n",
				final_data_raw->be2, final_data_raw->le2);
		ret = 1;
		goto out;
	}

	result->result = 2;

	out:
		RRR_FREE_IF_NOT_NULL(final_data_raw);
		rrr_array_clear(&collection);
		rrr_array_clear(&collection_converted);
		RRR_FREE_IF_NOT_NULL(str_to_h_tmp);
		rrr_msg_holder_unlock(entry);

		return ret;
}

int test_array (
		RRR_TEST_FUNCTION_ARGS
) {
	int ret = 0;

	struct rrr_test_result test_result_1 = {1};

	struct rrr_instance *output_1 = rrr_instance_find(instances, output_name);
	if (output_1 == NULL) {
		TEST_MSG("Could not find output instance %s in test_type_array\n",
				output_name);
		return 1;
	}

	struct rrr_test_type_array_callback_data array_callback_data = { test_function_data };
	struct rrr_test_callback_data callback_data = { &test_result_1, &array_callback_data };

	// Poll from first output
	TEST_MSG("Polling from %s\n", INSTANCE_M_NAME(output_1));
	ret |= test_do_poll_loop(
			INSTANCE_D_INSTANCE(self_thread_data),
			output_1,
			INSTANCE_D_BROKER(self_thread_data),
			test_type_array_callback,
			&callback_data
	);
	if (ret != 0) {
		goto out;
	}

	TEST_MSG("Result of test_type_array, should be 2: %i\n", test_result_1.result);

	// Error if result is not two from both polls
	ret |= (test_result_1.result != 2);

	out:
	return ret;
}

int test_anything (
		RRR_TEST_FUNCTION_ARGS
) {
	(void)(test_function_data);

	int ret = 0;

	struct rrr_test_result test_result_1 = {1};

	struct rrr_instance *output_1 = rrr_instance_find(instances, output_name);
	if (output_1 == NULL) {
		TEST_MSG("Could not find output instance %s in test_type_array\n",
				output_name);
		return 1;
	}

	struct rrr_test_callback_data callback_data = { &test_result_1, NULL };

	// Poll from first output
	TEST_MSG("Polling from %s\n", INSTANCE_M_NAME(output_1));
	ret |= test_do_poll_loop(
			INSTANCE_D_INSTANCE(self_thread_data),
			output_1,
			INSTANCE_D_BROKER(self_thread_data),
			test_anything_callback,
			&callback_data
	);
	if (ret != 0) {
		goto out;
	}
	TEST_MSG("Result of test_anything, should be 2: %i\n", test_result_1.result);

	// Error if result is not two from both polls
	ret |= (test_result_1.result != 2);

	out:
	return ret;
}

#ifdef RRR_WITH_MYSQL
int test_type_array_mysql_and_network_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_test_callback_data *callback_data = arg;
	struct rrr_test_result *test_result = callback_data->test_result;

	int ret = 0;

	RRR_DBG_2("Received message_1 in test_type_array_mysql_and_network_callback\n");

	test_result->result = 2;

	struct rrr_msg_msg *result_message = entry->message;
	if (!MSG_IS_TAG(result_message)) {
		RRR_MSG_0("Message from MySQL was not a TAG message\n");
	};

	rrr_msg_holder_unlock(entry);
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
		"`rrr_msg_msg` blob NOT NULL,"
		"`blob_combined` blob NOT NULL,"
		"`timestamp` bigint(20) NOT NULL"
	") ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	void *ptr;
	MYSQL mysql;

	ptr = mysql_init(&mysql);
	if (ptr == NULL) {
		RRR_MSG_0 ("Could not initialize MySQL\n");
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
		RRR_MSG_0 ("mysql_type_array_setup_mysql: Failed to connect to database: Error: %s\n",
				mysql_error(&mysql));
		ret = 1;
		goto out;
	}

	TEST_MSG("%s\n", create_table_sql);

	if (mysql_query(&mysql, create_table_sql)) {
		RRR_MSG_0 ("mysql_type_array_setup_mysql: Failed to create table: Error: %s\n",
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

int test_type_array_mysql_steal_config(struct test_type_array_mysql_data *data, struct rrr_instance *mysql) {
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

int test_type_array_mysql (
		RRR_TEST_FUNCTION_ARGS
) {
	(void)(test_function_data);

	int ret = 0;

	struct rrr_test_result test_result = {1};
	struct test_type_array_mysql_data mysql_data = {NULL, NULL, NULL, NULL, 0};
	struct rrr_msg_holder *entry = NULL;

	struct rrr_instance *tag_buffer = rrr_instance_find(instances, output_name);

	if (tag_buffer == NULL) {
		TEST_MSG("Could not find output instance %s in test_type_array_mysql_and_network\n",
				output_name);
		ret = 1;
		goto out;
	}

	struct rrr_instance *mysql = NULL;
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;
		if (strcmp(INSTANCE_M_MODULE_NAME(instance), "mysql") == 0) {
			mysql = instance;
		}
	RRR_LL_ITERATE_END();

	if (mysql == NULL) {
		TEST_MSG("Could not find any MySQL instance from which to get configuration to setup database in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	ret = test_type_array_mysql_steal_config(&mysql_data, mysql);
	if (ret != 0) {
		RRR_MSG_0("Failed to get configuration from MySQL in test_type_array_mysql_and_network\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("The error message_1 'Failed to prepare statement' is fine, it might show up before the table is created\n");
	ret = test_type_array_setup_mysql (&mysql_data);
	if (ret != 0) {
		RRR_MSG_0("Failed to setup MySQL test environment\n");
		ret = 1;
		goto out;
	}

	struct rrr_test_callback_data callback_data = { &test_result, NULL };

	TEST_MSG("Polling MySQL\n");
	ret |= test_do_poll_loop(
			INSTANCE_D_INSTANCE(self_thread_data),
			tag_buffer,
			INSTANCE_D_BROKER(self_thread_data),
			test_type_array_mysql_and_network_callback,
			&callback_data
	);
	TEST_MSG("Result from MySQL buffer callback: %i\n", test_result.result);

	if (test_result.result != 2) {
		RRR_MSG_0("Result was not OK from test_type_array_mysql_and_network_callback\n");
		ret = 1;
		goto out;
	}

	out:
	test_type_array_mysql_data_cleanup(&mysql_data);
	if (entry != NULL) {
		rrr_msg_holder_decref_while_locked_and_unlock(entry);
	}

	return ret;
}

#endif
