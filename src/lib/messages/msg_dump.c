/*

Read Route Record

Copyright (C) 2021-2023 Atle Solbakken atle@goliathdns.no

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

#include "msg_msg.h"
#include "msg_addr.h"
#include "msg_log.h"
#include "../array.h"
#include "../allocator.h"
#include "../helpers/string_builder.h"
#include "../util/macro_utils.h"
#include "../ip/ip_defines.h"

static int __rrr_msg_dump_msg (
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};
	char *topic_tmp = NULL;

	RRR_MSG_1("== Type: RRR Message (%s)\n", MSG_TYPE_NAME(msg));
	RRR_MSG_1("Version: %u\n", msg->version);

	if ((ret = rrr_msg_msg_topic_get(&topic_tmp, msg)) != 0) {
		goto out;
	}

	RRR_MSG_1("Topic: %s\n", (topic_tmp != NULL && *topic_tmp != '\0' ? topic_tmp : "(no topic)"));
	RRR_MSG_1("Value: %" PRIu32 "\n", msg->msg_value);
	RRR_MSG_1("Timestamp: %" PRIu64 "\n", msg->timestamp);

	if (MSG_CLASS(msg) == MSG_CLASS_ARRAY) {
		RRR_MSG_1("Class: array\n");
		if (msg->version != RRR_ARRAY_VERSION) {
			RRR_MSG_0("Unsupported version %u, dumps may be unreliable.\n", msg->version);
			goto out;
		}

		uint16_t array_version = 0;
		if ((ret = rrr_array_message_append_to_array(&array_version, &array_tmp, msg)) != 0) {
			goto out;
		}

		if (RRR_DEBUGLEVEL_2) {
			rrr_array_dump(&array_tmp);
		}
	}
	else if (MSG_CLASS(msg) == MSG_CLASS_DATA) {
		RRR_MSG_1("Class: data\n");
		RRR_MSG_1("Data size: %llu\n", (unsigned long long int) MSG_DATA_LENGTH(msg));
		if (RRR_DEBUGLEVEL_6) {
			struct rrr_string_builder str_tmp = {0};
			const unsigned char *buf = (const unsigned char *) MSG_DATA_PTR(msg);
			for (unsigned int i = 0; i < MSG_DATA_LENGTH(msg); i++) {
				rrr_string_builder_append_format(&str_tmp, "%02x-", *(buf + i));
			}
			RRR_DBG_6("Data: %s\n", rrr_string_builder_buf(&str_tmp));
			rrr_string_builder_clear(&str_tmp);
		}
	}
	else {
		RRR_MSG_0("Unknown class %u\n", MSG_CLASS(msg));
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_msg_dump_msg_callback (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	(void)(arg1);
	(void)(arg2);

	return __rrr_msg_dump_msg(*message);
}

static int __rrr_msg_dump_addr_callback (
		const struct rrr_msg_addr *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Address Message\n");
	RRR_MSG_1("Transport: %s\n", RRR_IP_TRANSPORT_NAME(message->protocol));

	char str[256];
	rrr_msg_addr_to_str(str, sizeof(str), message);

	RRR_MSG_1("Address: %s\n", str);

	return ret;
}

static int __rrr_msg_dump_log_callback (
		const struct rrr_msg_log *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Log Message\n");

	char *prefix_tmp = NULL;
	char *message_tmp = NULL;

	if ((ret = rrr_msg_msg_log_to_str(&prefix_tmp, &message_tmp, message)) != 0) {
		goto out;
	}

	RRR_MSG_1("RRR loglevel: %u\n", message->loglevel_orig);
	RRR_MSG_1("RFC loglevel: %u\n", message->loglevel_translated);
	RRR_MSG_1("Is stdout: %u\n", message->is_stdout);
	RRR_MSG_1("Location: %s:%" PRIu32 "\n", message->file, message->line);
	RRR_MSG_1("Prefix: %s\n", prefix_tmp);
	RRR_MSG_1("Message: %s\n", message_tmp);

	out:
	RRR_FREE_IF_NOT_NULL(prefix_tmp);
	RRR_FREE_IF_NOT_NULL(message_tmp);
	return ret;
}

#define PRINT_FLAG(flag) \
	RRR_MSG_1("- " RRR_QUOTE(flag) ": %s\n", RRR_MSG_CTRL_F_HAS(message, RRR_PASTE(RRR_MSG_CTRL_F_,flag)) ? "yes" : "no")

static int __rrr_msg_dump_ctrl_callback (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Control Message\n");
	RRR_MSG_1("Flags: %u\n", RRR_MSG_CTRL_FLAGS(message));
	PRINT_FLAG(PING);
	PRINT_FLAG(PONG);
	PRINT_FLAG(ACK);
	PRINT_FLAG(NACK);
	PRINT_FLAG(USR_A);
	PRINT_FLAG(USR_B);
	PRINT_FLAG(USR_C);
	PRINT_FLAG(USR_D);

	return ret;
}

int rrr_msg_dump_to_host_and_dump (
		struct rrr_msg *msg,
		rrr_length expected_size
) {
	int ret = 0;

	RRR_DBG_3("Header value: %" PRIu32 "\n", rrr_htobe32(msg->msg_value));
	RRR_DBG_3("Header CRC32: %" PRIu32 "\n", rrr_htobe32(msg->header_crc32));
	RRR_DBG_3("Data   CRC32: %" PRIu32 "\n", rrr_htobe32(msg->data_crc32));

	if ((ret = rrr_msg_to_host_and_verify_with_callback (
			&msg,
			expected_size,
			__rrr_msg_dump_msg_callback,
			__rrr_msg_dump_addr_callback,
			__rrr_msg_dump_log_callback,
			__rrr_msg_dump_ctrl_callback,
			NULL,
			NULL,
			NULL
	)) != 0) {
		if (RRR_MSG_IS_SETTING(msg)) {
			RRR_MSG_1("Possibly an RRR Setting Message (dump not supported)\n");
		}
		else if (RRR_MSG_IS_STATS(msg)) {
			RRR_MSG_1("Possibly an RRR Stats Engine Tree Data Message (dump not supported)\n");
		}
		goto out;
	}

	out:
	return ret;
}

int rrr_msg_dump_msg (
		const struct rrr_msg_msg *msg
) {
	return __rrr_msg_dump_msg (msg);
}
