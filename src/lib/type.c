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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "../macro_utils.h"
#include "type.h"
#include "fixed_point.h"
#include "socket/rrr_socket.h"
#include "socket/rrr_socket_msg.h"
#include "messages.h"
#include "rrr_endian.h"

static int __rrr_type_convert_integer_10(char **end, long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoll(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_type_convert_unsigned_integer_10(char **end, unsigned long long int *result, const char *value) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

#define CHECK_END_AND_RETURN(length)		\
	if (start + length > end) {				\
		return RRR_TYPE_PARSE_INCOMPLETE;	\
	}

static uint64_t __rrr_type_expand_be (
		rrr_type_length import_length,
		const char *src,
		rrr_type_flags flags
) {
	union beunion {
		rrr_type_be temp_f;
		unsigned char temp_b[sizeof(rrr_type_be)];
	};


	union beunion temp;


	temp.temp_f = 0;
	if (RRR_TYPE_FLAG_IS_SIGNED(flags)) {
		unsigned char sign = (*src) & 0x80;
		if (sign > 0) {
			temp.temp_f = 0xffffffffffffffff;
		}
	}

	rrr_type_length wpos = sizeof(temp.temp_f) - 1;
	rrr_type_length rpos = import_length - 1;

	// VL_DEBUG_MSG_3("rpos: %d, wpos: %d\n", rpos, wpos);

	/* Big endian:
	 * (0x00 0x00 0x01)be = 1
	 * (0x00 0x00 0x00 0x00 0x01)be = 1
	 * (0xff 0xff 0xff 0xff 0xff)be = huge number or -1 (if signed flag set)
	 */

	unsigned char sign = 0;
	while (1) {
		temp.temp_b[wpos] = src[rpos];

		if (rpos == 0) {
			break;
		}

		wpos--;
		rpos--;
	}

	temp.temp_b[0] |= sign;
	temp.temp_f = rrr_be64toh(temp.temp_f);
	return temp.temp_f;
}

static uint64_t __rrr_type_expand_le (
		rrr_type_length import_length,
		const char *src,
		rrr_type_flags flags
) {
	union leunion {
		rrr_type_le temp_f;
		unsigned char temp_b[sizeof(rrr_type_le)];
	};

	union leunion temp;

	temp.temp_f = 0;
	if (RRR_TYPE_FLAG_IS_SIGNED(flags)) {
		unsigned char sign = (*src + import_length - 1) & 0x80;
		if (sign > 0) {
			temp.temp_f = 0xffffffffffffffff;
		}
	}

	/* Little endian:
	 * (0x01 0x00 0x00)le = 1
	 * (0x01 0x00 0x00 0x00 0x00 0x00)le = 1
	 */

	rrr_type_length pos = 0;
	while (pos < import_length) {
		temp.temp_b[pos] = src[pos];
		pos++;
	}

	temp.temp_f = rrr_le64toh(temp.temp_f);

	return temp.temp_f;
}

static int __rrr_type_import_int (
		RRR_TYPE_IMPORT_ARGS,
		uint64_t (*expander)(rrr_type_length import_length, const char *src, rrr_type_flags flags)
) {
	if (node->import_length > (rrr_type_length) sizeof(uint64_t)) {
		RRR_BUG("BUG: __rrr_type_import_u received length > %lu", sizeof(uint64_t));
	}
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_int\n");
	}

	ssize_t array_size = node->import_elements;
	ssize_t total_size = node->import_elements * node->import_length;

	CHECK_END_AND_RETURN(total_size);

	node->total_stored_length = node->import_elements * sizeof(uint64_t);
	node->data = malloc(node->total_stored_length);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_int\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}

	char *target_wpos = node->data;
	const char *data_rpos = start;

	while (array_size-- > 0) {
		uint64_t result = expander(node->import_length, data_rpos, node->flags);

		memcpy(target_wpos, &result, sizeof(result));

		RRR_DBG_3("Imported a %s64: 0x%" PRIx64 "\n", (RRR_TYPE_FLAG_IS_SIGNED(node->flags) ? "s" : "u"), result);

		data_rpos += node->import_length;
		target_wpos += sizeof(result);
	}

	*parsed_bytes = total_size;

	node->total_stored_length = sizeof(uint64_t) * node->import_elements;
	node->definition = rrr_type_get_from_id(RRR_TYPE_H);

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_le (RRR_TYPE_IMPORT_ARGS) {
	return __rrr_type_import_int(node, parsed_bytes, start, end, __rrr_type_expand_le);
}

static int __rrr_type_import_be (RRR_TYPE_IMPORT_ARGS) {
	return __rrr_type_import_int(node, parsed_bytes, start, end, __rrr_type_expand_be);
}

static int __rrr_type_import_host (RRR_TYPE_IMPORT_ARGS) {
	return (RRR_TYPE_SYSTEM_ENDIAN_IS_LE ?
			__rrr_type_import_le(node, parsed_bytes, start, end) :
			__rrr_type_import_be(node, parsed_bytes, start, end)
	);
}

static int __rrr_type_import_blob (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in import_blob\n");
	}

	ssize_t total_size = node->import_length * node->import_elements;

	CHECK_END_AND_RETURN(total_size);

	node->total_stored_length = total_size;
	node->data = malloc(total_size);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in import_blob\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}
	memcpy(node->data, start, total_size);

	node->total_stored_length = total_size;

	*parsed_bytes = total_size;

	return RRR_TYPE_PARSE_OK;
}

int rrr_type_import_ustr_raw (uint64_t *target, ssize_t *parsed_bytes, const char *start, const char *end) {
	CHECK_END_AND_RETURN(1);

	*parsed_bytes = 0;

	ssize_t max = end - start;
	if (max > 30) {
		max = 30;
	}
	char tmp[max];
	memset(tmp, '\0', sizeof(tmp));
	strncpy(tmp, start, max - 1);

	int found_end_char = 0;
	for (const char *pos = tmp; pos < tmp + sizeof(tmp); pos++) {
		if (*pos >= '0' && *pos <= '9') {
			continue;
		}
		else {
			found_end_char = 1;
			break;
		}
	}

	if (found_end_char == 0) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	char *convert_end = NULL;
	unsigned long long int result = 0;

	if (__rrr_type_convert_unsigned_integer_10(&convert_end, &result, tmp)) {
		RRR_MSG_0("Error while converting unsigned integer in import_ustr\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	memcpy(target, &result, sizeof(rrr_type_ustr));

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_ustr (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in import_ustr\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in import_ustr\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in import_ustr\n");
	}

	int ret = RRR_TYPE_PARSE_OK;

	node->data = malloc(sizeof(rrr_type_ustr));
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in import_ustr\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	if ((ret = rrr_type_import_ustr_raw ((uint64_t *) node->data, parsed_bytes, start, end)) != 0) {
		goto out;
	}

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->total_stored_length = sizeof(rrr_type_h);
	RRR_TYPE_FLAG_SET_UNSIGNED(node->flags);

	out:
	return ret;
}

int rrr_type_import_istr_raw (int64_t *target, ssize_t *parsed_bytes, const char *start, const char *end) {
	CHECK_END_AND_RETURN(1);

	*parsed_bytes = 0;

	ssize_t max = end - start;
	if (max > 30) {
		max = 30;
	}
	char tmp[max];
	memset(tmp, '\0', sizeof(tmp));
	strncpy(tmp, start, max - 1);

	int found_end_char = 0;
	for (const char *pos = tmp + (tmp[0] == '-' || tmp[0] == '+' ? 1 : 0); pos < tmp + sizeof(tmp); pos++) {
		if (*pos >= '0' && *pos <= '9') {
			continue;
		}
		else {
			found_end_char = 1;
			break;
		}
	}

	if (found_end_char == 0) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	char *convert_end = NULL;
	long long int result = 0;

	if (__rrr_type_convert_integer_10(&convert_end, &result, tmp)) {
		RRR_MSG_0("Error while converting unsigned integer in import_istr\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	memcpy(target, &result, sizeof(rrr_type_ustr));

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_istr (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in import_istr\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in import_istr\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in import_istr\n");
	}

	int ret = RRR_TYPE_PARSE_OK;

	node->data = malloc(sizeof(rrr_type_istr));
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in import_istr\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	if ((ret = rrr_type_import_istr_raw ((int64_t*) node->data, parsed_bytes, start, end)) != 0) {
		goto out;
	}

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->total_stored_length = sizeof(rrr_type_h);
	RRR_TYPE_FLAG_SET_SIGNED(node->flags);

	out:
	return ret;
}

static int __rrr_type_validate_sep (char c) {
	return RRR_TYPE_CHAR_IS_SEP(c);
}

static int __rrr_type_validate_stx (char c) {
	return RRR_TYPE_CHAR_IS_STX(c);
}

static int __rrr_type_import_sep_stx (RRR_TYPE_IMPORT_ARGS, int (*validate)(char c)) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in import_sep_stx\n");
	}

	ssize_t total_size = node->import_length * node->element_count;

	ssize_t found = 0;
	for (const char *start_tmp = start; start_tmp < end && found < total_size; start_tmp++) {
		CHECK_END_AND_RETURN(1);

		unsigned char c = *start_tmp;
		if (!validate(c)) {
			RRR_MSG_0("Invalid separator or stx character 0x%01x\n", c);
			return RRR_TYPE_PARSE_SOFT_ERR;
		}

		found++;
	}

	if (found != total_size) {
		RRR_MSG_0("Not enough special characters found\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	node->data = malloc(found);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in import_sep_stx\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}
	memcpy (node->data, start, found);

	node->total_stored_length = total_size;

	*parsed_bytes = found;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_sep (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;
	if ((ret = __rrr_type_import_sep_stx(node, parsed_bytes, start, end, __rrr_type_validate_sep)) != RRR_TYPE_PARSE_OK) {
		RRR_MSG_0("Import of sep type failed\n");
	}
	return ret;
}

static int __rrr_type_import_stx (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;
	if ((ret = __rrr_type_import_sep_stx(node, parsed_bytes, start, end, __rrr_type_validate_stx)) != RRR_TYPE_PARSE_OK) {
		RRR_MSG_0("Import of stx type failed\n");
	}
	return ret;
}

static int __rrr_type_msg_to_host_single (
		struct rrr_message *msg,
		ssize_t max_size
) {
	struct rrr_socket_msg *socket_msg = (struct rrr_socket_msg *) msg;

	int ret = 0;
	ssize_t target_size = 0;

	if (rrr_socket_msg_get_target_size_and_check_checksum (
			&target_size,
			socket_msg,
			max_size
	) != 0) {
		RRR_MSG_0("Invalid header for message in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (max_size < target_size) {
		RRR_MSG_0("Invalid size for message in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_socket_msg_head_to_host_and_verify(socket_msg, target_size) != 0) {
		RRR_MSG_0("Error while verifying message in  __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_socket_msg_check_data_checksum_and_length(socket_msg, target_size) != 0) {
		RRR_MSG_0("Invalid checksum for message data in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_message_to_host_and_verify(msg, target_size) != 0) {
		RRR_MSG_0("Message was invalid in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_type_msg_unpack (RRR_TYPE_UNPACK_ARGS) {
	int ret = 0;

	// It is not possible to specify a multi-value msg definition, but we
	// support it here for now anyway

	ssize_t pos = 0;
	int count = 0;
	while (pos < node->total_stored_length) {
		struct rrr_socket_msg *socket_msg = (struct rrr_socket_msg *) (node->data + pos);
		struct rrr_message *msg = (struct rrr_message *) socket_msg;

		ssize_t max_size = node->total_stored_length - pos;

		if (__rrr_type_msg_to_host_single (msg, max_size) != 0) {
			RRR_MSG_0("Could not convert message in __rrr_type_msg_to_host\n");
			ret = 1;
			goto out;
		}

		pos += msg->msg_size;
		count++;
	}

	node->element_count = count;

	out:
	return ret;
}

static int __rrr_type_import_msg (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;

	*parsed_bytes = 0;

	ssize_t max_size_total = end - start;
	ssize_t target_size_total = 0;
	struct rrr_socket_msg *socket_msg = (struct rrr_socket_msg *) start;

	unsigned int count = 0;
	ssize_t max_size = max_size_total;
	while (max_size > 0) {
		if (max_size < (ssize_t) (sizeof (struct rrr_message) - 1)) {
			ret = RRR_TYPE_PARSE_INCOMPLETE;
			goto out;
		}

		ssize_t target_size = 0;
		if (rrr_socket_msg_get_target_size_and_check_checksum (
				&target_size,
				socket_msg,
				max_size
		) != 0) {
			RRR_MSG_0("Invalid header for message in __rrr_type_import_msg\n");
			ret = RRR_TYPE_PARSE_SOFT_ERR;
			goto out;
		}

		if (max_size < target_size) {
			ret = RRR_TYPE_PARSE_INCOMPLETE;
			goto out;
		}

		target_size_total += target_size;
		max_size -= target_size;
		count++;
	}

	if (target_size_total < max_size) {
		ret = RRR_TYPE_PARSE_INCOMPLETE;
		goto out;
	}

	if (count != node->element_count && node->element_count != 0) {
		RRR_MSG_0("Number of messages in array did not match definition. Found %i but expected %" PRIu32 "\n",
				count, node->element_count);
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	node->data = malloc(target_size_total);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_msg\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	node->total_stored_length = target_size_total;
	memcpy(node->data, start, target_size_total);

	if (__rrr_type_msg_unpack(node) != 0) {
		RRR_MSG_0("Could not convert message in __rrr_type_import_msg\n");
		ret = 1;
		goto out;
	}

	*parsed_bytes = target_size_total;

	out:
	return ret;
}


static int __rrr_type_64_unpack (RRR_TYPE_UNPACK_ARGS, uint8_t target_type) {
	if (node->total_stored_length % sizeof(rrr_type_be) != 0) {
		RRR_MSG_0("Size of 64 type was not 8 bytes in __rrr_type_64_unpack\n");
		return 1;
	}

	ssize_t array_size = node->total_stored_length / sizeof(rrr_type_be);
	const char *pos = node->data;
	for (unsigned int i = 0; i < array_size; i++) {
		rrr_type_be tmp = *((rrr_type_be *) pos);
		*((rrr_type_be *) pos) = rrr_be64toh(tmp);
//		printf("Unpacking host U %" PRIu64 "\n", *((rrr_type_be *) pos));
//		printf("Unpacking host I %" PRIi64 "\n", *((int64_t *) pos));
		pos += sizeof(rrr_type_be);
	}

	node->definition = rrr_type_get_from_id(target_type);

	return 0;
}

static int __rrr_type_be_unpack (RRR_TYPE_UNPACK_ARGS) {
	return __rrr_type_64_unpack (node, RRR_TYPE_H);
}

static int __rrr_type_fixp_unpack (RRR_TYPE_UNPACK_ARGS) {
	return __rrr_type_64_unpack (node, RRR_TYPE_FIXP);
}

static int __rrr_type_64_export_or_pack (RRR_TYPE_EXPORT_ARGS) {
	if (node->total_stored_length % sizeof(rrr_type_be) != 0) {
		RRR_MSG_0("Size of 64 type was not 8 bytes in __rrr_type_64_export_or_pack\n");
		return 1;
	}

	ssize_t array_size = node->total_stored_length / sizeof(rrr_type_be);
	ssize_t pos = 0;
	for (unsigned int i = 0; i < array_size; i++) {
		const char *rpos = node->data + pos;
		char *wpos = target + pos;
		*((rrr_type_be *) wpos) = rrr_htobe64(*((rrr_type_be *) rpos));
//		printf("Packing host U %" PRIu64 "\n", *((rrr_type_be *) wpos));
		pos += sizeof(rrr_type_be);
	}

	*written_bytes = node->total_stored_length;

	return 0;
}

static int __rrr_type_host_export (RRR_TYPE_EXPORT_ARGS) {
	return __rrr_type_64_export_or_pack (target, written_bytes, node);
}

static int __rrr_type_host_pack (RRR_TYPE_PACK_ARGS) {
	*new_type_id = RRR_TYPE_BE;
	return __rrr_type_64_export_or_pack (target, written_bytes, node);
}

static int __rrr_type_fixp_pack (RRR_TYPE_PACK_ARGS) {
	*new_type_id = RRR_TYPE_FIXP;
	return __rrr_type_64_export_or_pack (target, written_bytes, node);
}

static int __rrr_type_fixp_export (RRR_TYPE_EXPORT_ARGS) {
	RRR_BUG("__rrr_type_fixp_export not implemented");
	return 0;
}

static int __rrr_type_blob_unpack (RRR_TYPE_UNPACK_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_0("Length of blob type was 0 in __rrr_type_blob_unpack\n");
		return 1;
	}
	return 0;
}

static int __rrr_type_blob_export_or_pack (RRR_TYPE_EXPORT_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_0("Length of blob type was 0 in __rrr_type_blob_export_or_pack\n");
		return 1;
	}

	memcpy(target, node->data, node->total_stored_length);


	*written_bytes = node->total_stored_length;

	return 0;
}

static int __rrr_type_blob_pack (RRR_TYPE_PACK_ARGS) {
	*new_type_id = node->definition->type;
	return __rrr_type_blob_export_or_pack(target, written_bytes, node);
}

static int __rrr_type_blob_export (RRR_TYPE_EXPORT_ARGS) {
	return __rrr_type_blob_export_or_pack(target, written_bytes, node);
}

static int __rrr_type_msg_pack_or_export (
		char *target,
		ssize_t *written_bytes,
		const struct rrr_type_value *node
) {
	ssize_t pos = 0;

	// It is not possible to specify a multi-value msg definition, but we
	// support it here for now anyway

	while (pos < node->total_stored_length) {
		void *wpos = target + pos;
		void *rpos = node->data + pos;

		struct rrr_message *msg_at_source = rpos;

		if (MSG_TOTAL_SIZE(msg_at_source) < sizeof(struct rrr_message) - 1) {
			RRR_MSG_0("Message too short in __rrr_type_msg_pack_or_export\n");
			return 1;
		}

		if (pos + MSG_TOTAL_SIZE(msg_at_source) > node->total_stored_length) {
			RRR_MSG_0("Message longer than stated length __rrr_type_msg_pack_or_export\n");
			return 1;
		}

		memcpy(wpos, rpos, MSG_TOTAL_SIZE(msg_at_source));
		struct rrr_message *msg_at_target = wpos;

		pos += MSG_TOTAL_SIZE(msg_at_target);

		rrr_message_prepare_for_network(msg_at_target);
		rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) msg_at_target);
	}

	if (pos != node->total_stored_length) {
		RRR_MSG_0("Invalid size of messages in __rrr_type_msg_pack_or_export\n");
		return 1;
	}

	*written_bytes = pos;

	return 0;
}

static int __rrr_type_msg_export (RRR_TYPE_EXPORT_ARGS) {
	return __rrr_type_msg_pack_or_export(target, written_bytes, node);
}

static void __rrr_type_str_get_export_length (RRR_TYPE_GET_EXPORT_LENGTH_ARGS) {
	ssize_t escape_count = 0;
	const char *end = node->data + node->total_stored_length;
	for (const char *pos = node->data; pos < end; pos++) {
		if ((*pos) == '\\' || (*pos) == '"') {
			escape_count++;
		}
	}
	*bytes = node->total_stored_length + 2 + escape_count;
}

static int __rrr_type_str_export (RRR_TYPE_EXPORT_ARGS) {
	char *write_pos = target;

	(*write_pos) = '"';
	write_pos++;

	const char *read_end = node->data + node->total_stored_length;

	for (const char *read_pos = node->data; read_pos < read_end; read_pos++) {
		if (*read_pos == '\\' || *read_pos == '"') {
			(*write_pos) = '\\';
			write_pos++;
		}
		(*write_pos) = *read_pos;
		write_pos++;
	}

	(*write_pos) = '"';
	write_pos++;

	*written_bytes = write_pos - target;

	return 0;
}

static int __rrr_type_msg_pack (RRR_TYPE_PACK_ARGS) {
	int ret = __rrr_type_msg_pack_or_export(target, written_bytes, node);
	if (ret != 0) {
		goto out;
	}

	*new_type_id = RRR_TYPE_MSG;

	out:
	return 0;
}

static int __get_import_length_default (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	(void)(buf);
	(void)(buf_size);

	*import_length = node->import_elements * node->import_length;

	return 0;
}

static int __get_import_length_ustr (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	(void)(node);

	int found_end_char = 0;
	ssize_t length = 0;
	for (length = 0; length < buf_size; length++) {
		const char *pos = buf + length;
		if (*pos >= '0' && *pos <= '9') {
			continue;
		}
		else {
			found_end_char = 1;
			break;
		}
	}

	if (found_end_char == 1) {
		*import_length = length;
		return RRR_TYPE_PARSE_OK;
	}

	return RRR_TYPE_PARSE_INCOMPLETE;
}

static int __get_import_length_istr (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	const char *start = buf;
	const char *end = buf + buf_size;

	CHECK_END_AND_RETURN(1);

	ssize_t sign_length = 0;
	if (*start == '-' || *start == '+') {
		start++;
		sign_length = 1;
	}

	CHECK_END_AND_RETURN(1);

	ssize_t length = 0;
	if (__get_import_length_ustr(&length, node, start, buf_size - sign_length) == 0) {
		*import_length = sign_length + length;
		return RRR_TYPE_PARSE_OK;
	}

	return RRR_TYPE_PARSE_INCOMPLETE;
}

static int __get_import_length_msg (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	(void)(node);

	if (buf_size < (ssize_t) sizeof(struct rrr_socket_msg)) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	int ret = rrr_socket_msg_get_target_size_and_check_checksum (
			import_length,
			(struct rrr_socket_msg *) buf,
			buf_size
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			return RRR_TYPE_PARSE_INCOMPLETE;
		}

		RRR_MSG_0("Error while getting message length in __get_import_length_msg, return was %i\n", ret);
		return (ret == RRR_SOCKET_SOFT_ERROR ? RRR_TYPE_PARSE_SOFT_ERR : RRR_TYPE_PARSE_HARD_ERR);
	}

	return RRR_TYPE_PARSE_OK;
}


static int __get_import_length_fixp (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	(void)(node);

	int ret = RRR_TYPE_PARSE_OK;

	if (buf_size < 1) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	ssize_t length = 0;
	if ((ret = rrr_fixp_str_get_length (&length, buf, buf_size)) != 0) {
		if (ret == RRR_FIXED_POINT_PARSE_INCOMPLETE) {
			return RRR_TYPE_PARSE_INCOMPLETE;
		}
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	if (length == buf_size) {
		ret = RRR_TYPE_PARSE_INCOMPLETE;
		goto out;
	}

	*import_length = length;

	out:
	return ret;
}

static int __rrr_type_import_fixp (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;

	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_dec\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_dec\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in __rrr_type_import_dec\n");
	}

	int64_t fixp = 0;
	const char *endptr = NULL;

	if ((ret = rrr_fixp_str_to_fixp(&fixp, start, end - start, &endptr)) != 0) {
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	// Fixed point needs another field after it to know where the number ends
	if (endptr == end) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	node->data = malloc(sizeof(fixp));
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_fixp\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	memcpy(node->data, &fixp, sizeof(fixp));
	node->total_stored_length = sizeof(fixp);

	*parsed_bytes = endptr - start;

	out:
	return ret;
}

static int __get_import_length_str (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	const char *start = buf;
	const char *end = buf + buf_size;

	(void)(node);

	int ret = RRR_TYPE_PARSE_INCOMPLETE;

	ssize_t length = 0;

	CHECK_END_AND_RETURN(1);

	if (*start != '"') {
		RRR_MSG_0("String did not begin with \" in __get_import_length_str\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	length++;
	start++;

	int ignore_next_quote = 0;
	for (const char *pos = start; pos < end; pos++) {
		length++;

		if (*pos == '"' && ignore_next_quote != 1) {
			ret = RRR_TYPE_PARSE_OK;
			break;
		}
		else if (*pos == '\\') {
			ignore_next_quote = 1;
		}
		else {
			ignore_next_quote = 0;
		}
	}

	*import_length = length;

	out:
	return ret;
}

static int __get_import_length_nsep (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	const char *start = buf;
	const char *end = buf + buf_size;

	(void)(node);

	int ret = RRR_TYPE_PARSE_INCOMPLETE;

	ssize_t length = 0;

	// Parse any number of bytes until a separator is found.
	for (const char *pos = start; pos < end; pos++) {
		if (RRR_TYPE_CHAR_IS_SEP_A(*pos)||RRR_TYPE_CHAR_IS_SEP_F(*pos)) {
			if (length == 0) {
				RRR_MSG_0("No characters found for array nsep-field, only separator found\n");
				ret = RRR_TYPE_PARSE_SOFT_ERR;
			}
			else {
				ret = RRR_TYPE_PARSE_OK;
			}
			break;
		}

		length++;
	}

	*import_length = length;


	return ret;
}

static int __rrr_type_import_nsep (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;

	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_nsep\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_nsep\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in __rrr_type_import_nsep\n");
	}

	ssize_t import_length = 0;
	if ((ret = __get_import_length_nsep(&import_length, node, start, end - start)) != 0) {
		goto out;
	}

	node->import_length = import_length;
	ssize_t parsed_bytes_tmp = 0;
	if ((ret = __rrr_type_import_blob(node, &parsed_bytes_tmp, start, end)) != 0) {
		return ret;
	}

	if (parsed_bytes_tmp != import_length) {
		RRR_BUG("Parsed bytes vs import length mismatch in __rrr_type_import_nsep\n");
	}

	node->import_length = import_length;
	*parsed_bytes = parsed_bytes_tmp;

	out:
	return ret;
}

static int __rrr_type_import_str (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;

	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_str\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_str\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in __rrr_type_import_str\n");
	}

	ssize_t import_length = 0;

	if ((ret = __get_import_length_str(&import_length, node, start, end - start)) != 0) {
		goto out;
	}

	// Fake lengths to strip out the quotes
	node->import_length = import_length - 2;
	ssize_t parsed_bytes_tmp = 0;
	if ((ret = __rrr_type_import_blob(node, &parsed_bytes_tmp, start + 1, end)) != 0) {
		return ret;
	}

	if (parsed_bytes_tmp + 2 != import_length) {
		RRR_BUG("Parsed bytes vs import length mismatch in __rrr_type_import_str\n");
	}

	node->import_length = import_length;
	*parsed_bytes = parsed_bytes_tmp + 2;

	out:
	return ret;
}

int __rrr_type_h_to_str (RRR_TYPE_TO_STR_ARGS) {
	int ret = 0;

	ssize_t output_size = node->total_stored_length * 4;

	char *result = malloc(output_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in__rrr_type_bin_to_str\n");
		return 1;
	}

	char *wpos = result;
	for (int i = 0; i < (int) node->total_stored_length; i += sizeof(rrr_type_be)) {
		if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
			int64_t tmp = *((int64_t *) (node->data + i));
			sprintf(wpos, "%" PRIi64 ",", tmp);
		}
		else {
			uint64_t tmp = *((uint64_t *) (node->data + i));
			sprintf(wpos, "%" PRIu64 ",", tmp);
		}
		wpos = result + strlen(result);
	}
	result[output_size - 1] = '\0';

	*target = result;

	return ret;
}

int __rrr_type_bin_to_str (RRR_TYPE_TO_STR_ARGS) {
	int ret = 0;

	ssize_t output_size = node->total_stored_length * 2 + 1;

	// Valgrind complains about invalid writes for some reason
	if (output_size < 32) {
		output_size = 32;
	}

	char *result = malloc(output_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in__rrr_type_bin_to_str\n");
		return 1;
	}

	char *wpos = result;
	for (int i = 0; i < (int) node->total_stored_length; i++) {
		sprintf(wpos, "%02x", *(node->data + i));
		wpos += 2;
	}
	result[output_size - 1] = '\0';

	*target = result;

	return ret;
}

int __rrr_type_str_to_str (RRR_TYPE_TO_STR_ARGS) {
	char *result = malloc(node->total_stored_length + 1);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_str_to_str\n");
		return 1;
	}

	memcpy(result, node->data, node->total_stored_length);
	(*(result + node->total_stored_length)) = '\0';

	*target = result;

	return 0;
}

#define RRR_TYPE_DEFINE(name,type,max,import_length,import,export_length,export,unpack,pack,to_str,name_str) \
	const struct rrr_type_definition RRR_PASTE(rrr_type_definition_,name) = {type, max, import_length, import, export_length, export, unpack, pack, to_str, name_str}

RRR_TYPE_DEFINE(be, RRR_TYPE_BE,		RRR_TYPE_MAX_BE,	__get_import_length_default,	__rrr_type_import_be,	NULL,								NULL,					__rrr_type_be_unpack,		NULL,					NULL,					RRR_TYPE_NAME_BE);
RRR_TYPE_DEFINE(h, RRR_TYPE_H,			RRR_TYPE_MAX_H,		__get_import_length_default,	__rrr_type_import_host,	NULL,								__rrr_type_host_export,	NULL,						__rrr_type_host_pack,	__rrr_type_h_to_str,	RRR_TYPE_NAME_H);
RRR_TYPE_DEFINE(le, RRR_TYPE_LE,		RRR_TYPE_MAX_LE,	__get_import_length_default,	__rrr_type_import_le,	NULL,								NULL,					NULL,						NULL,					NULL,					RRR_TYPE_NAME_LE);
RRR_TYPE_DEFINE(blob, RRR_TYPE_BLOB,	RRR_TYPE_MAX_BLOB,	__get_import_length_default,	__rrr_type_import_blob,	NULL,								__rrr_type_blob_export,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	__rrr_type_bin_to_str,	RRR_TYPE_NAME_BLOB);
RRR_TYPE_DEFINE(ustr, RRR_TYPE_USTR,	RRR_TYPE_MAX_USTR,	__get_import_length_ustr,		__rrr_type_import_ustr,	NULL,								NULL,					NULL,						NULL,					NULL,					RRR_TYPE_NAME_USTR);
RRR_TYPE_DEFINE(istr, RRR_TYPE_ISTR,	RRR_TYPE_MAX_ISTR,	__get_import_length_istr,		__rrr_type_import_istr,	NULL,								NULL,					NULL,						NULL,					NULL,					RRR_TYPE_NAME_ISTR);
RRR_TYPE_DEFINE(sep, RRR_TYPE_SEP,		RRR_TYPE_MAX_SEP,	__get_import_length_default,	__rrr_type_import_sep,	NULL,								__rrr_type_blob_export,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	__rrr_type_str_to_str,	RRR_TYPE_NAME_SEP);
RRR_TYPE_DEFINE(msg, RRR_TYPE_MSG,		RRR_TYPE_MAX_MSG,	__get_import_length_msg,		__rrr_type_import_msg,	NULL,								__rrr_type_msg_export,	__rrr_type_msg_unpack,		__rrr_type_msg_pack,	__rrr_type_bin_to_str,	RRR_TYPE_NAME_MSG);
RRR_TYPE_DEFINE(fixp, RRR_TYPE_FIXP,	RRR_TYPE_MAX_FIXP,	__get_import_length_fixp,		__rrr_type_import_fixp,	NULL,								__rrr_type_fixp_export,	__rrr_type_fixp_unpack,		__rrr_type_fixp_pack,	__rrr_type_bin_to_str,	RRR_TYPE_NAME_FIXP);
RRR_TYPE_DEFINE(str, RRR_TYPE_STR,		RRR_TYPE_MAX_STR,	__get_import_length_str,		__rrr_type_import_str,	__rrr_type_str_get_export_length,	__rrr_type_str_export,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	__rrr_type_str_to_str,	RRR_TYPE_NAME_STR);
RRR_TYPE_DEFINE(nsep, RRR_TYPE_NSEP,	RRR_TYPE_MAX_NSEP,	__get_import_length_nsep,		__rrr_type_import_nsep,	NULL,								__rrr_type_blob_export,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	__rrr_type_str_to_str,	RRR_TYPE_NAME_NSEP);
RRR_TYPE_DEFINE(stx, RRR_TYPE_STX,		RRR_TYPE_MAX_STX,	__get_import_length_default,	__rrr_type_import_stx,	NULL,								__rrr_type_blob_export,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	__rrr_type_str_to_str,	RRR_TYPE_NAME_STX);
RRR_TYPE_DEFINE(null, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

// If there are types which begin with the same letters, the longest names must be first in the array
static const struct rrr_type_definition *type_templates[] = {
		&rrr_type_definition_be,
		&rrr_type_definition_h,
		&rrr_type_definition_le,
		&rrr_type_definition_blob,
		&rrr_type_definition_ustr,
		&rrr_type_definition_istr,
		&rrr_type_definition_sep,
		&rrr_type_definition_msg,
		&rrr_type_definition_fixp,
		&rrr_type_definition_str,
		&rrr_type_definition_nsep,
		&rrr_type_definition_stx,
		&rrr_type_definition_null
};

const struct rrr_type_definition *rrr_type_parse_from_string (
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	*parsed_bytes = 0;

	int i = 0;
	do {
		const struct rrr_type_definition *type = type_templates[i];
		ssize_t len = strlen(type->identifier);
		if (start + len > end) {
			goto next;
		}
		if (strncmp(type->identifier, start, len) == 0) {
			*parsed_bytes = len;
			return type;
		}

		next:
		i++;
	} while(type_templates[i]->type != 0);

	return NULL;
}

const struct rrr_type_definition *rrr_type_get_from_id (
		uint8_t type_in
) {
	for (unsigned int i = 0; i < sizeof(type_templates) / sizeof(type_templates[0]) - 1; i++) {
		const struct rrr_type_definition *type = type_templates[i];
		if (type->type == type_in) {
			return type;
		}
	}

	return NULL;
}

void rrr_type_value_destroy (
		struct rrr_type_value *template
) {
	RRR_FREE_IF_NOT_NULL(template->tag);
	RRR_FREE_IF_NOT_NULL(template->data);
	free(template);
}

int rrr_type_value_set_tag (
		struct rrr_type_value *value,
		const char *tag,
		ssize_t tag_length
) {
	RRR_FREE_IF_NOT_NULL(value->tag);
	if (tag_length > 0) {
		value->tag = malloc(tag_length + 1);
		if (value->tag == NULL) {
			RRR_MSG_0("Could not allocate tag in rrr_type_value_set_tag\n");
			return 1;
		}
		memcpy(value->tag, tag, tag_length);
		value->tag[tag_length] = '\0';
	}
	value->tag_length = tag_length;
	return 0;
}

int rrr_type_value_new (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_type_length tag_length,
		const char *tag,
		rrr_type_length import_length,
		rrr_type_array_size element_count,
		rrr_type_length stored_length
) {
	int ret = 0;

	struct rrr_type_value *value = malloc(sizeof(*value));
	if (value == NULL) {
		RRR_MSG_0("Could not allocate template in rrr_type_value_new\n");
		ret = 1;
		goto out;
	}

	memset(value, '\0', sizeof(*value));

	value->flags = flags;
	value->tag_length = tag_length;
	value->element_count = element_count;
	value->import_length = import_length;
	value->import_elements = element_count;
	value->total_stored_length = stored_length;
	value->definition = type;

	if (stored_length > 0) {
		value->data = malloc(stored_length);
		if (value->data == NULL) {
			RRR_MSG_0("Could not allocate data for template in rrr_type_value_new\n");
			ret = 1;
			goto out;
		}
	}

	if (rrr_type_value_set_tag(value, tag, tag_length) != 0) {
		ret = 1;
		goto out;
	}

	*result = value;
	value = NULL;

	out:
	if (value != NULL) {
		rrr_type_value_destroy(value);
	}

	return ret;
}

ssize_t rrr_type_value_get_export_length (
		const struct rrr_type_value *value
) {
	ssize_t exported_length = 0;

	if (value->definition->get_export_length != NULL) {
		value->definition->get_export_length(&exported_length, value);
	}
	else {
		exported_length = value->total_stored_length;
	}

	return exported_length;
}

int rrr_type_value_allocate_and_export (
		char **target,
		ssize_t *written_bytes,
		const struct rrr_type_value *node
) {
	int ret = 0;

	*target = NULL;
	*written_bytes = 0;

	char *buf_tmp = NULL;
	ssize_t buf_size = rrr_type_value_get_export_length(node);

	if ((buf_tmp = malloc(buf_size)) == NULL) {
		RRR_MSG_0("Error while allocating memory before exporting in rrr_type_value_allocate_and_export \n");
		ret = 1;
		goto out;
	}

	if (node->definition->export(buf_tmp, &buf_size, node) != 0) {
		RRR_MSG_0("Error while exporting in rrr_type_value_allocate_and_export \n");
		ret = 1;
		goto out;
	}

	*target = buf_tmp;
	*written_bytes = buf_size;

	out:
	RRR_FREE_IF_NOT_NULL(buf_tmp);
	return ret;
}

// It is only possible to use this with types for which
// import length and stored (unpacked) length is equal.
// It is not possible to import 3 byte ints for instance,
// they have to be full length 8 bytes.
int rrr_type_value_allocate_and_import_raw (
		struct rrr_type_value **result_value,
		const struct rrr_type_definition *definition,
		const char *data_start,
		const char *data_end,
		rrr_type_length tag_length,
		const char *tag,
		rrr_type_length import_length,
		rrr_type_array_size element_count
) {
	int ret = 0;

	rrr_type_length stored_length = import_length * element_count;

	if (stored_length != data_end - data_start) {
		RRR_BUG("BUG: Incorrect lengths to rrr_type_value_allocate_and_import_raw, import and stored lengths must be equal");
	}

	struct rrr_type_value *value = NULL;
	if ((rrr_type_value_new (
			&value,
			definition,
			0,
			tag_length,
			tag,
			import_length,
			element_count,
			0 // <-- Do not pass stored length, causes allocation which should be done by import function
	)) != 0) {
		RRR_MSG_0("Could not allocate value in rrr_type_value_allocate_and_import_raw\n");
		ret = 1;
		goto out;
	}

	if (value->data != NULL) {
		RRR_BUG("BUG: Data was allocated by new function in rrr_type_value_allocate_and_import_raw\n");
	}

	ssize_t parsed_bytes = 0;

	if (definition->import (
			value,
			&parsed_bytes,
			data_start,
			data_end
	) != 0) {
		RRR_MSG_0("Import failed in rrr_type_value_allocate_and_import_raw\n");
		ret = 1;
		goto out;
	}

	if (parsed_bytes != stored_length) {
		RRR_MSG_0("Parsed bytes mismatch, parsed %li bytes while %li was expected\n", parsed_bytes, stored_length);
		ret = 1;
		goto out;
	}

	*result_value = value;
	value = NULL;

	out:
	if (value != NULL) {
		rrr_type_value_destroy(value);
	}
	return ret;
}
