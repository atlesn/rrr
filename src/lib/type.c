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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../global.h"
#include "type.h"
#include "fixed_point.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "messages.h"
#include "rrr_endian.h"

#define PASTER(x,y) x ## _ ## y

#define RRR_TYPES_MATCH_RETURN(str,name) \
	if (strcmp(str,PASTER(RRR_TYPE_NAME,name)) == 0){return PASTER(RRR_TYPE,name);}

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
	temp.temp_f = be64toh(temp.temp_f);
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

	temp.temp_f = le64toh(temp.temp_f);

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
		RRR_BUG("data was not NULL in import_le\n");
	}

	ssize_t array_size = node->import_elements;
	ssize_t total_size = node->import_elements * node->import_length;

	CHECK_END_AND_RETURN(total_size);

	node->total_stored_length = node->import_elements * sizeof(uint64_t);
	node->data = malloc(node->total_stored_length);
	if (node->data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in import_le\n");
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
		RRR_MSG_ERR("Could not allocate memory in import_blob\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}
	memcpy(node->data, start, total_size);

	node->total_stored_length = total_size;

	*parsed_bytes = total_size;

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

	CHECK_END_AND_RETURN(1);

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
		RRR_MSG_ERR("Error while converting unsigned integer in import_ustr\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	node->data = malloc(sizeof(rrr_type_ustr));
	if (node->data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in import_ustr\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_ustr));

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->total_stored_length = sizeof(rrr_type_h);
	RRR_TYPE_FLAG_SET_UNSIGNED(node->flags);

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

	CHECK_END_AND_RETURN(1);

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
		RRR_MSG_ERR("Error while converting unsigned integer in import_istr\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	node->data = malloc(sizeof(rrr_type_istr));
	if (node->data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in import_istr\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}

	memcpy(node->data, &result, sizeof(rrr_type_istr));

	node->definition = rrr_type_get_from_id(RRR_TYPE_H);
	node->total_stored_length = sizeof(rrr_type_h);
	RRR_TYPE_FLAG_SET_SIGNED(node->flags);

	*parsed_bytes = convert_end - tmp;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_sep (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in import_sep\n");
	}

	ssize_t total_size = node->import_length * node->element_count;

	ssize_t found = 0;
	for (const char *start_tmp = start; start_tmp < end && found < total_size; start_tmp++) {
		CHECK_END_AND_RETURN(1);

		unsigned char c = *start_tmp;
		if (!RRR_TYPE_CHAR_IS_SEP(c)) {
			RRR_MSG_ERR("Invalid separator character %c\n", c);
			return RRR_TYPE_PARSE_SOFT_ERR;
		}

		found++;
	}

	if (found != total_size) {
		RRR_MSG_ERR("Not enough separator characters found\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	node->data = malloc(found);
	if (node->data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in import_sep\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}
	memcpy (node->data, start, found);

	node->total_stored_length = total_size;

	*parsed_bytes = found;

	return RRR_TYPE_PARSE_OK;
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
		RRR_MSG_ERR("Invalid header for message in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (max_size < target_size) {
		RRR_MSG_ERR("Invalid size for message in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_socket_msg_head_to_host_and_verify(socket_msg, target_size) != 0) {
		RRR_MSG_ERR("Error while verifying message in  __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_socket_msg_check_data_checksum_and_length(socket_msg, target_size) != 0) {
		RRR_MSG_ERR("Invalid checksum for message data in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	if (rrr_message_to_host_and_verify(msg, target_size) != 0) {
		RRR_MSG_ERR("Message was invalid in __rrr_type_convert_msg_to_host_single\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_type_msg_unpack (RRR_TYPE_UNPACK_ARGS) {
	int ret = 0;

	ssize_t pos = 0;
	int count = 0;
	while (pos < node->total_stored_length) {
		struct rrr_socket_msg *socket_msg = (struct rrr_socket_msg *) (node->data + pos);
		struct rrr_message *msg = (struct rrr_message *) socket_msg;

		ssize_t max_size = node->total_stored_length - pos;

		if (__rrr_type_msg_to_host_single (msg, max_size) != 0) {
			RRR_MSG_ERR("Could not convert message in __rrr_type_msg_to_host\n");
			ret = 1;
			goto out;
		}

		pos += msg->network_size;
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
			RRR_MSG_ERR("Invalid header for message in __rrr_type_import_msg\n");
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
		RRR_MSG_ERR("Number of messages in array did not match definition. Found %i but expected %" PRIu32 "\n",
				count, node->element_count);
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	node->data = malloc(target_size_total);
	if (node->data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_type_import_msg\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	node->total_stored_length = target_size_total;
	memcpy(node->data, start, target_size_total);

	if (__rrr_type_msg_unpack(node) != 0) {
		RRR_MSG_ERR("Could not convert message in __rrr_type_import_msg\n");
		ret = 1;
		goto out;
	}

	*parsed_bytes = target_size_total;

	out:
	return ret;
}


static int __rrr_type_64_unpack (RRR_TYPE_UNPACK_ARGS, uint8_t target_type) {
	if (node->total_stored_length % sizeof(rrr_type_be) != 0) {
		RRR_MSG_ERR("Size of 64 type was not 8 bytes in __rrr_type_64_unpack\n");
		return 1;
	}

	ssize_t array_size = node->total_stored_length / sizeof(rrr_type_be);
	const char *pos = node->data;
	for (unsigned int i = 0; i < array_size; i++) {
		rrr_type_be tmp = *((rrr_type_be *) pos);
		*((rrr_type_be *) pos) = be64toh(tmp);
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

static int __rrr_type_64_pack (RRR_TYPE_PACK_ARGS, uint8_t target_type) {
	if (node->total_stored_length % sizeof(rrr_type_be) != 0) {
		RRR_MSG_ERR("Size of 64 type was not 8 bytes in __rrr_type_64_pack\n");
		return 1;
	}

	ssize_t array_size = node->total_stored_length / sizeof(rrr_type_be);
	ssize_t pos = 0;
	for (unsigned int i = 0; i < array_size; i++) {
		const char *rpos = node->data + pos;
		char *wpos = target + pos;
		*((rrr_type_be *) wpos) = htobe64(*((rrr_type_be *) rpos));

		pos += sizeof(rrr_type_be);
	}

	*new_type_id = target_type;
	*written_bytes = node->total_stored_length;

	return 0;
}

static int __rrr_type_host_pack (RRR_TYPE_PACK_ARGS) {
	return __rrr_type_64_pack (target, written_bytes, new_type_id, node, RRR_TYPE_BE);
}

static int __rrr_type_fixp_pack (RRR_TYPE_PACK_ARGS) {
	return __rrr_type_64_pack (target, written_bytes, new_type_id, node, RRR_TYPE_FIXP);
}

static int __rrr_type_blob_unpack (RRR_TYPE_UNPACK_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_ERR("Length of blob type was 0 in __rrr_array_convert_blob_to_host\n");
		return 1;
	}
	return 0;
}

static int __rrr_type_blob_pack (RRR_TYPE_PACK_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_ERR("Length of blob type was 0 in __rrr_array_convert_blob_to_host\n");
		return 1;
	}

	memcpy(target, node->data, node->total_stored_length);

	*new_type_id = node->definition->type;
	*written_bytes = node->total_stored_length;

	return 0;
}

static int __rrr_type_msg_pack (RRR_TYPE_PACK_ARGS) {
	ssize_t pos = 0;

	while (pos < node->total_stored_length) {
		void *wpos = target + pos;
		void *rpos = node->data + pos;

		struct rrr_socket_msg *head = rpos;
		struct rrr_message *msg = rpos;

		if (pos + msg->network_size > node->total_stored_length) {
			RRR_BUG("Size mismatch in __rrr_type_msg_pack A\n");
		}

		memcpy(wpos, rpos, msg->network_size);

		head = wpos;
		msg = wpos;

		pos += msg->network_size;

		rrr_message_prepare_for_network(msg);
		rrr_socket_msg_checksum_and_to_network_endian(head);
	}

	if (pos != node->total_stored_length) {
		RRR_BUG("Size mismatch in __rrr_type_msg_pack B\n");
	}

	*new_type_id = RRR_TYPE_MSG;
	*written_bytes = pos;

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

		RRR_MSG_ERR("Error while getting message length in __get_import_length_msg, return was %i\n", ret);
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
		RRR_MSG_ERR("Could not allocate memory in __rrr_type_import_fixp\n");
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
		RRR_MSG_ERR("String did not begin with \" in __get_import_length_str\n");
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

	// Parse any number of bytes untill a separator is found.
	for (const char *pos = start; pos < end; pos++) {
		if (RRR_TYPE_CHAR_IS_SEP_A(*pos)) {
			ret = RRR_TYPE_PARSE_OK;
			break;
		}

		length++;
	}

	*import_length = length;

	out:
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

// If there are types which begin with the same letters, the longest names must be first in the array
static const struct rrr_type_definition type_templates[] = {
		{RRR_TYPE_BE,		RRR_TYPE_MAX_BE,	__get_import_length_default,	__rrr_type_import_be,	__rrr_type_be_unpack,		NULL,					RRR_TYPE_NAME_BE},
		{RRR_TYPE_H,		RRR_TYPE_MAX_H,		__get_import_length_default,	__rrr_type_import_host,	NULL,						__rrr_type_host_pack,	RRR_TYPE_NAME_H},
		{RRR_TYPE_LE,		RRR_TYPE_MAX_LE,	__get_import_length_default,	__rrr_type_import_le,	NULL,						NULL,					RRR_TYPE_NAME_LE},
		{RRR_TYPE_BLOB,		RRR_TYPE_MAX_BLOB,	__get_import_length_default,	__rrr_type_import_blob,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	RRR_TYPE_NAME_BLOB},
		{RRR_TYPE_USTR,		RRR_TYPE_MAX_USTR,	__get_import_length_ustr,		__rrr_type_import_ustr,	NULL,						NULL,					RRR_TYPE_NAME_USTR},
		{RRR_TYPE_ISTR,		RRR_TYPE_MAX_ISTR,	__get_import_length_istr,		__rrr_type_import_istr,	NULL,						NULL,					RRR_TYPE_NAME_ISTR},
		{RRR_TYPE_SEP,		RRR_TYPE_MAX_SEP,	__get_import_length_default,	__rrr_type_import_sep,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	RRR_TYPE_NAME_SEP},
		{RRR_TYPE_MSG,		RRR_TYPE_MAX_MSG,	__get_import_length_msg,		__rrr_type_import_msg,	__rrr_type_msg_unpack,		__rrr_type_msg_pack,	RRR_TYPE_NAME_MSG},
		{RRR_TYPE_FIXP,		RRR_TYPE_MAX_FIXP,	__get_import_length_fixp,		__rrr_type_import_fixp,	__rrr_type_fixp_unpack,		__rrr_type_fixp_pack,	RRR_TYPE_NAME_FIXP},
		{RRR_TYPE_STR,		RRR_TYPE_MAX_STR,	__get_import_length_str,		__rrr_type_import_str,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	RRR_TYPE_NAME_STR},
		{RRR_TYPE_NSEP,		RRR_TYPE_MAX_NSEP,	__get_import_length_nsep,		__rrr_type_import_nsep,	__rrr_type_blob_unpack,		__rrr_type_blob_pack,	RRR_TYPE_NAME_NSEP},
		{0,					0,					NULL,							NULL,					NULL,						NULL,					NULL}
};

const struct rrr_type_definition *rrr_type_parse_from_string (
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
) {
	*parsed_bytes = 0;

	int i = 0;
	do {
		const struct rrr_type_definition *type = &type_templates[i];
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
	} while(type_templates[i].type != 0);

	return NULL;
}


const struct rrr_type_definition *rrr_type_get_from_id (
		uint8_t type_in
) {
	for (unsigned int i = 0; i < sizeof(type_templates) / sizeof(type_templates[0]) - 1; i++) {
		const struct rrr_type_definition *type = &type_templates[i];
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
		RRR_MSG_ERR("Could not allocate template in rrr_type_value_new\n");
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
			RRR_MSG_ERR("Could not allocate data for template in rrr_type_value_new\n");
			ret = 1;
			goto out;
		}
	}

	if (tag_length > 0) {
		value->tag = malloc(tag_length + 1);
		if (value->tag == NULL) {
			RRR_MSG_ERR("Could not allocate tag for template in rrr_type_value_new\n");
			ret = 1;
			goto out;
		}
		memcpy(value->tag, tag, tag_length);
		value->tag[tag_length] = '\0';
	}

	*result = value;
	value = NULL;

	out:
	if (value != NULL) {
		rrr_type_value_destroy(value);
	}

	return ret;
}
