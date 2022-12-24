/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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
#include <ctype.h>

#include "log.h"
#include "allocator.h"
#include "type.h"
#include "fixed_point.h"
#include "socket/rrr_socket.h"
#include "messages/msg.h"
#include "messages/msg_msg.h"
#include "util/rrr_endian.h"
#include "util/macro_utils.h"
#include "util/gnu.h"
#include "util/hex.h"

static int __rrr_type_convert_integer_10 (
		char **end,
		long long int *result,
		const char *value
) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoll(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

static int __rrr_type_convert_unsigned_integer_10 (
		char **end,
		unsigned long long int *result,
		const char *value
) {
	if (*value == '\0') {
		return 1;
	}
	*result = strtoull(value, end, 10);
	if (*end == value) {
		return 1;
	}
	return 0;
}

#define CHECK_END_AND_RETURN(length)                           \
    if (start + length > end) {                                \
        return RRR_TYPE_PARSE_INCOMPLETE;                      \
    }

static uint64_t __rrr_type_expand_be (
		rrr_length import_length,
		const char *src,
		rrr_type_flags flags
) {
	if (import_length == 0) {
		RRR_BUG("BUG: Import length was 0 in __rrr_type_expand_be\n");
	}

	union beunion {
		rrr_type_be temp_f;
		char temp_b[sizeof(rrr_type_be)];
	};

	union beunion temp;

	temp.temp_f = 0;
	if (RRR_TYPE_FLAG_IS_SIGNED(flags)) {
		unsigned char sign = (unsigned char) ((*src) & 0x80);
		if (sign > 0) {
			temp.temp_f = 0xffffffffffffffff;
		}
	}

	rrr_length wpos = sizeof(temp.temp_f) - 1;
	rrr_length rpos = import_length - 1;

	/* Big endian:
	 * (0x00 0x00 0x01)be = 1
	 * (0x00 0x00 0x00 0x00 0x01)be = 1
	 * (0xff 0xff 0xff 0xff 0xff)be = huge number or -1 (if signed flag set)
	 */

	while (1) {
		temp.temp_b[wpos] = src[rpos];

		if (rpos == 0) {
			break;
		}

		wpos--;
		rpos--;
	}

	temp.temp_f = rrr_be64toh(temp.temp_f);
	return temp.temp_f;
}

static uint64_t __rrr_type_expand_le (
		rrr_length import_length,
		const char *src,
		rrr_type_flags flags
) {
	union leunion {
		rrr_type_le temp_f;
		char temp_b[sizeof(rrr_type_le)];
	};

	union leunion temp;

	temp.temp_f = 0;
	if (RRR_TYPE_FLAG_IS_SIGNED(flags)) {
		char sign = (*(src + import_length - 1)) & (char) 0x80;
		if (sign) {
			temp.temp_f = 0xffffffffffffffff;
		}
	}

	/* Little endian:
	 * (0x01 0x00 0x00)le = 1
	 * (0x01 0x00 0x00 0x00 0x00 0x00)le = 1
	 */

	rrr_length pos = 0;
	while (pos < import_length) {
		temp.temp_b[pos] = src[pos];
		pos++;
	}

	temp.temp_f = rrr_le64toh(temp.temp_f);

	return temp.temp_f;
}

static int __rrr_type_import_int (
		RRR_TYPE_IMPORT_ARGS,
		uint64_t (*expander)(rrr_length import_length, const char *src, rrr_type_flags flags)
) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_int\n");
	}

	if (node->import_length > (rrr_length) sizeof(uint64_t)) {
		RRR_MSG_0("Import length of 64 type exceeds maximum of %llu bytes (was %" PRIrrrl ")",
				(unsigned long long) sizeof(uint64_t), node->import_length);
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	rrr_length array_size = node->element_count;
	rrr_length total_size = node->element_count * node->import_length;

	CHECK_END_AND_RETURN(total_size);

	node->total_stored_length = node->element_count * (rrr_length) sizeof(uint64_t);
	node->data = rrr_allocate(node->total_stored_length);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_int\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}

	char *target_wpos = node->data;
	const char *data_rpos = start;

	while (array_size-- > 0) {
		uint64_t result = expander(node->import_length, data_rpos, node->flags);

		memcpy(target_wpos, &result, sizeof(result));

		data_rpos += node->import_length;
		target_wpos += sizeof(result);
	}

	*parsed_bytes = total_size;

	node->total_stored_length = (rrr_length) sizeof(uint64_t) * node->element_count;
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

	rrr_length total_size = node->import_length * node->element_count;

	CHECK_END_AND_RETURN(total_size);

	// Prevent 0 bytes allocation which occurs upon empty str
	// type. Allocate 1 byte in this case.
	if ((node->data = rrr_allocate(total_size > 0 ? total_size : 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory in import_blob\n");
		return RRR_TYPE_PARSE_HARD_ERR;
	}

	memcpy(node->data, start, total_size);
	node->total_stored_length = total_size;

	*parsed_bytes = total_size;

	return RRR_TYPE_PARSE_OK;
}

static int __rrr_type_import_numeric_str_raw (
		char target[8],
		rrr_length *parsed_bytes,
		const char *start,
		const char *end,
		int is_signed
) {
	CHECK_END_AND_RETURN(1);

	*parsed_bytes = 0;

	if (end < start) {
		RRR_BUG("BUG: end was less than start in rrr_type_import_istr_raw\n");
	}

	int found_end_char = 0;
	int total_length = 0;

	union {
		long long int s;
		unsigned long long int u;
	} result;

	result.s = 0;

	// Must match return argument
	RRR_ASSERT(8==sizeof(result),rrr_type_import_numeric_str_raw_size_of_result_correct);

	char tmp[64];
	memset(tmp, '\0', sizeof(tmp));

	for (const char *pos = start; pos < end; pos++) {
		if ((*pos >= '0' && *pos <= '9') || *pos == '+' || *pos == ' ' || *pos == '\t' || (is_signed && *pos == '-')) {
			tmp[total_length++] = *pos;

			// Make sure we don't overwrite last \0 needed by conversion function
			if ((unsigned int) total_length > sizeof(tmp) - 1) {
				RRR_MSG_0("Import failed in rrr_type_import_numeric_str_raw, number too long (> 63 characters)\n");
				return RRR_TYPE_PARSE_SOFT_ERR;
			}
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

	if (total_length == 0) {
		RRR_MSG_0("Import failed in rrr_type_import_numeric_str_raw, no number found.\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	char *convert_end = NULL;

	if (is_signed) {
		if (__rrr_type_convert_integer_10(&convert_end, &result.s, tmp)) {
			RRR_MSG_0("Error while converting signed integer in rrr_type_import_numeric_str_raw A, input data was '%s'\n", tmp);
			return RRR_TYPE_PARSE_SOFT_ERR;
		}
	}
	else {
		if (__rrr_type_convert_unsigned_integer_10(&convert_end, &result.u, tmp)) {
			RRR_MSG_0("Error while converting unsigned integer in rrr_type_import_numeric_str_raw A, input data was '%s'\n", tmp);
			return RRR_TYPE_PARSE_SOFT_ERR;
		}
	}

	if (convert_end - tmp != total_length) {
		RRR_MSG_0("Error while converting number in rrr_type_import_numeric_str_raw B, input data was '%s'\n", tmp);
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	memcpy(target, &result, sizeof(result));

	if (convert_end < tmp) {
		RRR_BUG("BUG: convert_end was less than tmp in __rrr_type_import_numeric_str_raw\n");
	}
	*parsed_bytes = (rrr_length) total_length;

	return RRR_TYPE_PARSE_OK;
}

int rrr_type_import_ustr_raw (
		uint64_t *target,
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
) {
	return __rrr_type_import_numeric_str_raw((char *) target, parsed_bytes, start, end, 0);
}

int rrr_type_import_istr_raw (
		int64_t *target,
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
) {
	return __rrr_type_import_numeric_str_raw((char *) target, parsed_bytes, start, end, 1);
}

static int __rrr_type_import_ustr (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_ustr\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_ustr\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in __rrr_type_import_ustr\n");
	}

	int ret = RRR_TYPE_PARSE_OK;

	// Keep on separate line to suppress warning from static code analysis
	size_t allocation_size = sizeof(rrr_type_ustr);

	if ((node->data = (char *) rrr_allocate(allocation_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_ustr\n");
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

static int __rrr_type_import_istr (RRR_TYPE_IMPORT_ARGS) {
	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_istr\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_istr\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("length was not 0 in __rrr_type_import_istr\n");
	}

	int ret = RRR_TYPE_PARSE_OK;

	// Keep on separate line to suppress warning from static code analysis
	size_t allocation_size = sizeof(rrr_type_istr);

	if ((node->data = (char *) rrr_allocate(allocation_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_istr\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	if ((ret = rrr_type_import_istr_raw ((int64_t *) node->data, parsed_bytes, start, end)) != 0) {
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

	rrr_length total_size = node->import_length * node->element_count;

	CHECK_END_AND_RETURN(total_size);

	rrr_length found = 0;
	for (const char *start_tmp = start; start_tmp < end && found < total_size; start_tmp++) {
		char c = *start_tmp;
		if (!validate(c)) {
			RRR_MSG_0("Invalid separator character 0x%01x\n", c);
			return RRR_TYPE_PARSE_SOFT_ERR;
		}

		found++;
	}

	if (found != total_size) {
		RRR_MSG_0("Not enough special characters found\n");
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	node->data = rrr_allocate((size_t) found);
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
		if (ret != RRR_TYPE_PARSE_INCOMPLETE) {
			RRR_MSG_0("Import of sep type failed\n");
		}
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
		struct rrr_msg_msg *msg_msg,
		rrr_length max_size
) {
	struct rrr_msg *msg = (struct rrr_msg *) msg_msg;

	int ret = 0;
	rrr_length target_size = 0;

	{
		rrr_length target_size_tmp = 0;
		if (rrr_msg_get_target_size_and_check_checksum (
				&target_size_tmp,
				msg,
				max_size
		) != 0) {
			RRR_MSG_0("Invalid header for message in __rrr_type_msg_to_host_single\n");
			ret = RRR_TYPE_PARSE_SOFT_ERR;
			goto out;
		}

		target_size = target_size_tmp;
	}

	if (max_size < target_size) {
		RRR_MSG_0("Invalid size for message in __rrr_type_msg_to_host_single\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify(msg, target_size) != 0) {
		RRR_MSG_0("Error while verifying message in  __rrr_type_msg_to_host_single\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_msg_check_data_checksum_and_length(msg, target_size) != 0) {
		RRR_MSG_0("Invalid checksum for message data in __rrr_type_msg_to_host_single\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify(msg_msg, target_size) != 0) {
		RRR_MSG_0("Message was invalid in __rrr_type_msg_to_host_single\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_type_msg_unpack (RRR_TYPE_UNPACK_ARGS) {
	int ret = 0;

	// It is not possible to specify a multi-value msg definition, but we
	// support it here for now anyway

	rrr_length pos = 0;
	rrr_length count = 0;
	while (pos < node->total_stored_length) {
		struct rrr_msg *msg = (struct rrr_msg *) (node->data + pos);
		struct rrr_msg_msg *msg_msg = (struct rrr_msg_msg *) msg;

		rrr_length max_size = node->total_stored_length - pos;

		if ((ret = __rrr_type_msg_to_host_single (msg_msg, max_size)) != 0) {
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

	if (end < start) {
		RRR_BUG("BUG: end was less than start in __rrr_type_import_msg\n");
	}

	rrr_slength size_total = end - start;
	rrr_slength remaining_size = size_total;

	RRR_TYPES_CHECKED_LENGTH_COUNTER_INIT(target_size_total);

	struct rrr_msg *msg = (struct rrr_msg *) start;

	rrr_length count = 0;
	while (remaining_size > 0 && count < node->element_count) {
		if ((size_t) remaining_size < (sizeof (struct rrr_msg_msg) - 1)) {
			ret = RRR_TYPE_PARSE_INCOMPLETE;
			goto out;
		}

		rrr_length target_size = 0;
		{
			if (rrr_msg_get_target_size_and_check_checksum (
					&target_size,
					msg,
					(rrr_length) remaining_size
			) != 0) {
				RRR_MSG_0("Invalid header for message in __rrr_type_import_msg\n");
				ret = RRR_TYPE_PARSE_SOFT_ERR;
				goto out;
			}
		}

		RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(target_size_total,target_size);

		if (target_size_total > size_total) {
			ret = RRR_TYPE_PARSE_INCOMPLETE;
			goto out;
		}

		remaining_size -= target_size;

		count++;
	}

	if (remaining_size < 0) {
		RRR_BUG("BUG: remaining_size was < 0 in __rrr_type_import_msg\n");
	}

	if (count != node->element_count && node->element_count != 0) {
		RRR_MSG_0("Number of messages in array did not match definition. Found %i but expected %" PRIu32 "\n",
				count, node->element_count);
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	if (target_size_total > RRR_LENGTH_MAX) {
		RRR_MSG_0("Total size too long in _rrr_type_import_msg\n");
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	node->data = rrr_allocate((rrr_length) target_size_total);
	if (node->data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_msg\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	node->total_stored_length = (rrr_length) target_size_total;
	memcpy(node->data, start, (rrr_length) target_size_total);

	if ((ret = __rrr_type_msg_unpack(node)) != 0) {
		goto out;
	}

	*parsed_bytes = (rrr_length) target_size_total;

	out:
	return ret;
}

static int __rrr_type_import_vain (RRR_TYPE_IMPORT_ARGS) {
	(void)(node);
	(void)(start);
	(void)(end);

	*parsed_bytes = 0;

	return 0;
}

static int __rrr_type_64_unpack (RRR_TYPE_UNPACK_ARGS, uint8_t target_type) {
	if (node->total_stored_length % sizeof(rrr_type_be) != 0) {
		RRR_MSG_0("Size of 64 type was not 8 bytes in __rrr_type_64_unpack\n");
		return 1;
	}

	rrr_length array_size = node->total_stored_length / sizeof(rrr_type_be);
	const char *pos = node->data;
	for (unsigned int i = 0; i < array_size; i++) {
		rrr_type_be tmp = *((rrr_type_be *) pos);
		*((rrr_type_be *) pos) = rrr_be64toh(tmp);
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

	rrr_length array_size = node->total_stored_length / sizeof(rrr_type_be);
	rrr_length pos = 0;
	for (unsigned int i = 0; i < array_size; i++) {
		const char *rpos = node->data + pos;
		char *wpos = target + pos;
		*((rrr_type_be *) wpos) = rrr_htobe64(*((rrr_type_be *) rpos));
		pos += (rrr_length) sizeof(rrr_type_be);
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

	(void)(target);
	(void)(written_bytes);
	(void)(node);

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
	memcpy(target, node->data, node->total_stored_length);

	*written_bytes = node->total_stored_length;

	return 0;
}

static int __rrr_type_blob_pack (RRR_TYPE_PACK_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_0("Length of blob type was 0 in __rrr_type_blob_pack\n");
		return 1;
	}

	*new_type_id = node->definition->type;
	return __rrr_type_blob_export_or_pack(target, written_bytes, node);
}

static int __rrr_type_blob_export (RRR_TYPE_EXPORT_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_MSG_0("Length of blob type was 0 in __rrr_type_blob_export\n");
		return 1;
	}
	return __rrr_type_blob_export_or_pack(target, written_bytes, node);
}

static int __rrr_type_str_unpack (RRR_TYPE_UNPACK_ARGS) {
	(void)(node);
	return 0;
}

static int __rrr_type_str_pack (RRR_TYPE_PACK_ARGS) {
	*new_type_id = node->definition->type;
	return __rrr_type_blob_export_or_pack(target, written_bytes, node);
}

static int __rrr_type_msg_pack_or_export (
		char *target,
		rrr_length *written_bytes,
		const struct rrr_type_value *node
) {
	rrr_length pos = 0;

	// It is not possible to specify a multi-value msg definition, but we
	// support it here for now anyway

	while (pos < node->total_stored_length) {
		void *wpos = target + pos;
		void *rpos = node->data + pos;

		struct rrr_msg_msg *msg_at_source = rpos;

		if (MSG_TOTAL_SIZE(msg_at_source) < sizeof(struct rrr_msg_msg) - 1) {
			RRR_MSG_0("Message too short in __rrr_type_msg_pack_or_export\n");
			return 1;
		}

		if (pos + MSG_TOTAL_SIZE(msg_at_source) > node->total_stored_length) {
			RRR_MSG_0("Message longer than stated length __rrr_type_msg_pack_or_export\n");
			return 1;
		}

		memcpy(wpos, rpos, MSG_TOTAL_SIZE(msg_at_source));
		struct rrr_msg_msg *msg_at_target = wpos;

		pos += MSG_TOTAL_SIZE(msg_at_target);

		rrr_msg_msg_prepare_for_network(msg_at_target);
		rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_at_target);
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

static int __rrr_type_str_get_export_length (RRR_TYPE_GET_EXPORT_LENGTH_ARGS) {
	rrr_length escape_count = 0;

	const char *end = node->data + node->total_stored_length;
	for (const char *pos = node->data; pos < end; pos++) {
		if ((*pos) == '\\' || (*pos) == '"') {
			escape_count++;
		}
	}

	rrr_biglength tmp = (rrr_biglength) node->total_stored_length + 2 + escape_count;
	if (tmp > RRR_LENGTH_MAX) {
		RRR_MSG_0("String was too long to export in  __rrr_type_str_get_export_length (%llu > %llu)\n",
			(unsigned long long) tmp,
			(unsigned long long) RRR_LENGTH_MAX
		);
		return 1;
	}

	*bytes = (rrr_length) tmp;

	return 0;
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

	*written_bytes = (rrr_length) (write_pos - target);

	return 0;
}

static int __rrr_type_msg_pack (RRR_TYPE_PACK_ARGS) {
	int ret = __rrr_type_msg_pack_or_export(target, written_bytes, node);
	if (ret != 0) {
		goto out;
	}

	*new_type_id = RRR_TYPE_MSG;

	out:
	return ret;
}

static int __rrr_type_import_err (RRR_TYPE_IMPORT_ARGS) {
	(void)(node);
	(void)(parsed_bytes);
	(void)(start);
	(void)(end);

	RRR_DBG_3("Error trigger reached while importing array definition, triggering soft error.\n");

	return RRR_TYPE_PARSE_SOFT_ERR;
}

static int __rrr_type_import_fixp (RRR_TYPE_IMPORT_ARGS) {
	int ret = RRR_TYPE_PARSE_OK;

	if (node->data != NULL) {
		RRR_BUG("data was not NULL in __rrr_type_import_fixpc\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("array size was not 1 in __rrr_type_import_fixp\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("import length was not 0 in __rrr_type_import_fixp\n");
	}

	rrr_fixp fixp = 0;
	const char *endptr = NULL;

	if ((ret = rrr_fixp_str_to_fixp (
			&fixp,
			start,
			rrr_length_from_ptr_sub_bug_const (end, start),
			&endptr
	)) != 0) {
		return RRR_TYPE_PARSE_SOFT_ERR;
	}

	// Fixed point needs another field after it to know where the number ends
	if (endptr == end) {
		return RRR_TYPE_PARSE_INCOMPLETE;
	}

	// Keep on separate line to suppress warning from static code analysis
	size_t allocation_size = sizeof(fixp);

	if ((node->data = (char *) rrr_allocate(allocation_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_import_fixp\n");
		ret = RRR_TYPE_PARSE_HARD_ERR;
		goto out;
	}

	memcpy(node->data, &fixp, sizeof(fixp));
	node->total_stored_length = sizeof(fixp);

	if (endptr < start) {
		RRR_BUG("BUG: endptr was less than start in __rrr_type_import_fixp\n");
	}

	*parsed_bytes = (rrr_length) (endptr - start);

	out:
	return ret;
}

static int __get_import_length_str (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	const char *start = buf;
	const char *end = buf + buf_size;

	(void)(node);

	int ret = RRR_TYPE_PARSE_INCOMPLETE;

	CHECK_END_AND_RETURN(1);

	if (*start != '"') {
		RRR_MSG_0("str type did not begin with \" but %c (0x%02x)\n", *start, *start);
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}
	start++;

	int prev_was_backslash = 0;
	for (; start < end; start++) {
		char c = *start;
		if (!prev_was_backslash && c == '"') {
			ret = RRR_TYPE_PARSE_OK;
			break;
		}
		else if (!prev_was_backslash && c == '\\') {
			prev_was_backslash = 1;
		}
		else {
			prev_was_backslash = 0;
		}
	}

	if (ret == RRR_TYPE_PARSE_OK) {
		rrr_slength length = start - buf;
		length += 1; // Increment for last "
		*import_length = (rrr_length) length;
	}

	out:
	return ret;
}

static int __get_import_length_nsep (RRR_TYPE_GET_IMPORT_LENGTH_ARGS) {
	const char *start = buf;
	const char *end = buf + buf_size;

	(void)(node);

	int ret = RRR_TYPE_PARSE_INCOMPLETE;

	rrr_length length = 0;

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
		RRR_BUG("BUG: data was not NULL in __rrr_type_import_nsep\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("BUG: array size was not 1 in __rrr_type_import_nsep\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("BUG: length was not 0 in __rrr_type_import_nsep\n");
	}
	if (end < start) {
		RRR_BUG("BUG: end was less than start in __rrr_type_import_nsep\n");
	}

	rrr_length import_length = 0;
	if ((ret = __get_import_length_nsep(&import_length, node, start, (rrr_length) (end - start))) != 0) {
		goto out;
	}

	node->import_length = import_length;
	rrr_length parsed_bytes_tmp = 0;
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
		RRR_BUG("BUG: data was not NULL in __rrr_type_import_str\n");
	}
	if (node->element_count != 1) {
		RRR_BUG("BUG: array size was not 1 in __rrr_type_import_str\n");
	}
	if (node->import_length != 0) {
		RRR_BUG("BUG: length was not 0 in __rrr_type_import_str\n");
	}
	if (end < start) {
		RRR_BUG("BUG: end was less than start in __rrr_type_import_str\n");
	}

	rrr_length import_length = 0;
	if ((ret = __get_import_length_str(&import_length, node, start, (rrr_length) (end - start))) != 0) {
		goto out;
	}

	// Fake lengths to strip out the quotes. Send start + 1 to import after first quote.
	node->import_length = import_length - 2;
	rrr_length parsed_bytes_tmp = 0;
	if ((ret = __rrr_type_import_blob(node, &parsed_bytes_tmp, start + 1, end)) != 0) {
		return ret;
	}

	if (parsed_bytes_tmp + 2 != import_length) {
		RRR_BUG("Parsed bytes vs import length mismatch in __rrr_type_import_str\n");
	}

	node->import_length = import_length;
	*parsed_bytes = parsed_bytes_tmp + 2;

	// Strip out escape sequences inside of the string
	int prev_was_backslash = 0;
	rrr_length wpos = 0;
	for (rrr_length i = 0; i < node->total_stored_length; i++) {
		char c = node->data[i];
		if (!prev_was_backslash && c == '\\') {
			prev_was_backslash = 1;
		}
		else {
			node->data[wpos++] = c;
			prev_was_backslash = 0;
		}
	}
	if (prev_was_backslash) {
		node->data[wpos++] = '\\';
	}
	node->total_stored_length = wpos;

	out:
	return ret;
}

static int __rrr_type_vain_unpack (RRR_TYPE_UNPACK_ARGS) {
	(void)(node);
	return 0;
}

static int __rrr_type_vain_export (RRR_TYPE_EXPORT_ARGS) {
	(void)(target);
	(void)(node);

	*written_bytes = 0;

	return 0;
}

static int __rrr_type_vain_pack (RRR_TYPE_PACK_ARGS) {
	(void)(node);
	(void)(target);

	*written_bytes = 0;
	*new_type_id = RRR_TYPE_VAIN;

	return 0;
}

static int __rrr_type_h_to_str (RRR_TYPE_TO_STR_ARGS) {
	int ret = 0;

	rrr_length output_size = node->total_stored_length * 4;

	char *result = rrr_allocate(output_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in__rrr_type_h_to_str\n");
		return 1;
	}

	char *wpos = result;
	for (rrr_length i = 0; i < node->total_stored_length; i += (rrr_length) sizeof(rrr_type_be)) {
		if (RRR_TYPE_FLAG_IS_SIGNED(node->flags)) {
			int64_t tmp = *((int64_t *) (node->data + i));
			sprintf(wpos, "%s%" PRIi64, (i > 0 ? "," : ""), tmp);
		}
		else {
			uint64_t tmp = *((uint64_t *) (node->data + i));
			sprintf(wpos, "%s%" PRIu64, (i > 0 ? "," : ""), tmp);
		}
		wpos = result + strlen(result);
	}
	result[output_size - 1] = '\0';

	*target = result;

	return ret;
}

static int __rrr_type_fixp_to_str (RRR_TYPE_TO_STR_ARGS) {
	int ret = 0;

	if (node->total_stored_length == 0) {
		RRR_BUG("BUG: Length was 0 in __rrr_type_fixp_to_str\n");
	}

	if (rrr_fixp_to_new_str_double (target, *((rrr_fixp *) (node->data))) != 0) {
		RRR_MSG_0("Could not convert fixp in __rrr_type_fixp_to_str\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_type_bin_to_str (RRR_TYPE_TO_STR_ARGS) {
	if (node->total_stored_length == 0) {
		RRR_BUG("BUG: Length was 0 in __rrr_type_bin_to_str\n");
	}

	rrr_biglength target_length_dummy = 0;

	return rrr_hex_bin_to_hex(target, &target_length_dummy, node->data, node->total_stored_length);
}

static int __rrr_type_str_to_str (RRR_TYPE_TO_STR_ARGS) {
	char *result = rrr_allocate(node->total_stored_length + 1);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_str_to_str\n");
		return 1;
	}

	memcpy(result, node->data, node->total_stored_length);
	(*(result + node->total_stored_length)) = '\0';

	*target = result;

	return 0;
}

static int __rrr_type_vain_to_str (RRR_TYPE_TO_STR_ARGS) {
	(void)(node);

	char *tmp = rrr_allocate(1);
	if (tmp == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_type_vain_to_str\n");
		return 1;
	}
	*tmp = '\0';
	*target = tmp;
	return 0;
}

static uint64_t __rrr_type_blob_to_64 (RRR_TYPE_TO_64_ARGS) {
	const char *end = node->data + node->total_stored_length;
	rrr_length get_length = node->total_stored_length > sizeof(uint64_t) ? sizeof(uint64_t) : node->total_stored_length;

	if (get_length == 0) {
		return 0;
	}

	return __rrr_type_expand_be(get_length, end - get_length, 0);
}

static unsigned long long __rrr_type_h_to_ull (RRR_TYPE_TO_ULL_ARGS) {
	uint64_t tmp = *((uint64_t*) node->data);
	return tmp;
}

static unsigned long long __rrr_type_fixp_to_ull (RRR_TYPE_TO_ULL_ARGS) {
	long double tmp;
	if (rrr_fixp_to_ldouble(&tmp, *((rrr_fixp*) node->data)) != 0) {
		tmp = 0.0;
	}
	return (unsigned long long) tmp;
}

static unsigned long long __rrr_type_str_to_ull (RRR_TYPE_TO_ULL_ARGS) {
	if (node->total_stored_length == 0) {
		return 0;
	}

	char tmp[256];

	rrr_length element_size = node->total_stored_length / node->element_count;
	rrr_length length = element_size < 256 ? element_size : 255;
	memcpy(tmp, node->data, length);
	tmp[length] = '\0';

	char *endptr = NULL;
	unsigned long long result = strtoull(tmp, &endptr, 10);

	return result;
}

static uint64_t __rrr_type_64_to_64 (RRR_TYPE_TO_64_ARGS) {
	return *((uint64_t *) node->data);
}

static uint64_t __rrr_type_vain_to_64 (RRR_TYPE_TO_64_ARGS) {
	(void)(node);
	return 0;
}

#define RRR_TYPE_DEFINE(name,type,max,import,export_length,export,unpack,pack,to_str,to_64,to_ull,name_str) \
    const struct rrr_type_definition RRR_PASTE(rrr_type_definition_,name) = {type, max, import, export_length, export, unpack, pack, to_str, to_64, to_ull, name_str}

RRR_TYPE_DEFINE(be,   RRR_TYPE_BE,   RRR_TYPE_MAX_BE,   __rrr_type_import_be,   NULL,                             NULL,                   __rrr_type_be_unpack,   NULL,                 NULL,                   __rrr_type_64_to_64,   NULL, RRR_TYPE_NAME_BE);
RRR_TYPE_DEFINE(h,    RRR_TYPE_H,    RRR_TYPE_MAX_H,    __rrr_type_import_host, NULL,                             __rrr_type_host_export, NULL,                   __rrr_type_host_pack, __rrr_type_h_to_str,    __rrr_type_64_to_64,   __rrr_type_h_to_ull, RRR_TYPE_NAME_H);
RRR_TYPE_DEFINE(le,   RRR_TYPE_LE,   RRR_TYPE_MAX_LE,   __rrr_type_import_le,   NULL,                             NULL,                   NULL,                   NULL,                 NULL,                   __rrr_type_64_to_64,   NULL, RRR_TYPE_NAME_LE);
RRR_TYPE_DEFINE(blob, RRR_TYPE_BLOB, RRR_TYPE_MAX_BLOB, __rrr_type_import_blob, NULL,                             __rrr_type_blob_export, __rrr_type_blob_unpack, __rrr_type_blob_pack, __rrr_type_bin_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_BLOB);
RRR_TYPE_DEFINE(ustr, RRR_TYPE_USTR, RRR_TYPE_MAX_USTR, __rrr_type_import_ustr, NULL,                             NULL,                   NULL,                   NULL,                 NULL,                   __rrr_type_blob_to_64, NULL, RRR_TYPE_NAME_USTR);
RRR_TYPE_DEFINE(istr, RRR_TYPE_ISTR, RRR_TYPE_MAX_ISTR, __rrr_type_import_istr, NULL,                             NULL,                   NULL,                   NULL,                 NULL,                   __rrr_type_blob_to_64, NULL, RRR_TYPE_NAME_ISTR);
RRR_TYPE_DEFINE(sep,  RRR_TYPE_SEP,  RRR_TYPE_MAX_SEP,  __rrr_type_import_sep,  NULL,                             __rrr_type_blob_export, __rrr_type_blob_unpack, __rrr_type_blob_pack, __rrr_type_str_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_SEP);
RRR_TYPE_DEFINE(msg,  RRR_TYPE_MSG,  RRR_TYPE_MAX_MSG,  __rrr_type_import_msg,  NULL,                             __rrr_type_msg_export,  __rrr_type_msg_unpack,  __rrr_type_msg_pack,  __rrr_type_bin_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_MSG);
RRR_TYPE_DEFINE(fixp, RRR_TYPE_FIXP, RRR_TYPE_MAX_FIXP, __rrr_type_import_fixp, NULL,                             __rrr_type_fixp_export, __rrr_type_fixp_unpack, __rrr_type_fixp_pack, __rrr_type_fixp_to_str, __rrr_type_blob_to_64, __rrr_type_fixp_to_ull, RRR_TYPE_NAME_FIXP);
RRR_TYPE_DEFINE(str,  RRR_TYPE_STR,  RRR_TYPE_MAX_STR,  __rrr_type_import_str,  __rrr_type_str_get_export_length, __rrr_type_str_export,  __rrr_type_str_unpack,  __rrr_type_str_pack,  __rrr_type_str_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_STR);
RRR_TYPE_DEFINE(nsep, RRR_TYPE_NSEP, RRR_TYPE_MAX_NSEP, __rrr_type_import_nsep, NULL,                             __rrr_type_blob_export, __rrr_type_blob_unpack, __rrr_type_blob_pack, __rrr_type_str_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_NSEP);
RRR_TYPE_DEFINE(stx,  RRR_TYPE_STX,  RRR_TYPE_MAX_STX,  __rrr_type_import_stx,  NULL,                             __rrr_type_blob_export, __rrr_type_blob_unpack, __rrr_type_blob_pack, __rrr_type_str_to_str,  __rrr_type_blob_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_STX);
RRR_TYPE_DEFINE(err,  RRR_TYPE_ERR,  RRR_TYPE_MAX_ERR,  __rrr_type_import_err,  NULL,                             NULL,                   NULL,                   NULL,                 NULL,                   NULL,                  NULL, RRR_TYPE_NAME_ERR);
RRR_TYPE_DEFINE(vain, RRR_TYPE_VAIN, RRR_TYPE_MAX_VAIN, __rrr_type_import_vain, NULL,                             __rrr_type_vain_export, __rrr_type_vain_unpack, __rrr_type_vain_pack, __rrr_type_vain_to_str, __rrr_type_vain_to_64, __rrr_type_str_to_ull, RRR_TYPE_NAME_VAIN);
RRR_TYPE_DEFINE(null, 0,             0,                 NULL,                   NULL,                             NULL,                   NULL,                   NULL,                 NULL,                   NULL,                  NULL, NULL);

// If there are types which begin with the same letters, the longest names must be first in the array
// The list MUST end with a null definition
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
		&rrr_type_definition_err,
		&rrr_type_definition_vain,
		&rrr_type_definition_null
};

const struct rrr_type_definition *rrr_type_parse_from_string (
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
) {
	*parsed_bytes = 0;

	int i = 0;
	do {
		const struct rrr_type_definition *type = type_templates[i];
		rrr_length len = (rrr_length) strlen(type->identifier);
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
		const uint8_t type_in
) {
	for (int i = 0; type_templates[i]->type != 0; i++) {
		if (type_templates[i]->type == type_in) {
			return type_templates[i];
		}
	}

	return NULL;
}

void rrr_type_value_destroy (
		struct rrr_type_value *template
) {
	if (template == NULL) {
		return;
	}
	RRR_FREE_IF_NOT_NULL(template->import_length_ref);
	RRR_FREE_IF_NOT_NULL(template->element_count_ref);
	RRR_FREE_IF_NOT_NULL(template->tag);
	RRR_FREE_IF_NOT_NULL(template->data);
	rrr_free(template);
}

int rrr_type_value_is_tag (
		const struct rrr_type_value *value,
		const char *tag
) {
	return ((value->tag == NULL && value == NULL) || (value->tag != NULL && strcmp(tag, value->tag) == 0));
}

int rrr_type_value_set_tag (
		struct rrr_type_value *value,
		const char *tag,
		rrr_length tag_length
) {
	RRR_FREE_IF_NOT_NULL(value->tag);
	if (tag_length > 0) {
		value->tag = rrr_allocate(tag_length + 1);
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

void rrr_type_value_set_data (
		struct rrr_type_value *value,
		char *data,
		rrr_length data_length
) {
	if (value->element_count == 0 || data_length % value->element_count != 0) {
		RRR_BUG("BUG: Data length not divisible by element count in rrr_type_value_set_data or element count was 0\n");
	}

	RRR_FREE_IF_NOT_NULL(value->data);
	value->total_stored_length = data_length;
	value->data = data;
}

int rrr_type_value_new (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_length tag_length,
		const char *tag,
		rrr_length import_length,
		char *import_length_ref,
		rrr_length element_count,
		const char *element_count_ref,
		rrr_length stored_length
) {
	int ret = 0;

	struct rrr_type_value *value = rrr_allocate(sizeof(*value));
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
	value->total_stored_length = stored_length;
	value->definition = type;

	if (import_length_ref != NULL && *import_length_ref != '\0') {
		if ((value->import_length_ref = rrr_strdup(import_length_ref)) == NULL) {
			RRR_MSG_0("Could not allocate data for import length ref in rrr_type_value_new\n");
			ret = 1;
			goto out;
		}
	}

	if (element_count_ref != NULL && *element_count_ref != '\0') {
		if ((value->element_count_ref = rrr_strdup(element_count_ref)) == NULL) {
			RRR_MSG_0("Could not allocate data for element count ref in rrr_type_value_new\n");
			ret = 1;
			goto out;
		}
	}

	if (stored_length > 0) {
		value->data = rrr_allocate(stored_length);
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

int rrr_type_value_new_and_unpack (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		const char *data_start,
		rrr_type_flags flags,
		rrr_length tag_length,
		rrr_length total_length,
		rrr_length element_count
) {
	int ret = 0;

	struct rrr_type_value *value = NULL;

	if ((ret = rrr_type_value_new (
			&value,
			type,
			flags,
			tag_length,
			data_start,
			total_length,
			NULL,
			element_count,
			NULL,
			total_length
	)) != 0) {
		goto out;
	}

	if (total_length > 0) {
		memcpy (value->data, data_start + tag_length, total_length);
	}

	if (value->definition->unpack == NULL) {
		RRR_MSG_0("Illegal type %s in %s, cannot be unpacked.\n", type->identifier, __func__);
		ret = 1;
		goto out_free;

	}

	if ((ret = value->definition->unpack(value)) != 0) {
		RRR_MSG_0("Error while unpacking type %s in %s\n", type->identifier, __func__);
		goto out_free;
	}

	*result = value;

	goto out;
	out_free:
		rrr_type_value_destroy(value);
	out:
		return ret;
}

int rrr_type_value_new_simple (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_length tag_length,
		const char *tag
) {
	return rrr_type_value_new (result, type, flags, tag_length, tag, 0, NULL, 0, NULL, 0);
}

int rrr_type_new_vain (
		struct rrr_type_value **target,
		rrr_length tag_length,
		const char *tag
) {
	return rrr_type_value_new (
			target,
			&rrr_type_definition_vain,
			0,
			tag_length,
			tag,
			0,
			NULL,
			1,
			NULL,
			0
	);
}

int rrr_type_new_h (
		struct rrr_type_value **target,
		rrr_length tag_length,
		const char *tag,
		rrr_length element_count
) {
	int ret = 0;

	if (element_count == 0) {
		RRR_BUG("BUG: Element count was 0 in rrr_type_new_h\n");
	}

	rrr_biglength stored_length = sizeof(uint64_t) * element_count;

	if (stored_length > RRR_LENGTH_MAX) {
		RRR_MSG_0("Requested length exceeded maximum in rrr_type_new_h (%" PRIrrrbl ">%u)",
			stored_length, RRR_LENGTH_MAX);
		ret = RRR_TYPE_PARSE_SOFT_ERR;
		goto out;
	}

	if ((ret = rrr_type_value_new (
			target,
			&rrr_type_definition_h,
			0,
			tag_length,
			tag,
			0,
			NULL,
			element_count,
			NULL,
			(rrr_length) stored_length
	)) != 0) {
		goto out;
	}

	memset((*target)->data, '\0', (long unsigned int) stored_length);

	out:
	return ret;
}

int rrr_type_value_clone (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		int do_clone_data
) {
	int ret = 0;

	*target = NULL;

	struct rrr_type_value *new_value;
	if ((new_value = rrr_allocate(sizeof(*new_value))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_type_value_clone\n");
		ret = 1;
		goto out;
	}

	// Use memcpy to ensure that flags, type etc. are cloned
	memcpy(new_value, source, sizeof(*new_value));

	// Ensure that pointers to allocated values are NULL
	new_value->import_length_ref = NULL;
	new_value->element_count_ref = NULL;
	new_value->tag = NULL;
	new_value->data = NULL;

	if (source->import_length_ref != NULL && (new_value->import_length_ref = rrr_strdup(source->import_length_ref)) == NULL) {
		RRR_MSG_0("Could not duplicate string in rrr_type_value_clone\n");
		ret = 1;
		goto out;
	}

	if (source->element_count_ref != NULL && (new_value->element_count_ref = rrr_strdup(source->element_count_ref)) == NULL) {
		RRR_MSG_0("Could not duplicate string in rrr_type_value_clone\n");
		ret = 1;
		goto out;
	}

	if (do_clone_data && source->data != NULL) {
		if ((new_value->data = rrr_allocate(source->total_stored_length)) == NULL) {
			RRR_MSG_0("Could not allocate memory for data in rrr_type_value_clone\n");
			ret = 1;
			goto out;
		}
		memcpy(new_value->data, source->data, (size_t) source->total_stored_length);
		new_value->total_stored_length = source->total_stored_length;
	}
	else {
		new_value->data = NULL;
	}

	if (source->tag_length > 0) {
		// Do not use strdup, no \0 at the end
		if ((new_value->tag = rrr_allocate(source->tag_length + 1)) == NULL) {
			RRR_MSG_0("Could not allocate memory for tag in rrr_type_value_clone\n");
			ret = 1;
			goto out;
		}
		memcpy(new_value->tag, source->tag, new_value->tag_length);
		new_value->tag[source->tag_length] = '\0';
		new_value->tag_length = source->tag_length;
	}
	else if (new_value->tag != NULL) {
		RRR_BUG("tag was not NULL but tag length was >0 in rrr_type_value_clone\n");
	}

	*target = new_value;
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	return ret;
}

int rrr_type_value_get_export_length (
		rrr_length *result,
		const struct rrr_type_value *value
) {
	*result = 0;

	if (value->definition->get_export_length != NULL) {
		return value->definition->get_export_length(result, value);
	}

	*result = value->total_stored_length;

	return 0;
}

int rrr_type_value_allocate_and_export (
		char **target,
		rrr_length *written_bytes,
		const struct rrr_type_value *node
) {
	int ret = 0;

	*target = NULL;
	*written_bytes = 0;

	char *buf_tmp = NULL;
	rrr_length buf_size = 0;

	if ((ret = rrr_type_value_get_export_length(&buf_size, node)) != 0) {
		goto out;
	}

	if ((buf_tmp = rrr_allocate(buf_size)) == NULL) {
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
	buf_tmp = NULL;

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
		rrr_length tag_length,
		const char *tag,
		rrr_length import_length,
		rrr_length element_count
) {
	int ret = 0;

	rrr_length stored_length = import_length * element_count;

	if (data_end < data_start) {
		RRR_BUG("BUG: end was less than start in rrr_type_value_allocate_and_import_raw\n");
	}

	if (stored_length != (uintptr_t) data_end - (uintptr_t) data_start) {
		RRR_BUG("BUG: Incorrect lengths to rrr_type_value_allocate_and_import_raw, import and stored lengths must be equal\n");
	}

	struct rrr_type_value *value = NULL;
	if ((rrr_type_value_new (
			&value,
			definition,
			0,
			tag_length,
			tag,
			import_length,
			NULL,
			element_count,
			NULL,
			0 // <-- Do not pass stored length, causes allocation which should be done by import function
	)) != 0) {
		RRR_MSG_0("Could not allocate value in rrr_type_value_allocate_and_import_raw\n");
		ret = 1;
		goto out;
	}

	if (value->data != NULL) {
		RRR_BUG("BUG: Data was allocated by new function in rrr_type_value_allocate_and_import_raw\n");
	}

	rrr_length parsed_bytes = 0;

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
		RRR_MSG_0("Parsed bytes mismatch, parsed %" PRIrrrl " bytes while %" PRIrrrl " was expected\n", parsed_bytes, stored_length);
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

int rrr_type_value_with_tmp_do (
		RRR_TYPE_RAW_FIELDS,
		int (*callback)(const struct rrr_type_value *value, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_type_value *value_tmp = NULL;

	if ((ret = rrr_type_value_new_and_unpack (
			&value_tmp,
			type,
			data_start,
			flags,
			tag_length,
			total_length,
			element_count
	)) != 0) {
		goto out;
	}

	if ((ret = callback(value_tmp, callback_arg)) != 0) {
		goto out;
	}

	out:
	if (value_tmp != NULL) {
		rrr_type_value_destroy(value_tmp);
	}
	return ret;
}
