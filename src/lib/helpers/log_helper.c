/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "log_helper.h"

#include "../array.h"
#include "../log.h"
#include "../messages/msg_log.h"
#include "../messages/msg_msg_struct.h"
#include "../socket/rrr_socket.h"
#include "../allocator.h"

static int __rrr_log_helper_extract_uint_field (
		uint64_t *target,
		struct rrr_array *array,
		const char *field,
		int mandatory
) {
	int ret = RRR_LOG_HELPER_OK;

	const struct rrr_type_value *value_tmp;

	if ((value_tmp = rrr_array_value_get_by_tag_const(array, field)) == NULL && mandatory) {
		RRR_MSG_0("Required field '%s' not present\n",
			field);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}
	else if (value_tmp == NULL) {
		goto out;
	}
	else if (!RRR_TYPE_IS_64(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' was not an integer\n",
			field);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}
	else if (!RRR_TYPE_FLAG_IS_UNSIGNED(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' was not unsigned\n",
			field);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}

	if (rrr_array_get_value_unsigned_64_by_tag(target, array, field, 0)) {
		RRR_MSG_0("Failed to get unsigned field '%s' from array\n",
			field);
		ret = RRR_LOG_HELPER_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_log_helper_extract_string_field (
		char **target,
		struct rrr_array *array,
		const char *field,
		int mandatory
) {
	int ret = RRR_LOG_HELPER_OK;

	const struct rrr_type_value *value_tmp;

	if ((value_tmp = rrr_array_value_get_by_tag_const(array, field)) == NULL && mandatory) {
		RRR_MSG_0("Required field '%s' not present\n",
			field);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}
	else if (value_tmp == NULL) {
		goto out;
	}
	else if (!RRR_TYPE_IS_STR(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' was not a string\n",
			field);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}

	if (rrr_array_get_value_str_by_tag(target, array, field) != 0) {
		RRR_MSG_0("Failed to get string field '%s'\n",
			field);
		ret = RRR_LOG_HELPER_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

int rrr_log_helper_extract_log_fields_from_array (
		char **log_file,
		int *log_line,
		uint8_t *log_level_translated,
		char **log_prefix,
		char **log_message,
		struct rrr_array *array
) {
	int ret = 0;

	char *log_file_tmp = NULL;
	char *log_message_tmp = NULL;
	char *log_prefix_tmp = NULL;
	uint64_t log_level_translated_tmp = 7;
	uint64_t log_line_tmp = 0;

	if ((ret = __rrr_log_helper_extract_string_field(&log_file_tmp, array, "log_file", 0)) != 0) {
		goto out;
	}

	if ((ret = __rrr_log_helper_extract_uint_field(&log_line_tmp, array, "log_line", 0)) != 0) {
		goto out;
	}

	if (log_line_tmp > INT_MAX) {
		RRR_MSG_0("Line number exceeded maximum of %i\n", INT_MAX);
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}

	if ((ret = __rrr_log_helper_extract_uint_field(&log_level_translated_tmp, array, "log_level_translated", 0)) != 0) {
		goto out;
	}

	if (log_level_translated_tmp > 7) {
		RRR_MSG_0("Log level exceeded the maximum of 7\n");
		ret = RRR_LOG_HELPER_SOFT_ERROR;
		goto out;
	}

	if ((ret = __rrr_log_helper_extract_string_field(&log_prefix_tmp, array, "log_prefix", 0)) != 0) {
		goto out;
	}

	if ((ret = __rrr_log_helper_extract_string_field(&log_message_tmp, array, "log_message", 1)) != 0) {
		goto out;
	}

	*log_message = log_message_tmp;
	*log_prefix = log_prefix_tmp;
	*log_file = log_file_tmp;
	*log_level_translated = (uint8_t) log_level_translated_tmp;
	*log_line = rrr_int_from_slength_bug_const(log_line_tmp);

	goto out_final;
	out:
		RRR_FREE_IF_NOT_NULL(log_message_tmp);
		RRR_FREE_IF_NOT_NULL(log_prefix_tmp);
		RRR_FREE_IF_NOT_NULL(log_file_tmp);
	out_final:
		return ret;
}

int rrr_log_helper_log_msg_make (
		struct rrr_msg_log **target,
		rrr_length *target_size,
		const char *log_file,
		int log_line,
		uint8_t log_level_translated,
		uint8_t log_level_orig,
		const char *log_prefix,
		const char *log_message
) {
	int ret = 0;

	if ((ret = rrr_msg_msg_log_new (
			target,
			log_file,
			log_line,
			log_level_translated,
			log_level_orig,
			log_prefix,
			log_message
	)) != 0) {
		goto out;
	}

	*target_size = MSG_TOTAL_SIZE(*target);

	rrr_msg_msg_log_prepare_for_network(*target);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) *target);

	out:
	return ret;
}
