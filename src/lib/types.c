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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include "cmdlineparser/cmdline.h"
#include "types.h"
#include "messages.h"
#include "../global.h"

#define PASTER(x,y) x ## _ ## y

#define RRR_TYPES_MATCH_RETURN(str,name) \
	if (strcmp(str,PASTER(RRR_TYPE_NAME,name)) == 0){return PASTER(RRR_TYPE,name);}

rrr_type rrr_types_get_type(const char *type) {
	rrr_type ret = 0;

	RRR_TYPES_MATCH_RETURN(type,BE)
	RRR_TYPES_MATCH_RETURN(type,LE)
	RRR_TYPES_MATCH_RETURN(type,BLOB)

	return ret;
}

#define RRR_TYPE_LENGTH_CHECK_CASE(type,length,max) \
		case PASTER(RRR_TYPE,type): \
			max = PASTER(RRR_TYPE_MAX,type); \
			return ((length <= PASTER(RRR_TYPE_MAX,type)) == 1 ? 0 : 1)

int rrr_types_check_size (rrr_type type, rrr_type_length length, rrr_type_length *max) {
	switch (type) {
		RRR_TYPE_LENGTH_CHECK_CASE(LE,length,*max);
		RRR_TYPE_LENGTH_CHECK_CASE(BE,length,*max);
		RRR_TYPE_LENGTH_CHECK_CASE(BLOB,length,*max);
		default:
			VL_MSG_ERR("BUG: Unknown type '%d' given too rrr_types_check_size\n", type);
			exit(EXIT_FAILURE);
	};

	return 1;
}

int convert_le(void *target, const char *data, rrr_type_length length) {
	if (length > sizeof(rrr_type_le)) {
		VL_MSG_ERR("BUG: convert_le received length > %lu", sizeof(rrr_type_le));
		return 1;
	}

	union leunion {
		rrr_type_le temp_f;
		char temp_b[sizeof(rrr_type_le)];
	};

	union leunion temp;
	rrr_type_le final;

	temp.temp_f = 0;

	rrr_type_length wpos = 0;
	rrr_type_length i = 0;
	do {
		temp.temp_b[wpos++] = data[i++];
	} while (i < length);

	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(final),convert_function_size_match_le)
	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(temp.temp_f),convert_function_size_match_le)
	final = le64toh(temp.temp_f);

	memcpy(target, &final, sizeof(final));

	return 0;
}

int convert_be(void *target, const char *data, rrr_type_length length) {
	if (length > sizeof(rrr_type_le)) {
		VL_MSG_ERR("BUG: convert_le received length > %lu", sizeof(rrr_type_le));
		return 1;
	}

	union beunion {
		rrr_type_be temp_f;
		char temp_b[sizeof(rrr_type_be)];
	};

	union beunion temp;
	rrr_type_be final;

	temp.temp_f = 0;

	rrr_type_length wpos = sizeof(rrr_type_be) - 1;
	rrr_type_length i = 0;
	do {
		temp.temp_b[wpos--] = data[i++];
	} while (i < length);

	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(final),convert_function_size_match_le)
	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(temp.temp_f),convert_function_size_match_le)
	final = be64toh(temp.temp_f);

	memcpy(target, &final, sizeof(final));

	return 0;
}

int convert_blob(void *target, const char *data, rrr_type_length length) {
	return 0;
}

int convert_64_to_le(void *data) {
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = htole64(temp);
	return 0;
}

int convert_blob_to_le(void *target) {
	return 0;
}

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_convert_functions[]) (void *target, const char *data, rrr_type_length length) = {
		NULL,
		&convert_le,
		&convert_be,
		&convert_blob
};

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_to_le[]) (void *data) = {
		NULL,
		&convert_64_to_le,
		&convert_64_to_le,
		&convert_blob_to_le
};

int rrr_types_parse_definition (
		struct rrr_type_definition_collection *target,
		struct cmd_data *cmd,
		const char *cmd_key
) {
	rrr_def_count count = 0;

	memset (target, '\0', sizeof(*target));

	target->version = RRR_VERSION;

	for (cmd_arg_count i = 0; i < CMD_ARGUMENT_MAX; i += 2) {
		const char *type_c = cmd_get_subvalue(cmd, cmd_key, 0, i);
		if (*type_c == '\0') {
			break;
		}

		const char *length_c = cmd_get_subvalue(cmd, cmd_key, 0, i + 1);
		if (length_c == NULL) {
			VL_MSG_ERR("Missing size definition for '%s' type definition in '%s'\n", type_c, cmd_key);
			goto out_err;
		}

		rrr_type type = rrr_types_get_type(type_c);
		if (type == 0) {
			VL_MSG_ERR("Unknown type '%s' in '%s\n", type_c, cmd_key);
			goto out_err;
		}

		int length;
		if (cmd_convert_integer_10(cmd, length_c, &length) != 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' was not a valid number\n", length_c, type_c, cmd_key);
			goto out_err;
		}

		if (length <= 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' must be >0\n", length_c, type_c, cmd_key);
			goto out_err;
		}

		rrr_type_length max;
		if (rrr_types_check_size(type, length, &max) != 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' is too large, max is '%lu'\n", length_c, type_c, cmd_key, max);
			goto out_err;
		}

		target->definitions[count].max_length = max;
		target->definitions[count].length = length;
		target->definitions[count].type = type;

		count++;
	}

	target->count = count;

	return 0;

	out_err:
	return 1;
}

int rrr_types_parse_data (
		const char *data, const rrr_type_length length,
		struct rrr_data_collection *target
) {
	const char *pos = data;
	const char *end = data + length;
	const struct rrr_type_definition_collection *definitions = &target->definitions;

	for (rrr_def_count i = 0; i < definitions->count; i++) {
		VL_DEBUG_MSG_3("Parsing type index %lu of type %d\n", i, definitions->definitions[i].type);
		if (rrr_types_convert_functions[definitions->definitions[i].type] == NULL) {
			VL_MSG_ERR("BUG: No convert function found for type %d\n", definitions->definitions[i].type);
			exit (EXIT_FAILURE);
		}
		if (pos > end || pos + definitions->definitions[i].length > end) {
			VL_MSG_ERR("Input data was too short according to configuration in type conversion\n");
			VL_MSG_ERR("Received length was '%lu'\n", length);
			return 1;
		}
		if (rrr_types_convert_functions[definitions->definitions[i].type](target->data[i], pos, definitions->definitions[i].length) != 0) {
			VL_MSG_ERR("Invalid data in type conversion\n");
			return 1;
		}

		pos += definitions->definitions[i].length;
	}

	return 0;
}
struct rrr_data_collection *rrr_types_allocate_data (
		const struct rrr_type_definition_collection *definitions
) {
	struct rrr_data_collection *collection = malloc(sizeof(struct rrr_data_collection));
	if (collection == NULL) {
		VL_MSG_ERR("Could not allocate memory for data collection\n");
		return NULL;
	}

	memset (collection->data, '\0', sizeof(collection->data));

	if (definitions->count > RRR_TYPES_MAX_DEFINITIONS) {
		VL_MSG_ERR("BUG: Too many definitions in rrr_types_parse_data\n");
		exit (EXIT_FAILURE);
	}

	for (rrr_def_count i = 0; i < definitions->count; i++) {
		collection->data[i] = malloc (definitions->definitions[i].max_length);
		if (collection->data[i] == NULL) {
			VL_MSG_ERR("Could not allocate %lu bytes of memory for collection type data\n", definitions->definitions[i].length);
			goto out_free_elements;
		}
	}

	memcpy (&collection->definitions, definitions, sizeof(collection->definitions));

	return collection;

	out_free_elements:
	for (rrr_def_count i = 0; i < definitions->count; i++) {
		if (collection->data[i] != NULL) {
			free(collection->data[i]);
		}
	}

	out_free_collection:
	free (collection);

	return NULL;
}

rrr_type_length rrr_get_total_max_data_length(const struct rrr_data_collection *data) {
	rrr_type_length ret = 0;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
			ret += data->definitions.definitions[i].max_length;
	}
	return ret;
}

int rrr_types_merge_data(char *target, rrr_type_length target_length, const struct rrr_data_collection *data) {
	rrr_type_length length = rrr_get_total_max_data_length(data);
	if (target_length < length) {
		VL_MSG_ERR("BUG: Target length was too small in rrr_types_merge_data\n");
		return 1;
	}

	char *pos = target;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		memcpy(target, data->data + i, length);
		target += data->definitions.definitions[i].max_length;
	}

	return 0;
}

void rrr_types_destroy_data (struct rrr_data_collection *collection) {
	for (rrr_def_count i = 0; i < collection->definitions.count; i++) {
		free(collection->data[i]);
	}
	free (collection);
}

void rrr_types_definition_to_le(struct rrr_type_definition_collection *definition) {
	struct rrr_type_definition_collection new;
	memset (&new, '\0', sizeof(new));

	new.count = htole32(definition->count);
	new.version = htole16(definition->version);

	for (rrr_def_count i = 0; i < definition->count; i++) {
		new.definitions[i].length = htole32(definition->definitions[i].length);
		new.definitions[i].max_length = htole32(definition->definitions[i].max_length);
		new.definitions[i].type = definition->definitions[i].type;
	}

	memcpy (definition, &new, sizeof (*definition));
}

struct vl_message *rrr_types_create_message_le(const struct rrr_data_collection *data, uint64_t time) {
	rrr_type_length total_length = sizeof(struct rrr_type_definition_collection) + rrr_get_total_max_data_length(data);
	struct vl_message *message = message_new_array(time, total_length);
	if (message == NULL) {
		VL_MSG_ERR("Could not create message for data collection\n");
		return NULL;
	}

	struct rrr_type_definition_collection *new_definition = (void*) message->data;
	char *new_datastream = message->data + sizeof(*new_definition);

	memcpy (new_definition, &data->definitions, sizeof(*new_definition));

	char *pos = new_datastream;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		memcpy(pos, data->data + i, data->definitions.definitions[i].length);
		rrr_types_to_le[data->definitions.definitions[i].type](pos);
	}

	rrr_types_definition_to_le(new_definition);

	return message;
}
