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
#include <inttypes.h>

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
			return ((length <= PASTER(RRR_TYPE_MAX,type) && (length >= 0)) == 1 ? 0 : 1)

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

int convert_le(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	if (length > sizeof(rrr_type_le)) {
		VL_MSG_ERR("BUG: convert_le received length > %lu", sizeof(rrr_type_le));
		return 1;
	}

	if (array_size > 1) {
		int ret = 0;
		for (int i = 0; i < array_size; i++) {
			ret = convert_le(target + (i * length), data + (i * length), 1, length);
			if (ret != 0) {
				break;
			}
		}
		return ret;
	}

	union leunion {
		rrr_type_le temp_f;
		char temp_b[sizeof(rrr_type_le)];
	};

	union leunion temp;
	rrr_type_le final;

	temp.temp_f = 0;

	rrr_type_length pos = 0;
	while (pos < length) {
		temp.temp_b[pos] = data[pos];
		pos++;
	}

	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(final),convert_function_size_match_le)
	VL_ASSERT(sizeof(le64toh(temp.temp_f))==sizeof(temp.temp_f),convert_function_size_match_le)

	final = le64toh(temp.temp_f);

	memcpy(target, &final, sizeof(final));

	VL_DEBUG_MSG_3("Converted a le64: %llu\n", (long long unsigned int) final);

	return 0;
}

int convert_be(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	if (length > sizeof(rrr_type_le)) {
		VL_MSG_ERR("BUG: convert_le received length > %lu", sizeof(rrr_type_le));
		return 1;
	}

	if (array_size > 1) {
		int ret = 0;
		for (int i = 0; i < array_size; i++) {
			ret = convert_be(target + (i * length), data + (i * length), 1, length);
			if (ret != 0) {
				break;
			}
		}
		return ret;
	}

	union beunion {
		rrr_type_be temp_f;
		char temp_b[sizeof(rrr_type_be)];
	};

	union beunion temp;
	rrr_type_be final;

	temp.temp_f = 0;

	rrr_type_length wpos = sizeof(rrr_type_be) - 1;
	rrr_type_length rpos = length - 1;

	VL_DEBUG_MSG_3("rpos: %d, wpos: %d\n", rpos, wpos);

	while (1) {
		temp.temp_b[wpos] = data[rpos];

		if (rpos == 0) {
			break;
		}

		wpos--;
		rpos--;
	}

	VL_ASSERT(sizeof(be64toh(temp.temp_f))==sizeof(final),convert_function_size_match_be)
	VL_ASSERT(sizeof(be64toh(temp.temp_f))==sizeof(temp.temp_f),convert_function_size_match_be)

	final = be64toh(temp.temp_f);

	memcpy(target, &final, sizeof(final));

	VL_DEBUG_MSG_3("Converted a be64: %llu\n", (long long unsigned int) final);

	return 0;
}

int convert_blob(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	return 0;
}

int convert_64_to_le(void *data) {
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = htole64(temp);

//	VL_DEBUG_MSG_3("Converted type host64 to le64: %llu->%llu\n", temp, *result);

	return 0;
}

int convert_blob_to_le(void *target) {
	return 0;
}

int convert_64_to_host(void *data) {
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = le64toh(temp);
	return 0;
}

int convert_blob_to_host(void *target) {
	return 0;
}

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_convert_functions[]) (void *target, const char *data, rrr_array_size array_size, rrr_type_length length) = {
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

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_to_host[]) (void *data) = {
		NULL,
		&convert_64_to_host,
		&convert_64_to_host,
		&convert_blob_to_host
};

int rrr_types_parse_definition (
		struct rrr_type_definition_collection *target,
		struct cmd_data *cmd,
		const char *cmd_key
) {
	rrr_def_count count = 0;

	memset (target, '\0', sizeof(*target));

	target->version = RRR_VERSION;

	int do_array = 0;
	rrr_array_size array_size = 1;
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

		if (strcmp(type_c, RRR_TYPE_NAME_ARRAY) == 0) {
			int length;
			if (cmd_convert_integer_10(cmd, length_c, &length) != 0) {
				VL_MSG_ERR("Size argument '%s' in type definition for array in '%s' was not a valid number\n", length_c, cmd_key);
				goto out_err;
			}
			if (length < 1 || length > RRR_TYPE_MAX_ARRAY) {
				VL_MSG_ERR("Size argument '%s' in type definition for array in '%s' was not within range\n", length_c, cmd_key);
				goto out_err;
			}

			do_array = 1;
			array_size = length;
			continue;
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
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' is too large, max is '%u'\n", length_c, type_c, cmd_key, max);
			goto out_err;
		}

		target->definitions[count].max_length = max;
		target->definitions[count].length = length;
		target->definitions[count].type = type;
		target->definitions[count].array_size = array_size;

		count++;
		do_array = 0;
		array_size = 1;
	}

	if (do_array) {
		VL_MSG_ERR("Array was specified at end of type definition in '%s'\n", cmd_key);
		goto out_err;
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
		VL_DEBUG_MSG_3("Parsing type index %u of type %d, %d copies\n", i, definitions->definitions[i].type, definitions->definitions[i].array_size);
		if (rrr_types_convert_functions[definitions->definitions[i].type] == NULL) {
			VL_MSG_ERR("BUG: No convert function found for type %d\n", definitions->definitions[i].type);
			exit (EXIT_FAILURE);
		}
		if (pos > end || pos + definitions->definitions[i].length > end) {
			VL_MSG_ERR("Input data was too short according to configuration in type conversion\n");
			VL_MSG_ERR("Received length was '%u'\n", length);
			return 1;
		}
		if (rrr_types_convert_functions[definitions->definitions[i].type](target->data[i], pos, definitions->definitions[i].array_size, definitions->definitions[i].length) != 0) {
			VL_MSG_ERR("Invalid data in type conversion\n");
			return 1;
		}

		pos += (definitions->definitions[i].length * definitions->definitions[i].array_size);
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
		if (!RRR_TYPE_OK(definitions->definitions[i].type)) {
			VL_MSG_ERR("Invalid type %d received in rrr_types_allocate_data\n",
					definitions->definitions[i].type);
			goto out_free_elements;
		}

		rrr_type_length max_length;
		if (rrr_types_check_size(definitions->definitions[i].type, definitions->definitions[i].length, &max_length) != 0) {
			VL_MSG_ERR("Invalid length %d received in rrr_types_allocate_data, max length is %d\n",
					definitions->definitions[i].length, max_length);
			goto out_free_elements;
		}

		if (definitions->definitions[i].max_length != max_length) {
			VL_MSG_ERR("Max length mismatch from default in rrr_types_allocate_data, %d vs %d",
					definitions->definitions[i].max_length, max_length);
			goto out_free_elements;
		}

		if (definitions->definitions[i].array_size < 1 || definitions->definitions[i].array_size > RRR_TYPE_MAX_ARRAY) {
			VL_MSG_ERR("Invalid array length %d received in rrr_types_allocate_data, bounds are %d to %d\n",
					definitions->definitions[i].array_size, 1, RRR_TYPE_MAX_ARRAY);
			goto out_free_elements;
		}

		int allocate = definitions->definitions[i].max_length * definitions->definitions[i].array_size;
		VL_DEBUG_MSG_3("Allocating memory for type in definition: %d\n", allocate);
		collection->data[i] = malloc (allocate);

		if (collection->data[i] == NULL) {
			VL_MSG_ERR("Could not allocate %u bytes of memory for collection type data\n", allocate);
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
			ret += data->definitions.definitions[i].max_length * data->definitions.definitions[i].array_size;
	}
	return ret;
}
/*
int rrr_types_merge_data(char *target, rrr_type_length target_length, const struct rrr_data_collection *data) {
	rrr_type_length length = rrr_get_total_max_data_length(data);
	if (target_length < length) {
		VL_MSG_ERR("BUG: Target length was too small in rrr_types_merge_data\n");
		return 1;
	}

	char *pos = target;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		memcpy(target, data->data + i, data->definitions.definitions[i].length * data->definitions.definitions[i].array_size);
		target += data->definitions.definitions[i].max_length;
	}

	return 0;
}
*/
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
		new.definitions[i].array_size = htole32(definition->definitions[i].array_size);
	}

	memcpy (definition, &new, sizeof (*definition));
}

void rrr_types_definition_to_host(struct rrr_type_definition_collection *definition) {
	struct rrr_type_definition_collection new;
	memset (&new, '\0', sizeof(new));

	new.count = le32toh(definition->count);
	new.version = le16toh(definition->version);

	for (rrr_def_count i = 0; i < definition->count; i++) {
		new.definitions[i].length = le32toh(definition->definitions[i].length);
		new.definitions[i].max_length = le32toh(definition->definitions[i].max_length);
		new.definitions[i].type = definition->definitions[i].type;
		new.definitions[i].array_size = le32toh(definition->definitions[i].array_size);
	}

	memcpy (definition, &new, sizeof (*definition));
}

struct vl_message *rrr_types_create_message_le(const struct rrr_data_collection *data, uint64_t time) {
	rrr_type_length total_length = sizeof(struct rrr_type_definition_collection) + rrr_get_total_max_data_length(data);
	struct vl_message *message = NULL;

	message = message_new_array(time, total_length);
	if (message == NULL) {
		VL_MSG_ERR("Could not create message for data collection\n");
		return NULL;
	}

	struct rrr_type_definition_collection *new_definition = (void*) message->data;
	char *new_datastream = message->data + sizeof(*new_definition);

	memcpy (new_definition, &data->definitions, sizeof(*new_definition));

	char *pos = new_datastream;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		memcpy(pos, data->data[i], data->definitions.definitions[i].max_length * data->definitions.definitions[i].array_size);

		if (rrr_types_to_le[data->definitions.definitions[i].type](pos) != 0) {
			VL_MSG_ERR("Error while converting type index %lu to le\n", (long unsigned int) i);
			return NULL;
		}

		pos += data->definitions.definitions[i].max_length * data->definitions.definitions[i].array_size;
	}

	rrr_types_definition_to_le(new_definition);

	return message;
}

int rrr_types_message_to_collection(struct rrr_data_collection **target, const struct vl_message *message_orig) {
	struct rrr_type_definition_collection definitions;
	memcpy (&definitions, message_orig->data, sizeof(definitions));
	const char *data_pos = message_orig->data + sizeof(definitions);

	rrr_types_definition_to_host(&definitions);

	if (definitions.version != RRR_VERSION) {
		VL_MSG_ERR("rrr_types received array of incompatible version %u, expected %d\n", definitions.version, RRR_VERSION);
		return 1;
	}

	struct rrr_data_collection *new_data = *target = rrr_types_allocate_data(&definitions);

	if (new_data == NULL) {
		VL_MSG_ERR("Could not allocate data for new data collection in rrr_types_message_to_collection\n");
		return 1;
	}

	const char *pos = data_pos;
	for (rrr_def_count i = 0; i < definitions.count; i++) {
		char *target = new_data->data[i];
		struct rrr_type_definition *definition = &definitions.definitions[i];

		memcpy (target, data_pos, definition->max_length * definition->array_size);
		data_pos += definition->max_length * definition->array_size;

		if (data_pos > message_orig->data + message_orig->length) {
			VL_MSG_ERR("Data read position exceeded message length in rrr_types_message_to_collection\n");
			exit(EXIT_FAILURE);
		}

		if (!RRR_TYPE_OK(definition->type)) {
			VL_MSG_ERR("Invalid type %u found when parsing array message to collection\n", definition->type);
			goto out_free_data;
		}

		rrr_types_to_host[definition->type](target);
	}

	return 0;

	out_free_data:
	free(new_data);
	return 1;
}
