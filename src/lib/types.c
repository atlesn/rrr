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
#include "settings.h"
#include "instance_config.h"
#include "messages.h"
#include "../global.h"

#define PASTER(x,y) x ## _ ## y

#define RRR_TYPES_MATCH_RETURN(str,name) \
	if (strcmp(str,PASTER(RRR_TYPE_NAME,name)) == 0){return PASTER(RRR_TYPE,name);}

rrr_type rrr_types_get_type(const char *type) {
	rrr_type ret = 0;

	RRR_TYPES_MATCH_RETURN(type,BE)
	RRR_TYPES_MATCH_RETURN(type,LE)
	RRR_TYPES_MATCH_RETURN(type,H)
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
		RRR_TYPE_LENGTH_CHECK_CASE(H,length,*max);
		RRR_TYPE_LENGTH_CHECK_CASE(BLOB,length,*max);
		default:
			VL_MSG_ERR("BUG: Unknown type '%d' given too rrr_types_check_size\n", type);
			exit(EXIT_FAILURE);
	};

	return 1;
}

int import_le(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	if (length > sizeof(rrr_type_le)) {
		VL_MSG_ERR("BUG: import_le received length > %lu", sizeof(rrr_type_le));
		return 1;
	}

	if (array_size > 1) {
		int ret = 0;
		for (int i = 0; i < array_size; i++) {
			ret = import_le(target + (i * length), data + (i * length), 1, length);
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

	temp.temp_f = 0;

	/* Little endian:
	 * (0x01 0x00 0x00)le = 1
	 * (0x01 0x00 0x00 0x00 0x00 0x00)le = 1
	 */

	rrr_type_length pos = 0;
	while (pos < length) {
		temp.temp_b[pos] = data[pos];
		pos++;
	}

	memcpy(target, &temp.temp_f, sizeof(temp.temp_f));

	VL_DEBUG_MSG_3("Imported a le64: 0x%" PRIx64 "\n", le64toh(temp.temp_f));

	return 0;
}

int import_be(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	if (length > sizeof(rrr_type_be)) {
		VL_MSG_ERR("BUG: convert_be received length > %lu", sizeof(rrr_type_be));
		return 1;
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("import_be input: 0x");
		for (int i = 0; i < length; i++) {
			char c = data[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	if (array_size > 1) {
		int ret = 0;
		for (int i = 0; i < array_size; i++) {
			ret = import_be(target + (i * length), data + (i * length), 1, length);
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

	temp.temp_f = 0;

	rrr_type_length wpos = sizeof(temp.temp_f) - 1;
	rrr_type_length rpos = length - 1;

	// VL_DEBUG_MSG_3("rpos: %d, wpos: %d\n", rpos, wpos);

	/* Big endian:
	 * (0x00 0x00 0x01)be = 1
	 * (0x00 0x00 0x00 0x00 0x00 0x01)be = 1
	 */

	while (1) {
		temp.temp_b[wpos] = data[rpos];

		if (rpos == 0) {
			break;
		}

		wpos--;
		rpos--;
	}

	memcpy(target, &temp.temp_f, sizeof(temp.temp_f));

	VL_DEBUG_MSG_3("Imported a be64: 0x%" PRIx64 "\n", be64toh(temp.temp_f));

	return 0;
}

int import_h(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	return (RRR_TYPE_SYSTEM_ENDIAN_IS_LE ?
			import_le(target, data, array_size, length) :
			import_be(target, data, array_size, length)
	);
}

int import_blob(void *target, const char *data, rrr_array_size array_size, rrr_type_length length) {
	memcpy(target, data, array_size * length);
	return 0;
}

int convert_le_64_to_host(void *data) {
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = le64toh(temp);
	return 0;
}

int convert_be_64_to_host(void *data) {
	uint64_t temp;
	memcpy (&temp, data, sizeof(temp));

	uint64_t *result = data;
	*result = be64toh(temp);
	return 0;
}

int convert_h_64_to_host(void *data) {
	return 0;
}

int convert_blob_to_host(void *target) {
	return 0;
}

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_import_functions[]) (void *target, const char *data, rrr_array_size array_size, rrr_type_length length) = {
		NULL,
		&import_le,
		&import_be,
		&import_h,
		&import_blob
};

/* Must be in same positions as type ID in types.h */
/*static int (*rrr_types_convert_functions[]) (void *target, const char *data, rrr_array_size array_size, rrr_type_length length) = {
		NULL,
		&convert_le,
		&convert_be,
		&convert_blob
};*/

/* Must be in same positions as type ID in types.h */
/*static int (*rrr_types_to_le[]) (void *data) = {
		NULL,
		&convert_64_to_le,
		&convert_64_to_le,
		&convert_blob_to_le
};*/

/* Must be in same positions as type ID in types.h */
static int (*rrr_types_to_host[]) (void *data) = {
		NULL,
		&convert_le_64_to_host,
		&convert_be_64_to_host,
		&convert_h_64_to_host,
		&convert_blob_to_host
};

int convert_integer_10(const char *value, int *result) {
	char *err;
	*result = strtol(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int rrr_types_parse_definition (
		struct rrr_type_definition_collection *target,
		struct rrr_instance_config *config,
		const char *cmd_key
) {
	int ret = 0;
	rrr_def_count count = 0;
	struct rrr_settings_list *list = NULL;

	memset (target, '\0', sizeof(*target));

	target->endian_two = RRR_TYPE_ENDIAN_BYTES;

	if (rrr_instance_config_split_commas_to_array (&list, config, cmd_key) != 0) {
		VL_MSG_ERR("Error while splitting comma list to array for instance %s setting %s\n", config->name, cmd_key);
		ret = 1;
		goto out_nofree;
	}

	if (list->length % 2 != 0) {
		VL_MSG_ERR ("Number of elements in type definition was not even for instance %s setting %s\n", config->name, cmd_key);
		ret = 1;
		goto out;
	}

	if (list->length / 2 > RRR_TYPE_MAX_DEFINITIONS) {
		VL_MSG_ERR ("Too many elements in type definition (%i vs %i) for instance %s setting %s\n",
				list->length, RRR_TYPE_MAX_DEFINITIONS, config->name, cmd_key);
		ret = 1;
		goto out;
	}

	int do_array = 0;
	rrr_array_size array_size = 1;
	for (cmd_arg_count i = 0; i < list->length; i += 2) {
		const char *type_c = list->list[i];
		if (*type_c == '\0') {
			break;
		}

		const char *length_c = list->list[i + 1];
		if (length_c == NULL) {
			VL_MSG_ERR("Missing size definition for '%s' type definition in '%s'\n", type_c, cmd_key);
			ret = 1;
			goto out;
		}

		if (strcmp(type_c, RRR_TYPE_NAME_ARRAY) == 0) {
			int length;
			if (convert_integer_10(length_c, &length) != 0) {
				VL_MSG_ERR("Size argument '%s' in type definition for array in '%s' was not a valid number\n", length_c, cmd_key);
				ret = 1;
				goto out;
			}
			if (length < 1 || length > RRR_TYPE_MAX_ARRAY) {
				VL_MSG_ERR("Size argument '%s' in type definition for array in '%s' was not within range\n", length_c, cmd_key);
				ret = 1;
				goto out;
			}

			do_array = 1;
			array_size = length;
			continue;
		}

		rrr_type type = rrr_types_get_type(type_c);
		if (type == 0) {
			VL_MSG_ERR("Unknown type '%s' in '%s\n", type_c, cmd_key);
			ret = 1;
			goto out;
		}

		int length;
		if (convert_integer_10(length_c, &length) != 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' was not a valid number\n", length_c, type_c, cmd_key);
			ret = 1;
			goto out;
		}

		if (length <= 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' must be >0\n", length_c, type_c, cmd_key);
			ret = 1;
			goto out;
		}

		rrr_type_length max;
		if (rrr_types_check_size(type, length, &max) != 0) {
			VL_MSG_ERR("Size argument '%s' in type definition '%s' in '%s' is too large, max is '%u'\n", length_c, type_c, cmd_key, max);
			ret = 1;
			goto out;
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
		ret = 1;
		goto out;
	}

	target->count = count;
	target->version = RRR_TYPE_VERSION;

	out:
	rrr_settings_list_destroy(list);

	out_nofree:

	return ret;
}

int rrr_types_parse_data (
		struct rrr_data_collection *target,
		const char *data, const rrr_type_length length
) {
	const char *pos = data;
	const char *end = data + length;
	const struct rrr_type_definition_collection *definitions = &target->definitions;

	if (length == 0) {
		VL_MSG_ERR("BUG: Length was 0 in rrr_types_parse_data\n");
		exit(EXIT_FAILURE);
	}

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG("rrr_types_parse_data input: 0x");
		for (int i = 0; i < length; i++) {
			char c = data[i];
			if (c < 0x10) {
				VL_DEBUG_MSG("0");
			}
			VL_DEBUG_MSG("%x", c);
		}
		VL_DEBUG_MSG("\n");
	}

	for (rrr_def_count i = 0; i < definitions->count; i++) {
		const struct rrr_type_definition *def = &definitions->definitions[i];

		VL_DEBUG_MSG_3("Parsing type index %u of type %d, %d copies\n", i, def->type, def->array_size);
		if (rrr_types_import_functions[def->type] == NULL) {
			VL_MSG_ERR("BUG: No convert function found for type %d\n", def->type);
			exit (EXIT_FAILURE);
		}
		if (pos > end || pos + def->length > end) {
			VL_MSG_ERR("Input data was too short according to configuration in type conversion\n");
			VL_MSG_ERR("Received length was '%u'\n", length);
			return 1;
		}
		if (rrr_types_import_functions[def->type](target->data[i], pos, def->array_size, def->length) != 0) {
			VL_MSG_ERR("Invalid data in type conversion\n");
			return 1;
		}

		pos += (def->length * def->array_size);
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

	collection->definitions.endian_two = RRR_TYPE_ENDIAN_BYTES;

	if (definitions->count > RRR_TYPE_MAX_DEFINITIONS) {
		VL_MSG_ERR("BUG: Too many definitions in rrr_types_parse_data\n");
		exit (EXIT_FAILURE);
	}

	for (rrr_def_count i = 0; i < definitions->count; i++) {
		const struct rrr_type_definition *def = &definitions->definitions[i];
		if (!RRR_TYPE_OK(def->type)) {
			VL_MSG_ERR("Invalid type %d received in rrr_types_allocate_data\n",
					def->type);
			goto out_free_elements;
		}

		rrr_type_length max_length;
		if (rrr_types_check_size(def->type, def->length, &max_length) != 0) {
			VL_MSG_ERR("Invalid length %d received in rrr_types_allocate_data, max length is %d\n",
					def->length, max_length);
			goto out_free_elements;
		}

		if (def->max_length != max_length) {
			VL_MSG_ERR("Max length mismatch from default in rrr_types_allocate_data, %d vs %d",
					def->max_length, max_length);
			goto out_free_elements;
		}

		if (def->array_size < 1 || def->array_size > RRR_TYPE_MAX_ARRAY) {
			VL_MSG_ERR("Invalid array length %d received in rrr_types_allocate_data, bounds are %d to %d\n",
					def->array_size, 1, RRR_TYPE_MAX_ARRAY);
			goto out_free_elements;
		}

		int allocate = (RRR_TYPE_IS_64(def->type) ? def->max_length : def->length) * def->array_size;

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

rrr_type_length rrr_get_total_integer_max_length(const struct rrr_data_collection *data) {
	rrr_type_length ret = 0;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		if (RRR_TYPE_IS_64(data->definitions.definitions[i].type)) {
			ret += data->definitions.definitions[i].max_length * data->definitions.definitions[i].array_size;
		}
	}
	return ret;
}

rrr_type_length rrr_get_total_blob_length(const struct rrr_data_collection *data) {
	rrr_type_length ret = 0;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		if (RRR_TYPE_IS_BLOB(data->definitions.definitions[i].type)) {
			ret += data->definitions.definitions[i].length * data->definitions.definitions[i].array_size;
		}
	}
	return ret;
}

rrr_type_length rrr_get_raw_length(const struct rrr_data_collection *data) {
	rrr_type_length ret = 0;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		const struct rrr_type_definition *def = &data->definitions.definitions[i];

		if (RRR_TYPE_IS_64(def->type)) {
			ret += def->max_length * def->array_size;
		}
		else if (RRR_TYPE_IS_BLOB(def->type)) {
			ret += def->length * def->array_size;
		}
		else {
			VL_MSG_ERR("BUG: Unknown type %u in rrr_get_raw_length\n", def->type);
			exit(EXIT_FAILURE);
		}
	}
	return ret;
}

void rrr_types_destroy_data (struct rrr_data_collection *collection) {
	for (rrr_def_count i = 0; i < collection->definitions.count; i++) {
		free(collection->data[i]);
	}
	free (collection);
}

int rrr_types_collection_data_to_host (struct rrr_data_collection *data) {
	int ret = 0;

	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		struct rrr_type_definition *def = &data->definitions.definitions[i];

		if (!RRR_TYPE_OK(def->type)) {
			VL_MSG_ERR("BUG: Unknown type %u in rrr_types_collection_data_to_host\n", i);
			exit(EXIT_FAILURE);
		}

		if (rrr_types_to_host[def->type](data->data[i]) != 0) {
			VL_MSG_ERR("Error while converting member with index %u in rrr_types_collection_data_to_host\n", i);
			return 1;
		}

		if (RRR_TYPE_IS_64(def->type)) {
			def->type = RRR_TYPE_H;
		}
	}

	return ret;
}

int rrr_types_definition_to_host(struct rrr_type_definition_collection *definition) {
	int ret = 0;

	struct rrr_type_definition_collection new;
	memset (&new, '\0', sizeof(new));

	if (RRR_TYPE_DEF_IS_LE(definition)) {
		new.count = le32toh(definition->count);
		new.version = le16toh(definition->version);

		for (rrr_def_count i = 0; i < definition->count; i++) {
			new.definitions[i].length = le32toh(definition->definitions[i].length);
			new.definitions[i].max_length = le32toh(definition->definitions[i].max_length);
			new.definitions[i].type = definition->definitions[i].type;
			new.definitions[i].array_size = le32toh(definition->definitions[i].array_size);
		}
	}
	else if (RRR_TYPE_DEF_IS_BE(definition)) {
		new.count = be32toh(definition->count);
		new.version = be16toh(definition->version);

		for (rrr_def_count i = 0; i < definition->count; i++) {
			new.definitions[i].length = be32toh(definition->definitions[i].length);
			new.definitions[i].max_length = be32toh(definition->definitions[i].max_length);
			new.definitions[i].type = definition->definitions[i].type;
			new.definitions[i].array_size = be32toh(definition->definitions[i].array_size);
		}
	}
	else {
		VL_MSG_ERR("Unknown endian indicator 0x%02x in rrr_types_definition_to_host\n", definition->endian_two);
		ret = 1;
		goto out;
	}

	memcpy (definition, &new, sizeof (*definition));

	out:
	return ret;
}

int rrr_types_extract_blob (char **target, rrr_size *size, const struct rrr_data_collection *collection, rrr_def_count pos, rrr_def_count array_pos, int do_zero_terminate) {
	int ret = 0;
	*target = NULL;
	*size = 0;

	if (pos > collection->definitions.count) {
		VL_MSG_ERR("BUG: Out of bounds access in rrr_types_extract_host_64\n");
		return 1;
	}

	const struct rrr_type_definition *def = &collection->definitions.definitions[pos];

	if (array_pos > def->array_size) {
		VL_MSG_ERR("BUG: Out of bounds array access in rrr_types_extract_host_64\n");
		return 1;
	}

	if (!RRR_TYPE_IS_BLOB(def->type)) {
		VL_MSG_ERR("BUG: Tries to access an element which was not a blob in rrr_types_extract_blob\n");
		return 1;
	}

	rrr_size def_size = def->length;
	if (def_size > def->max_length) {
		VL_MSG_ERR("BUG: Wrong sizes in rrr_types_extract_blob\n");
		return 1;
	}

	char *out = malloc(def_size + 1);
	if (out == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_types_extract_blob\n");
		return 1;
	}

	memcpy(out, collection->data[pos] + def_size * array_pos, def_size);

	*target = out;
	*size = def->length;

	if (do_zero_terminate) {
		out[def_size] = '\0';
		(*size)++;
	}

	return ret;
}

int rrr_types_extract_host_64 (uint64_t *target, const struct rrr_data_collection *collection, rrr_def_count pos, rrr_def_count array_pos) {
	if (pos > collection->definitions.count) {
		VL_MSG_ERR("BUG: Out of bounds access in rrr_types_extract_host_64\n");
		return 1;
	}

	const struct rrr_type_definition *def = &collection->definitions.definitions[pos];

	if (array_pos > def->array_size) {
		VL_MSG_ERR("BUG: Out of bounds array access in rrr_types_extract_host_64\n");
		return 1;
	}

	if (!RRR_TYPE_IS_64(def->type)) {
		VL_MSG_ERR("BUG: Tries to access an element which was not a 64 in rrr_types_extract_host_64\n");
		return 1;
	}

	if (def->max_length != sizeof(*target) || def->length > def->max_length) {
		VL_MSG_ERR("BUG: Wrong sizes in rrr_types_extract_host_64\n");
		return 1;
	}

	memcpy(target, collection->data[pos] + sizeof(def->max_length) * array_pos, sizeof(*target));

	if (rrr_types_to_host[def->type](target) != 0) {
		VL_MSG_ERR("BUG: Received error from endian convert function in rrr_types_extract_host_64\n");
		return 1;
	}

	return 0;
}

int rrr_types_extract_raw_from_collection_static(char *target, rrr_size target_size, rrr_size *return_size, const struct rrr_data_collection *data) {
	rrr_type_length length = rrr_get_raw_length(data);
	*return_size = 0;

	if (target_size < length) {
		VL_MSG_ERR("BUG: Target size was too small in rrr_types_extract_raw_from_collection_static\n");
		return 1;
	}

	char *out = target;

	char *pos = out;
	for (rrr_def_count i = 0; i < data->definitions.count; i++) {
		const struct rrr_type_definition *def = &data->definitions.definitions[i];

		if (RRR_TYPE_IS_64(def->type)) {
			memcpy(pos, data->data[i], def->max_length * def->array_size);
			pos += def->max_length * def->array_size;
		}
		else if (RRR_TYPE_IS_BLOB(def->type)) {
			memcpy(pos, data->data[i], def->length * def->array_size);
			pos += def->length * def->array_size;
		}
		else {
			VL_MSG_ERR("BUG: Unknown type %u in rrr_types_extract_raw_from_collection\n", def->type);
			exit(EXIT_FAILURE);
		}

	}

	*return_size = length;
	return 0;
}

int rrr_types_extract_raw_from_collection(char **target, rrr_size *size, const struct rrr_data_collection *data) {
	rrr_type_length length = rrr_get_raw_length(data);

	char *out = malloc(length);
	if (out == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_types_extract_raw_from_collection\n");
		return 1;
	}

	int ret = rrr_types_extract_raw_from_collection_static(out, length, size, data);
	if (ret != 0) {
		free(out);
		return 1;
	}

	return 0;
}

struct vl_message *rrr_types_create_message(const struct rrr_data_collection *data, uint64_t time) {
	rrr_type_length total_length = sizeof(struct rrr_type_definition_collection) + rrr_get_raw_length(data);
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
		const struct rrr_type_definition *def = &data->definitions.definitions[i];

		char *new_pos = pos;
		if (RRR_TYPE_IS_64(def->type)) {
			memcpy(pos, data->data[i], def->max_length * def->array_size);
			new_pos += def->max_length * def->array_size;
		}
		else {
			memcpy(pos, data->data[i], def->length * def->array_size);
			new_pos += def->length * def->array_size;
		}

/*		if (rrr_types_to_le[def->type](pos) != 0) {
			VL_MSG_ERR("Error while converting type index %lu to le\n", (long unsigned int) i);
			return NULL;
		}*/

		pos = new_pos;
	}

//	rrr_types_definition_to_le(new_definition);

	return message;
}

int rrr_types_message_to_collection(struct rrr_data_collection **target, const struct vl_message *message_orig) {
	struct rrr_type_definition_collection definitions;
	memcpy (&definitions, message_orig->data, sizeof(definitions));
	const char *data_pos = message_orig->data + sizeof(definitions);

	if (rrr_types_definition_to_host(&definitions) != 0) {
		VL_MSG_ERR("Error while converting type definition to host endianess\n");
		return 1;
	}

	if (definitions.version != RRR_TYPE_VERSION) {
		VL_MSG_ERR("rrr_types received array of incompatible version %u, expected %d\n", definitions.version, RRR_TYPE_VERSION);
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
		struct rrr_type_definition *def = &definitions.definitions[i];

		if (RRR_TYPE_IS_64(def->type)) {
			memcpy (target, data_pos, def->max_length * def->array_size);
			data_pos += def->max_length * def->array_size;
		}
		else {
			memcpy (target, data_pos, def->length * def->array_size);
			data_pos += def->length * def->array_size;
		}

		if (data_pos > message_orig->data + message_orig->length) {
			VL_MSG_ERR("Data read position exceeded message length in rrr_types_message_to_collection\n");
			exit(EXIT_FAILURE);
		}

		if (!RRR_TYPE_OK(def->type)) {
			VL_MSG_ERR("Invalid type %u found when parsing array message to collection\n", def->type);
			goto out_free_data;
		}
	}

	return 0;

	out_free_data:
	free(new_data);
	return 1;
}
