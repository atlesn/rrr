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
#include <endian.h>
#include <string.h>
#include <ctype.h>

#include "mqtt_packet.h"
#include "mqtt_common.h"
#include "utf8.h"

static const struct rrr_mqtt_packet_protocol_version protocol_versions[] = {
		{RRR_MQTT_VERSION_3_1, "MQISDP"},
		{RRR_MQTT_VERSION_3_1_1, "MQTT"},
		{RRR_MQTT_VERSION_5, "MQTT"},
		{0, NULL}
};

static const char *rrr_mqtt_packet_type_names[] = {
	"RESERVED",
	"CONNECT",
	"CONNACK",
	"PUBLISH",
	"PUBACK",
	"PUBREC",
	"PUBREL",
	"PUBCOMP",
	"SUBSCRIBE",
	"SUBACK",
	"UNSUBSCRIBE",
	"UNSUBACK",
	"PINGREQ",
	"PINGRESP",
	"DISCONNECT",
	"AUTH"
};

#define RRR_MQTT_P_GET_TYPE_NAME(p)	\
	(rrr_mqtt_packet_type_names[RRR_MQTT_P_GET_TYPE(p)])

#define RRR_MQTT_P_GET_TYPE_NAME_RAW(t)	\
	(rrr_mqtt_packet_type_names[(t)])

static const struct rrr_mqtt_packet_protocol_version *__rrr_mqtt_packet_get_protocol_version_from_id (uint8_t id) {
	for (int i = 0; protocol_versions[i].name != NULL; i++) {
		if (protocol_versions[i].id == id) {
			return &protocol_versions[i];
		}
	}

	return NULL;
}

static int __rrr_mqtt_packet_protocol_version_validate_name (
		const struct rrr_mqtt_packet_protocol_version *protocol_version,
		const char *string
) {
	int len = strlen(string);

	char uppercase[len + 1];
	uppercase[len] = '\0';

	const char *input = string;
	char *output = uppercase;
	while (*input) {
		*output = toupper(*input);
		output++;
		input++;
	}

	if (strcmp(protocol_version->name, uppercase) == 0) {
		return 0;
	}

	return 1;
}

static void __rrr_mqtt_packet_property_destroy (
		struct rrr_mqtt_property *property
) {
	if (property == NULL) {
		return;
	}
	if (property->sibling != NULL) {
		__rrr_mqtt_packet_property_destroy(property->sibling);
	}

	RRR_FREE_IF_NOT_NULL(property->data);
	free(property);
}

static int __rrr_mqtt_packet_property_new (
		struct rrr_mqtt_property **target,
		const struct rrr_mqtt_property_definition *definition
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_property *res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_packet_property_new\n");
		ret = 1;
		goto out;
	}

	memset(res, '\0', sizeof(*res));

	res->definition = definition;

	*target = res;

	out:
	return ret;
}

static void __rrr_mqtt_packet_property_collection_add (
		struct rrr_mqtt_property_collection *collection,
		struct rrr_mqtt_property *property
) {
	property->next = NULL;
	property->order = ++(collection->count);

	if (collection->first == NULL) {
		collection->first = property;
		collection->last = property;
		return;
	}

	collection->last->next = property;
	collection->last = property;
}

static void __rrr_mqtt_packet_property_collection_destroy (
		struct rrr_mqtt_property_collection *collection
) {
	struct rrr_mqtt_property *cur = collection->first;
	while (cur) {
		struct rrr_mqtt_property *next = cur->next;

		__rrr_mqtt_packet_property_destroy(cur);

		cur = next;
	}
	collection->first = NULL;
	collection->last = NULL;
}

void __rrr_mqtt_packet_property_collection_init (
		struct rrr_mqtt_property_collection *collection
) {
	memset(collection, '\0', sizeof(*collection));
}

void rrr_mqtt_packet_parse_session_destroy (
		struct rrr_mqtt_p_parse_session *session
) {
	if (session->buf == NULL) {
		return;
	}

	__rrr_mqtt_packet_property_collection_destroy(&session->properties);

	memset(session, '\0', sizeof(*session));
}

void rrr_mqtt_packet_parse_session_init (
		struct rrr_mqtt_p_parse_session *session,
		const char *buf,
		ssize_t buf_size
) {
	if (session->buf != NULL) {
		VL_BUG("rrr_mqtt_packet_parse_session_init called with non-NULL buf\n");
	}

	memset(session, '\0', sizeof(*session));

	__rrr_mqtt_packet_property_collection_init(&session->properties);

	session->buf = buf;
	session->buf_size = buf_size;
}

#define RRR_MQTT_PACKET_PARSE_OK 0
#define RRR_MQTT_PACKET_PARSE_INTERNAL_ERROR 1
#define RRR_MQTT_PACKET_PARSE_INCOMPLETE 2
#define RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR 3
#define RRR_MQTT_PACKET_PARSE_OVERFLOW 4

#define RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session) \
	do { if ((start) + (end-start) >= (session)->buf + (session)->buf_size) { \
		return RRR_MQTT_PACKET_PARSE_INCOMPLETE; \
	}} while (0)

int __rrr_mqtt_packet_parse_variable_int (uint32_t *target, ssize_t *bytes_parsed, const void *buf, ssize_t len) {
	ssize_t pos = 0;
	uint32_t result = 0;
	uint32_t exponent = 1;
	uint8_t carry = 1;

	*target = 0;
	*bytes_parsed = 0;

	if (len == 0) {
		VL_BUG("__rrr_mqtt_packet_parse_variable_int called with zero length");
	}

	while (carry) {
		if (pos == len) {
			/* Could not finish the value, input too short */
			return RRR_MQTT_PACKET_PARSE_INCOMPLETE;
		}
		if (pos > 3) {
			/* Only four bytes allowed */
			return RRR_MQTT_PACKET_PARSE_OVERFLOW;
		}

		uint8_t current = *((uint8_t *) (buf + pos));
		uint8_t value = current & 0x7f;
		carry = current & 0x80;

		result += (value * exponent);

		exponent *= 128;
		pos++;
	}

	*target = result;
	*bytes_parsed = pos;

	return RRR_MQTT_PACKET_PARSE_OK;
}

#define RRR_MQTT_PROPERTY_DATA_TYPE_ONE 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_TWO 2
#define RRR_MQTT_PROPERTY_DATA_TYPE_FOUR 4
#define RRR_MQTT_PROPERTY_DATA_TYPE_VINT 5
#define RRR_MQTT_PROPERTY_DATA_TYPE_BLOB 6
#define RRR_MQTT_PROPERTY_DATA_TYPE_UTF8 7
#define RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8 8

#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32 1
#define RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB 2

#define RRR_PROPERTY_PARSER_DEFINITION \
		struct rrr_mqtt_property *target, struct rrr_mqtt_p_parse_session *session, \
		const char *start, ssize_t *bytes_parsed_final

static int __rrr_mqtt_property_save_uint32 (struct rrr_mqtt_property *target, uint32_t value) {
	target->data = malloc(sizeof(value));
	if (target->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_property_parse_integer\n");
		return RRR_MQTT_PACKET_PARSE_INTERNAL_ERROR;
	}

	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_UINT32;
	target->length = sizeof(value);
	memcpy (target->data, &value, sizeof(value));

	return RRR_MQTT_PACKET_PARSE_OK;
}

static int __rrr_mqtt_property_parse_integer (struct rrr_mqtt_property *target, const char *start, ssize_t length) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	if (length > 4) {
		VL_BUG("Too many bytes in __rrr_mqtt_property_parse_integer\n");
	}

	union {
		uint32_t result;
		uint8_t bytes[4];
	} int_merged;

	int_merged.result = 0;

	int wpos = 3;
	int rpos = length - 1;
	while (rpos >= 0) {
		int_merged.bytes[wpos] = *((uint8_t *) (start + rpos));
		wpos--;
		rpos--;
	}

	int_merged.result = be32toh(int_merged.result);

	if ((ret = __rrr_mqtt_property_save_uint32(target, int_merged.result)) != 0) {
		return ret;
	}

	target->length = length;

	return ret;
}

static int __rrr_mqtt_property_parse_one (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,start + 1,session);

	ret = __rrr_mqtt_property_parse_integer(target, start, 1);
	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		return ret;
	}

	*bytes_parsed_final = 1;

	return ret;
}

static int __rrr_mqtt_property_parse_two (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,start + 2,session);

	ret = __rrr_mqtt_property_parse_integer(target, start, 2);
	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		return ret;
	}

	*bytes_parsed_final = 2;

	return ret;
}
static int __rrr_mqtt_property_parse_four (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,start + 4,session);

	ret = __rrr_mqtt_property_parse_integer(target, start, 4);
	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		return ret;
	}

	*bytes_parsed_final = 4;

	return ret;
}
static int __rrr_mqtt_property_parse_vint (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	uint32_t result = 0;

	ret = __rrr_mqtt_packet_parse_variable_int(&result, bytes_parsed_final, start, session->buf_size - (start - session->buf));
	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		return ret;
	}

	if ((ret = __rrr_mqtt_property_save_uint32(target, result)) != 0) {
		return ret;
	}

	return ret;
}

static int __rrr_mqtt_property_parse_blob (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_PACKET_PARSE_OK;

	uint16_t blob_length = 0;
	ssize_t bytes_parsed = 0;

	const char *end = start + 2;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);
	blob_length = be16toh(*((uint16_t*)start));

	bytes_parsed += 2;

	start = end;
	end = start + blob_length;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);

	target->data = malloc(blob_length);
	if (target->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_property_parse_blob\n");
		return RRR_MQTT_PACKET_PARSE_INTERNAL_ERROR;
	}

	memcpy(target->data, start, blob_length);
	target->length = blob_length;
	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB;

	bytes_parsed += blob_length;

	*bytes_parsed_final = bytes_parsed;

	return ret;
}

struct parse_utf_validate_callback_data {
	uint32_t character;
	int has_illegal_character;
};

static int __rrr_mqtt_property_parse_utf_validate_callback (uint32_t character, void *arg) {
	struct parse_utf_validate_callback_data *data = arg;
	if (character == 0 || (character >= 0xD800 && character <= 0xDFFF)) {
		data->has_illegal_character = 1;
		data->character = character;
		return 1;
	}
	return 0;
}

static int __rrr_mqtt_property_parse_utf8 (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = 0;

	ret = __rrr_mqtt_property_parse_blob(target, session, start, bytes_parsed_final);
	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		return ret;
	}

	struct parse_utf_validate_callback_data callback_data = {0, 0};

	if (rrr_utf8_validate_and_iterate (
			target->data,
			target->length,
			__rrr_mqtt_property_parse_utf_validate_callback,
			&callback_data
	) != 0) {
		VL_MSG_ERR("Malformed UTF-8 detected in mqtt message\n");
		if (callback_data.has_illegal_character == 1) {
			VL_MSG_ERR("Illegal character 0x%04x\n", callback_data.character);
		}
		ret = RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
	}

	return ret;
}
static int __rrr_mqtt_property_parse_2utf8 (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}

static int (* const property_parsers[]) (RRR_PROPERTY_PARSER_DEFINITION) = {
		NULL,
		__rrr_mqtt_property_parse_one,
		__rrr_mqtt_property_parse_two,
		NULL,
		__rrr_mqtt_property_parse_four,
		__rrr_mqtt_property_parse_vint,
		__rrr_mqtt_property_parse_blob,
		__rrr_mqtt_property_parse_utf8,
		__rrr_mqtt_property_parse_2utf8
};

static const struct rrr_mqtt_property_definition property_definitions[] = {
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x01, "Payload format indicator"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x02, "Message expiry interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x03, "Content type"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x08, "Response topic"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_BLOB,	0x09, "Correlation data"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_VINT,	0x0B, "Subscription identifier"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x11, "Session expiry interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x12, "Assigned client identifier"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x13, "Server keep-alive"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x15, "Authentication method"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_BLOB,	0x16, "Authentication data"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x17, "Request problem information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x18, "Will delay interval"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x19, "Request response information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1A, "Response information"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1C, "Server reference"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_UTF8,	0x1F, "Reason string"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x21, "Receive maximum"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x22, "Topic alias maximum"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_TWO,	0x23, "Topic alias"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x24, "Maximum QoS"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x25, "Retain available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_2UTF8,	0x26, "User property"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_FOUR,	0x27, "Maximum packet size"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x28, "Wildcard subscription available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x29, "Subscription identifier available"},
		{RRR_MQTT_PROPERTY_DATA_TYPE_ONE,	0x2A, "Shared subscription available"},
		{0, 0, NULL}
};

static const struct rrr_mqtt_property_definition *__rrr_mqtt_p_get_property_definition(uint8_t id) {
	for (int i = 0; property_definitions[i].type != 0; i++) {
		if (property_definitions[i].identifier == id) {
			return &property_definitions[i];
		}
	}

	return NULL;
}

static int __rrr_mqtt_p_parse_properties (
		struct rrr_mqtt_p_parse_session *session,
		const char *start,
		ssize_t *bytes_parsed_final
) {
	int ret = 0;
	const char *end = NULL;

	*bytes_parsed_final = 0;

	uint32_t property_length = 0;
	ssize_t bytes_parsed = 0;
	ssize_t bytes_parsed_total = 0;

	ret = __rrr_mqtt_packet_parse_variable_int(&property_length, &bytes_parsed, start, (session->buf_size - (start - session->buf)));

	if (ret != RRR_MQTT_PACKET_PARSE_OK) {
		if (ret == RRR_MQTT_PACKET_PARSE_OVERFLOW) {
			VL_MSG_ERR("Overflow while parsing property length variable int\n");
		}
		return ret;
	}

	bytes_parsed_total += bytes_parsed;
	start += bytes_parsed;
	while (1) {
		end = start + 1;
		RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);

		uint8_t type = *((uint8_t *) start);

		const struct rrr_mqtt_property_definition *property_def = __rrr_mqtt_p_get_property_definition(type);
		if (property_def == NULL) {
			VL_MSG_ERR("Unknown mqtt property field found: 0x%02x\n", type);
			return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
		}

		struct rrr_mqtt_property *property = NULL;
		if ((ret = __rrr_mqtt_packet_property_new(&property, property_def)) != 0) {
			return RRR_MQTT_PACKET_PARSE_INTERNAL_ERROR;
		}

		start = end;
		ret = property_parsers[property_def->type](property, session, start, &bytes_parsed);
		if (ret != 0) {
			__rrr_mqtt_packet_property_destroy(property);
			return ret;
		}

		 __rrr_mqtt_packet_property_collection_add (&session->properties, property);

		bytes_parsed_total += bytes_parsed;
		start = end + bytes_parsed;
	}

	*bytes_parsed_final = bytes_parsed_total;

	return ret;
}

static int rrr_mqtt_p_parser_connect (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;

	const char *start = NULL;
	const char *end = NULL;

	// PROTOCOL NAME LENGTH
	start = session->buf + session->variable_header_pos;
	end = start + 2;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);

	uint16_t protocol_name_length = be16toh(*((uint16_t *) start));

	if (protocol_name_length > 6) {
		VL_MSG_ERR("Protocol name in connect packet was too long\n");
		return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
	}

	// PROTOCOL NAME
	start = end;
	end = start + protocol_name_length;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);

	char name_buf[7];
	strncpy(name_buf, start, protocol_name_length);
	name_buf[protocol_name_length] = '\0';

	// PROTOCOL VERSION
	start = end;
	end = start + 1;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);

	uint8_t protocol_version = *((uint8_t *) start);

	/* The actual protocol version may change later when the properties are parsed */
	session->protocol_version = __rrr_mqtt_packet_get_protocol_version_from_id(protocol_version);

	if (session->protocol_version == NULL) {
		VL_MSG_ERR("MQTT protocol version could not be found, input name was '%s' version was '%u'\n",
				name_buf, protocol_version);
		return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
	}

	if (__rrr_mqtt_packet_protocol_version_validate_name(session->protocol_version, name_buf) != 0) {
		VL_MSG_ERR("MQTT protocol version name mismatch, input name was '%s' version was '%u'. Expected name '%s'\n",
				name_buf, protocol_version, session->protocol_version->name);
		return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
	}

	// CONNECT FLAGS
	start = end;
	end = start + 1;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);
	session->connect_flags = *((uint8_t *) start);

	if (RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(session) != 0) {
		VL_MSG_ERR("Last bit of MQTT connect packet flags was not zero\n");
		return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL(session) == 0) {
		if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(session) != 0 || RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(session) != 0) {
			VL_MSG_ERR("WILL flag of mqtt connect packet was zero, but not WILL_QOS and WILL_RETAIN\n");
			return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
		}
	}

	if (session->protocol_version->id < RRR_MQTT_VERSION_5) {
		if (RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(session) == 1 && RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(session) == 0) {
			VL_MSG_ERR("Password flag was set in mqtt connect packet but not username flag. Not allowed for protocol version <5\n");
			return RRR_MQTT_PACKET_PARSE_PARAMETER_ERROR;
		}
	}

	// KEEP ALIVE
	start = end;
	end = start + 2;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);
	session->keep_alive = be16toh(*((uint16_t *) start));

	// CONNECT PROPERTIES
	if (session->protocol_version->id >= RRR_MQTT_VERSION_5) {
		start = end;
		ssize_t bytes_parsed;
		ret = __rrr_mqtt_p_parse_properties(session, start, &bytes_parsed);
		if (ret != 0) {
			VL_MSG_ERR("Error while parsing properties of connect packet\n");
			return ret;
		}
		end = start + bytes_parsed;
	}

	// CLIENT IDENTIFIER
	start = end;
	end = start + 2;
	RRR_MQTT_PACKET_PARSE_CHECK_END_AND_RETURN(start,end,session);



	return ret;
}
static int rrr_mqtt_p_parser_connack (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_publish (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_puback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubrec (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubrel (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pubcomp (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_subscribe (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_suback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_unsubscribe (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_unsuback (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pingreq (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_pingresp (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_disconnect (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_parser_auth (RRR_MQTT_PACKET_TYPE_PARSER_DEFINITION) {
	int ret = 0;
	return ret;
}

static const struct rrr_mqtt_p_type_parser_properties  parser_properties[] = {
	{1, 0, NULL},
	{1, 0, rrr_mqtt_p_parser_connect},
	{1, 0, rrr_mqtt_p_parser_connack},
	{0, 0, rrr_mqtt_p_parser_publish},
	{1, 0, rrr_mqtt_p_parser_puback},
	{1, 0, rrr_mqtt_p_parser_pubrec},
	{1, 2, rrr_mqtt_p_parser_pubrel},
	{1, 0, rrr_mqtt_p_parser_pubcomp},
	{1, 2, rrr_mqtt_p_parser_subscribe},
	{1, 0, rrr_mqtt_p_parser_suback},
	{1, 2, rrr_mqtt_p_parser_unsubscribe},
	{1, 0, rrr_mqtt_p_parser_unsuback},
	{1, 0, rrr_mqtt_p_parser_pingreq},
	{1, 0, rrr_mqtt_p_parser_pingresp},
	{1, 0, rrr_mqtt_p_parser_disconnect},
	{1, 0, rrr_mqtt_p_parser_auth}
};

int rrr_mqtt_packet_parse (
		struct rrr_mqtt_p_parse_session *session
) {
	int ret = 0;

	/*
	 * We might return 0 on error if the error is data-related and it's
	 * the client's fault. In that case, we only set the error status flag.
	 * On other horrendous errors, we return 1.
	 */

	if (session->buf == NULL) {
		VL_BUG("buf was NULL in rrr_mqtt_packet_parse\n");
	}
	if (RRR_MQTT_P_PARSE_IS_ERR(session)) {
		VL_BUG("rrr_mqtt_packet_parse called with error flag set, connection should have been closed.\n");
	}
	if (RRR_MQTT_P_PARSE_IS_COMPLETE(session)) {
		VL_BUG("rrr_mqtt_packet_parse called while parsing was complete\n");
	}

	if (session->buf_size < 2) {
		goto out;
	}

	if (!RRR_MQTT_P_PARSE_FIXED_HEADER_IS_DONE(session)) {
		const struct rrr_mqtt_p_header *header = (const struct rrr_mqtt_p_header *) session->buf;

		if (RRR_MQTT_P_GET_TYPE(header) == 0) {
			VL_MSG_ERR("Received 0 header type in rrr_mqtt_packet_parse\n");
			RRR_MQTT_P_PARSE_STATUS_SET_ERR(session);
			goto out;
		}

		const struct rrr_mqtt_p_type_parser_properties *properties = &parser_properties[RRR_MQTT_P_GET_TYPE(header)];

		printf ("Received mqtt packet of type %u name %s\n",
				RRR_MQTT_P_GET_TYPE(header), RRR_MQTT_P_GET_TYPE_NAME(header));

		if (properties->has_reserved_flags != 0 && RRR_MQTT_P_GET_TYPE_FLAGS(header) != properties->flags) {
			VL_MSG_ERR("Invalid reserved flags %u received in mqtt packet of type %s\n",
					RRR_MQTT_P_GET_TYPE_FLAGS(header),
					RRR_MQTT_P_GET_TYPE_NAME(header)
			);
			RRR_MQTT_P_PARSE_STATUS_SET_ERR(session);
			goto out;
		}

		uint32_t remaining_length = 0;
		ssize_t bytes_parsed = 0;
		if ((ret = __rrr_mqtt_packet_parse_variable_int (
				&remaining_length,
				&bytes_parsed,
				header->length,
				session->buf_size - sizeof(header->type))
		) != 0) {
			if (ret == RRR_MQTT_PACKET_PARSE_INCOMPLETE) {
				/* Not enough bytes were read */
				ret = 0;
				goto out;
			}
			else {
				VL_MSG_ERR("Parse error in packet fixed header remaining length of type %s\n",
						RRR_MQTT_P_GET_TYPE_NAME(header));
				RRR_MQTT_P_PARSE_STATUS_SET_ERR(session);
				goto out;
			}
		}

		session->variable_header_pos = sizeof(header->type) + bytes_parsed;
		session->target_size = sizeof(header->type) + bytes_parsed + remaining_length;
		session->type = RRR_MQTT_P_GET_TYPE(header);
		session->type_flags = RRR_MQTT_P_GET_TYPE_FLAGS(header);

		printf ("parsed a packet fixed header of type %s\n",
				RRR_MQTT_P_GET_TYPE_NAME(header));

		RRR_MQTT_P_PARSE_STATUS_SET(session,RRR_MQTT_P_PARSE_STATUS_FIXED_HEADER_DONE);
	}

	if ((ret = parser_properties[session->type].parser(session)) != RRR_MQTT_PACKET_PARSE_OK) {
		if (ret == RRR_MQTT_PACKET_PARSE_INCOMPLETE) {
			/* Not enough bytes were read */
			ret = 0;
			goto out;
		}
		else {
			VL_MSG_ERR("Error from mqtt parse function of type %s\n",
					RRR_MQTT_P_GET_TYPE_NAME_RAW(session->type));
			ret = 1;
			goto out;
		}
	}

	/* Type parser might haver set error flag */
	if (RRR_MQTT_P_PARSE_IS_ERR(session)) {
		goto out;
	}

	out:
	if (ret != 0) {
		RRR_MQTT_P_PARSE_STATUS_SET(session,RRR_MQTT_P_PARSE_STATUS_ERR);
	}
	return ret;
}

int rrr_mqtt_packet_parse_finalize (
		struct rrr_mqtt_packet_internal **packet,
		struct rrr_mqtt_p_parse_session *session
) {
	int ret = 0;

	*packet = NULL;

	// TODO : Finalize packet

	rrr_mqtt_packet_parse_session_destroy(session);

	return ret;
}
