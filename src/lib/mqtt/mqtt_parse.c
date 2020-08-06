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

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <util/utf8.h>

#include "../log.h"

#include "mqtt_packet.h"
#include "mqtt_parse.h"
#include "mqtt_property.h"
#include "mqtt_subscription.h"
#include "mqtt_topic.h"
#include "mqtt_common.h"

#include "../util/rrr_endian.h"
#include "../util/macro_utils.h"

struct parse_state {
	int ret;
	const char *start;
	const char *end;
	ssize_t bytes_parsed;
	uint16_t blob_length;
	ssize_t payload_length;
};

#define PARSE_CHECK_END_RAW(end,final_end)										\
	((end) > (final_end))

#define PARSE_CHECK_END_AND_RETURN_RAW(end,final_end)							\
	do { if (PARSE_CHECK_END_RAW(end, final_end)) {								\
		return RRR_MQTT_INCOMPLETE;												\
	}} while (0)

#define PARSE_CHECK_TARGET_END()												\
	PARSE_CHECK_END_RAW((parse_state->end)+1,(session)->buf+(session)->target_size)

#define PARSE_CHECK_END_AND_RETURN(end,session)									\
	PARSE_CHECK_END_AND_RETURN_RAW((end),(session)->buf+(session)->buf_wpos)

#define PARSE_INIT(type)																\
	struct parse_state parse_state_static = {											\
			RRR_MQTT_OK,																\
			NULL,																		\
			NULL,																		\
			0,																			\
			0,																			\
			0																			\
	};																					\
	struct parse_state *parse_state = &parse_state_static;								\
	struct RRR_PASTE(rrr_mqtt_p_,type) *type = NULL

#define PARSE_BEGIN(type)																\
	if (RRR_MQTT_PARSE_STATUS_PAYLOAD_IS_DONE(session)) {								\
		RRR_BUG("rrr_mqtt_parse called for same packet again after payload was done\n");\
	}																					\
	if (RRR_MQTT_PARSE_VARIABLE_HEADER_IS_DONE(session)) {								\
		goto parse_payload;																\
	}																					\
	parse_state->start = parse_state->end = session->buf + session->variable_header_pos

#define PARSE_REQUIRE_PROTOCOL_VERSION()												\
	if (session->protocol_version == NULL) {											\
		return RRR_MQTT_INCOMPLETE;														\
	}

#define PARSE_ALLOCATE(type)															\
	if (session->packet == NULL) {														\
		session->packet = session->type_properties->allocate (							\
			session->type_properties,													\
			session->protocol_version													\
		);																				\
		if (session->packet == NULL) {													\
			RRR_MSG_0("Could not allocate packet of type %s while parsing\n",			\
				session->type_properties->name);										\
			return RRR_MQTT_INTERNAL_ERROR;												\
		}																				\
	}																					\
	type = (struct RRR_PASTE(rrr_mqtt_p_,type) *) session->packet; (void)(type)

#define PARSE_PACKET_ID(target) 											\
	do {parse_state->start = parse_state->end;								\
	parse_state->end = parse_state->start + 2;								\
	PARSE_CHECK_END_AND_RETURN(parse_state->end,session);					\
	(target)->packet_identifier = rrr_be16toh(*((uint16_t *) parse_state->start));\
	if ((target)->packet_identifier == 0) {									\
		RRR_MSG_0("Packet ID was zero while parsing packet of type %s\n",	\
			session->type_properties->name);								\
		return RRR_MQTT_SOFT_ERROR;											\
	}} while(0)																\


#define PARSE_PREPARE_RAW(start,end,bytes)			\
		(start) = (end);							\
		(end) = (start) + (bytes);					\
		PARSE_CHECK_END_AND_RETURN(end,session)

#define PARSE_PREPARE(bytes)						\
	PARSE_PREPARE_RAW(parse_state->start,parse_state->end,bytes)

#define PARSE_U8_RAW(start,end,target)				\
	PARSE_PREPARE_RAW(start,end,1);					\
	(target) = *((uint8_t*) (start));

#define PARSE_U16_RAW(start,end,target)				\
	PARSE_PREPARE_RAW(start,end,2);					\
	(target) = rrr_be16toh(*((uint16_t*) (start)));

#define PARSE_U8(type,target)						\
	PARSE_U8_RAW(parse_state->start,parse_state->end,(type)->target)

#define PARSE_U16(type,target)						\
	PARSE_U16_RAW(parse_state->start,parse_state->end,(type)->target)

#define PARSE_CHECK_V5(type)						\
	((type)->protocol_version->id >= RRR_MQTT_VERSION_5)

static int __rrr_mqtt_parse_save_and_check_reason (struct rrr_mqtt_p *packet, uint8_t reason_v31_or_v5) {
	int ret = RRR_MQTT_OK;

	const struct rrr_mqtt_p_reason *reason = NULL;
	if (PARSE_CHECK_V5(packet)) {
		reason = rrr_mqtt_p_reason_get_v5 (reason_v31_or_v5);
		if (reason == NULL) {
			RRR_MSG_0("Unknown v5 reason %u in %s message\n",
				reason_v31_or_v5, RRR_MQTT_P_GET_TYPE_NAME(packet));
			return RRR_MQTT_SOFT_ERROR;
		}
	}
	else {
		reason = rrr_mqtt_p_reason_get_v31 (reason_v31_or_v5);
		if (reason == NULL) {
			RRR_MSG_0("Unknown v3.1 reason %u in %s message\n",
				reason_v31_or_v5, RRR_MQTT_P_GET_TYPE_NAME(packet));
			return RRR_MQTT_SOFT_ERROR;
		}
	}
	packet->reason = reason;
	packet->reason_v5 = reason->v5_reason;

	return ret;
}

#define PARSE_SAVE_AND_CHECK_REASON_STRUCT(packet,class,reason_v31_or_v5) do {	\
	if (__rrr_mqtt_parse_save_and_check_reason (								\
		(struct rrr_mqtt_p *) packet,											\
		reason_v31_or_v5														\
	) != RRR_MQTT_OK) {															\
		return RRR_MQTT_SOFT_ERROR;												\
	}																			\
	if (packet->reason->RRR_PASTE(for_,class) == 0) {							\
			RRR_MSG_0("Reason %u->%u '%s' is invalid for %s message\n",			\
					reason_v31_or_v5, packet->reason->v5_reason,				\
					packet->reason->description,								\
				RRR_MQTT_P_GET_TYPE_NAME(packet));								\
		return RRR_MQTT_SOFT_ERROR;												\
	}} while(0)

#define PARSE_VALIDATE_QOS(qos)													\
	if ((qos) > 2) {															\
		RRR_MSG_0("Invalid QoS flags %u in %s packet\n",						\
			(qos), RRR_MQTT_P_GET_TYPE_NAME(session->packet));					\
		return RRR_MQTT_SOFT_ERROR;												\
	}

#define PARSE_VALIDATE_RETAIN(retain)											\
	if ((retain) > 2) {															\
		RRR_MSG_0("Invalid retain flags %u in %s packet\n",						\
			(retain), RRR_MQTT_P_GET_TYPE_NAME(session->packet));				\
		return RRR_MQTT_SOFT_ERROR;												\
	}

#define PARSE_VALIDATE_RESERVED(reserved, value)								\
	if ((reserved) != value) {													\
		RRR_MSG_0("Invalid reserved flags %u in %s packet, must be %u\n",		\
			(reserved), RRR_MQTT_P_GET_TYPE_NAME(session->packet), (value));	\
		return RRR_MQTT_SOFT_ERROR;												\
	}

#define PARSE_VALIDATE_ZERO_RESERVED(reserved)									\
		PARSE_VALIDATE_RESERVED(reserved, 0)

#define PARSE_PROPERTIES_IF_V5(type,target)														\
	do {if (PARSE_CHECK_V5(type)) {																\
		parse_state->start = parse_state->end;													\
		parse_state->ret = __rrr_mqtt_parse_properties(&(type)->target, session, parse_state->start, &(parse_state->bytes_parsed));\
		if (parse_state->ret != 0) {															\
			if (parse_state->ret != RRR_MQTT_INCOMPLETE) {										\
				RRR_MSG_0("Error while parsing properties of MQTT packet of type %s\n",			\
					RRR_MQTT_P_GET_TYPE_NAME(type));											\
			}																					\
			return parse_state->ret;															\
		}																						\
		parse_state->end = parse_state->start + parse_state->bytes_parsed;						\
	}} while (0)

#define PARSE_UTF8(type,target,min_length,field_name)											\
	parse_state->start = parse_state->end;														\
	RRR_FREE_IF_NOT_NULL(type->target);															\
	if ((parse_state->ret = __rrr_mqtt_parse_utf8 (												\
			&type->target,																		\
			parse_state->start,																	\
			session->buf + session->buf_wpos,													\
			&(parse_state->bytes_parsed),														\
			min_length																			\
	)) != 0) {																					\
		if (parse_state->ret != RRR_MQTT_INCOMPLETE) {											\
			RRR_MSG_0(	"Error while parsing UTF8 of MQTT message of type %s "					\
						"in field '" RRR_QUOTE(field_name) "'\n",								\
					RRR_MQTT_P_GET_TYPE_NAME(type));											\
		}																						\
		return parse_state->ret;																\
	}																							\
	parse_state->end = parse_state->start + parse_state->bytes_parsed

#define PARSE_BLOB(type,target)																	\
	parse_state->start = parse_state->end;														\
	RRR_FREE_IF_NOT_NULL(type->target);															\
	if ((parse_state->ret = __rrr_mqtt_parse_blob (												\
			&type->target,																		\
			parse_state->start,																	\
			session->buf + session->buf_wpos,													\
			&(parse_state->bytes_parsed),														\
			&(parse_state->blob_length)															\
	)) != 0) {																					\
		if (parse_state->ret != RRR_MQTT_INCOMPLETE) {											\
			RRR_MSG_0("Error while parsing blob of MQTT message of type %s\n",					\
					RRR_MQTT_P_GET_TYPE_NAME(type));											\
		}																						\
		return parse_state->ret;																\
	}																							\
	parse_state->end = parse_state->start + parse_state->bytes_parsed

#define PARSE_VARIABLE_INT_RAW(target)															\
	start = end;																				\
	if ((ret = __rrr_mqtt_parse_variable_int (													\
			&target,																			\
			start,																				\
			session->buf + session->buf_wpos,													\
			&bytes_parsed																		\
	)) != 0) {																					\
		if (ret != RRR_MQTT_OK && ret != RRR_MQTT_INCOMPLETE) {									\
			RRR_MSG_0("Error while parsing VINT return was %i\n", ret);							\
		}																						\
		return ret;																				\
	}																							\
	end = start + bytes_parsed

#define PARSE_PREV_PARSED_BYTES() \
	(parse_state->bytes_parsed)

#define PARSE_CHECK_ZERO_PAYLOAD()																\
	do {parse_state->payload_length = session->target_size - session->payload_pos;				\
	if (parse_state->payload_length < 0) {														\
		RRR_BUG("Payload length was < 0 while parsing\n");										\
	}																							\
	if (parse_state->payload_length == 0) {														\
		goto parse_done;																		\
	}} while(0)

#define PARSE_GET_PAYLOAD_SIZE()																\
	(parse_state->payload_length = session->target_size - session->payload_pos)

#define PARSE_CHECK_NO_MORE_DATA()																\
	do {if (PARSE_CHECK_TARGET_END()) {															\
		goto header_complete;																	\
	}} while (0)

#define PARSE_PAYLOAD_SAVE_CHECKPOINT()															\
	session->payload_checkpoint = parse_state->end - session->buf

#define PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(type)										\
	goto header_complete;																		\
	header_complete:																			\
	RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_VARIABLE_HEADER_DONE);				\
	PARSE_PAYLOAD_SAVE_CHECKPOINT();															\
	session->payload_pos = parse_state->end - session->buf;										\
	goto parse_payload;																			\
	parse_payload:																				\
	type = (struct RRR_PASTE(rrr_mqtt_p_,type) *) session->packet;								\
	parse_state->end = session->buf + session->payload_checkpoint

#define PARSE_END_PAYLOAD()																		\
	goto parse_done;																			\
	parse_done:																					\
	RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_PAYLOAD_DONE);						\
	RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_VARIABLE_HEADER_DONE);				\
	return parse_state->ret

#define PARSE_END_NO_HEADER(type)																	\
	if (!PARSE_CHECK_TARGET_END()) {																\
		RRR_MSG_0("Data after fixed header in mqtt packet type %s which has no variable header\n",	\
				session->type_properties->name);													\
	}																								\
	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(type);												\
	PARSE_END_PAYLOAD()


void rrr_mqtt_parse_session_destroy (
		struct rrr_mqtt_parse_session *session
) {
	if (session->buf == NULL) {
		return;
	}

	if (session->packet != NULL) {
//		printf ("Packet refcount in rrr_mqtt_parse_session_destroy: %i\n", rrr_mqtt_p_get_refcount(session->packet));
		RRR_MQTT_P_DECREF(session->packet);
		session->packet = NULL;
	}
}

void rrr_mqtt_parse_session_init (
		struct rrr_mqtt_parse_session *session
) {
	memset(session, '\0', sizeof(*session));
}

void rrr_mqtt_parse_session_update (
		struct rrr_mqtt_parse_session *session,
		const char *buf,
		ssize_t buf_wpos,
		const struct rrr_mqtt_p_protocol_version *protocol_version
) {
	session->buf = buf;
	session->buf_wpos = buf_wpos;

	// May be NULL before CONNECT packet has been received or sent
	session->protocol_version = protocol_version;
}

static int __rrr_mqtt_parse_variable_int (uint32_t *target, const char *start, const char *final_end, ssize_t *bytes_parsed) {
	ssize_t pos = 0;
	uint32_t result = 0;
	uint32_t exponent = 1;
	uint8_t carry = 1;

	*target = 0;
	*bytes_parsed = 0;

	const char *end = start;

	while (carry) {
		if (pos > 3) {
			/* Only four bytes allowed */
			RRR_MSG_0("Carry of last byte was one while parsing VINT\n");
			return RRR_MQTT_SOFT_ERROR;
		}

		end++;
		PARSE_CHECK_END_AND_RETURN_RAW(end, final_end);

		uint8_t current = *((uint8_t*) start + pos);

		uint8_t value = current & 0x7f;
		carry = current & 0x80;

		result += (value * exponent);

		exponent *= 128;
		pos++;
	}

	*target = result;
	*bytes_parsed = pos;

	return RRR_MQTT_OK;
}

static int __rrr_mqtt_parse_blob (
		char **target, const char *start, const char *final_end, ssize_t *bytes_parsed, uint16_t *blob_length
) {
	if (*target != NULL) {
		RRR_BUG ("target was not NULL in __rrr_mqtt_parse_blob\n");
	}

	const char *end = start + 2;
	*bytes_parsed = 2;

	PARSE_CHECK_END_AND_RETURN_RAW(end,final_end);
	*blob_length = rrr_be16toh(*((uint16_t *) start));

	*target = malloc((*blob_length) + 1);
	if (*target == NULL){
		RRR_MSG_0("Could not allocate memory for UTF8 in __rrr_mqtt_parse_utf8\n");
		return RRR_MQTT_INTERNAL_ERROR;
	}
	**target = '\0';

	start = end;
	end = start + *blob_length;
/*	{
		char buf_debug[(*blob_length) + 1];
		int length_available = final_end - start;
		if (length_available > 0) {
			int length_print = *blob_length > length_available ? length_available : *blob_length;
			memcpy(buf_debug, start, length_print);
			buf_debug[length_print] = '\0';
			printf ("blob string: %s\n", buf_debug);
		}
	}*/
	PARSE_CHECK_END_AND_RETURN_RAW(end,final_end);

	memcpy(*target, start, *blob_length);
	(*target)[*blob_length] = '\0';

	*bytes_parsed += *blob_length;

	return RRR_MQTT_OK;
}

struct parse_utf8_validate_callback_data {
	uint32_t character;
	int has_illegal_character;
};

static int __rrr_mqtt_parse_utf8_validate_callback (uint32_t character, void *arg) {
	struct parse_utf8_validate_callback_data *data = arg;
	if (character == 0 || (character >= 0xD800 && character <= 0xDFFF)) {
		data->has_illegal_character = 1;
		data->character = character;
		return 1;
	}
	return 0;
}

static int __rrr_mqtt_parse_utf8 (
		char **target, const char *start, const char *final_end, ssize_t *bytes_parsed, uint16_t minimum_length
) {
	uint16_t utf8_length = 0;
	int ret = __rrr_mqtt_parse_blob(target, start, final_end, bytes_parsed, &utf8_length);
	if (ret != RRR_MQTT_OK) {
		return ret;
	}

	if (utf8_length < minimum_length) {
		RRR_MSG_0("Too short UTF-8 string encountered (%u<%u)\n", utf8_length, minimum_length);
		return RRR_MQTT_SOFT_ERROR;
	}

	struct parse_utf8_validate_callback_data callback_data = {0, 0};
	if (rrr_utf8_validate_and_iterate(*target, utf8_length, __rrr_mqtt_parse_utf8_validate_callback, &callback_data) != 0) {
		RRR_MSG_0 ("Malformed UTF-8 detected in UTF8-data\n");
		if (callback_data.has_illegal_character == 1){
			RRR_MSG_0("Illegal character 0x%04x\n", callback_data.character);
		}
		return RRR_MQTT_SOFT_ERROR;
	}

	return RRR_MQTT_OK;
}

#define RRR_PROPERTY_PARSER_DEFINITION \
		struct rrr_mqtt_property *target, struct rrr_mqtt_parse_session *session, \
		const char *start, ssize_t *bytes_parsed_final

static int __rrr_mqtt_parse_property_integer (struct rrr_mqtt_property *target, const char *start, ssize_t length) {
	int ret = RRR_MQTT_OK;

	if (length > 4) {
		RRR_BUG("Too many bytes in __rrr_mqtt_property_parse_integer\n");
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

	int_merged.result = rrr_be32toh(int_merged.result);

	if ((ret = rrr_mqtt_property_save_uint32(target, int_merged.result)) != 0) {
		return ret;
	}

	target->length_orig = length;

	return ret;
}

static int __rrr_mqtt_parse_property_one (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_OK;

	PARSE_CHECK_END_AND_RETURN(start + 1,session);

	ret = __rrr_mqtt_parse_property_integer(target, start, 1);
	if (ret != RRR_MQTT_OK) {
		return ret;
	}

	*bytes_parsed_final = 1;

	return ret;
}

static int __rrr_mqtt_parse_property_two (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_OK;

	PARSE_CHECK_END_AND_RETURN(start + 2,session);

	ret = __rrr_mqtt_parse_property_integer(target, start, 2);
	if (ret != RRR_MQTT_OK) {
		return ret;
	}

	*bytes_parsed_final = 2;

	return ret;
}

static int __rrr_mqtt_parse_property_four (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_OK;

	PARSE_CHECK_END_AND_RETURN(start + 4,session);

	ret = __rrr_mqtt_parse_property_integer(target, start, 4);
	if (ret != RRR_MQTT_OK) {
		return ret;
	}

	*bytes_parsed_final = 4;

	return ret;
}

static int __rrr_mqtt_parse_property_vint (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_OK;

	uint32_t result = 0;

	ret = __rrr_mqtt_parse_variable_int(&result, start, session->buf_wpos + session->buf, bytes_parsed_final);
	if (ret != RRR_MQTT_OK) {
		return ret;
	}

	if ((ret = rrr_mqtt_property_save_uint32(target, result)) != 0) {
		return ret;
	}

	return ret;
}

static int __rrr_mqtt_parse_property_blob (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = RRR_MQTT_OK;

	uint16_t blob_length = 0;
	ssize_t bytes_parsed = 0;

	if ((ret = __rrr_mqtt_parse_blob(&target->data, start, session->buf + session->buf_wpos, &bytes_parsed, &blob_length)) != 0) {
		return ret;
	}


	target->length = blob_length;
	target->length_orig = blob_length;
	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB;

	bytes_parsed += blob_length;

	*bytes_parsed_final = bytes_parsed;

	return ret;
}

static int __rrr_mqtt_parse_property_utf8 (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = 0;

	ret = __rrr_mqtt_parse_utf8 (&target->data, start, session->buf + session->buf_wpos, bytes_parsed_final, 0);

	target->length = target->length_orig = (*bytes_parsed_final) - sizeof(uint16_t);
	target->internal_data_type = RRR_MQTT_PROPERTY_DATA_TYPE_INTERNAL_BLOB;

	return ret;
}

static int __rrr_mqtt_parse_property_2utf8 (RRR_PROPERTY_PARSER_DEFINITION) {
	int ret = 0;

	ssize_t bytes_parsed = 0;
	*bytes_parsed_final = 0;

	if ((ret = rrr_mqtt_property_new(&target->sibling, target->definition)) != 0) {
		return ret;
	}

	if ((ret = __rrr_mqtt_parse_property_utf8 (target, session, start, &bytes_parsed)) != 0) {
		return ret;
	}

	*bytes_parsed_final += bytes_parsed;

	start = start + bytes_parsed;
	if ((ret = __rrr_mqtt_parse_property_utf8 (target->sibling, session, start, &bytes_parsed)) != 0) {
		return ret;
	}

	*bytes_parsed_final += bytes_parsed;

	return ret;
}

static int (* const property_parsers[]) (RRR_PROPERTY_PARSER_DEFINITION) = {
		NULL,
		__rrr_mqtt_parse_property_one,
		__rrr_mqtt_parse_property_two,
		NULL,
		__rrr_mqtt_parse_property_four,
		__rrr_mqtt_parse_property_vint,
		__rrr_mqtt_parse_property_blob,
		__rrr_mqtt_parse_property_utf8,
		__rrr_mqtt_parse_property_2utf8
};

static int __rrr_mqtt_parse_properties (
		struct rrr_mqtt_property_collection *target,
		struct rrr_mqtt_parse_session *session,
		const char *start,
		ssize_t *bytes_parsed_final
) {
	int ret = 0;
	const char *end = start;

	*bytes_parsed_final = 0;

	uint32_t property_length = 0;
	ssize_t bytes_parsed = 0;

	rrr_mqtt_property_collection_clear(target);

	const char *properties_length_start = start;

	PARSE_VARIABLE_INT_RAW(property_length);

	if (ret != RRR_MQTT_OK) {
		RRR_MSG_0("Error while parsing property length variable int\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	start = end;
	const char *properties_body_start = start;
	const char *properties_body_end = properties_body_start + property_length;

	while (end < properties_body_end) {
		uint8_t type;
		PARSE_U8_RAW(start,end,type);

		const struct rrr_mqtt_property_definition *property_def = rrr_mqtt_property_get_definition(type);
		if (property_def == NULL) {
			RRR_MSG_0("Unknown mqtt property field found: 0x%02x\n", type);
			return RRR_MQTT_SOFT_ERROR;
		}

		struct rrr_mqtt_property *property = NULL;
		if ((ret = rrr_mqtt_property_new(&property, property_def)) != 0) {
			return RRR_MQTT_INTERNAL_ERROR;
		}

		start = end;
		ret = property_parsers[property_def->internal_data_type](property, session, start, &bytes_parsed);
		if (ret != 0) {
			rrr_mqtt_property_destroy(property);
			return ret;
		}
		end = start + bytes_parsed;

		rrr_mqtt_property_collection_add (target, property);
	}

	*bytes_parsed_final = end - properties_length_start;

	return ret;
}

static int __rrr_mqtt_parse_protocol_version_validate_name (
		const struct rrr_mqtt_p_protocol_version *protocol_version,
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

int rrr_mqtt_parse_connect (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(connect);
	PARSE_BEGIN(connect);

	PARSE_PREPARE(2);
	uint16_t protocol_name_length = rrr_be16toh(*((uint16_t *) parse_state->start));

	if (protocol_name_length > 6) {
		RRR_MSG_0("Protocol name in connect packet was too long\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	PARSE_PREPARE(protocol_name_length);

	char name_buf[7];
	strncpy(name_buf, parse_state->start, protocol_name_length);
	name_buf[protocol_name_length] = '\0';

	PARSE_PREPARE(1);
	uint8_t protocol_version_id = *((uint8_t *) parse_state->start);

	const struct rrr_mqtt_p_protocol_version *protocol_version = rrr_mqtt_p_get_protocol_version(protocol_version_id);
	if (protocol_version == NULL) {
		RRR_MSG_0("MQTT protocol version could not be found, input name was '%s' version was '%u'\n",
				name_buf, protocol_version_id);
		return RRR_MQTT_SOFT_ERROR;
	}

	if (__rrr_mqtt_parse_protocol_version_validate_name(protocol_version, name_buf) != 0) {
		RRR_MSG_0("MQTT protocol version name mismatch, input name was '%s' version was '%u'. Expected name '%s'\n",
				name_buf, protocol_version_id, protocol_version->name);
		return RRR_MQTT_SOFT_ERROR;
	}

	session->protocol_version = protocol_version;

	PARSE_ALLOCATE(connect);

	// CONNECT FLAGS
	PARSE_U8(connect,connect_flags);

	PARSE_VALIDATE_ZERO_RESERVED(RRR_MQTT_P_CONNECT_GET_FLAG_RESERVED(connect));

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL(connect) == 0) {
		if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(connect) != 0 || RRR_MQTT_P_CONNECT_GET_FLAG_WILL_RETAIN(connect) != 0) {
			RRR_MSG_0("WILL flag of mqtt connect packet was zero, but not WILL_QOS and WILL_RETAIN\n");
			return RRR_MQTT_SOFT_ERROR;
		}
	}

	if (connect->protocol_version->id < RRR_MQTT_VERSION_5) {
		if (RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(connect) == 1 && RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(connect) == 0) {
			RRR_MSG_0("Password flag was set in mqtt connect packet but not username flag. Not allowed for protocol version <5\n");
			return RRR_MQTT_SOFT_ERROR;
		}
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL_QOS(connect) > 2) {
		RRR_MSG_0("Received CONNECT with QoS >2\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	PARSE_U16(connect,keep_alive);
	PARSE_PROPERTIES_IF_V5(connect,properties);

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(connect);

	// May be zero bytes
	PARSE_UTF8(connect,client_identifier,0,client identifier);

	if (RRR_MQTT_P_CONNECT_GET_FLAG_WILL(connect) != 0) {
		PARSE_PROPERTIES_IF_V5(connect,will_properties);
		PARSE_UTF8(connect,will_topic,1,will topic);
		if (rrr_mqtt_topic_validate_name(connect->will_topic) != 0) {
			RRR_MSG_0("Invalid will topic name '%s' in received CONNECT packet\n",
					connect->will_topic);
			return RRR_MQTT_SOFT_ERROR;
		}
		PARSE_BLOB(connect,will_message);
		connect->will_message_size = parse_state->blob_length;
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_USER_NAME(connect) != 0) {
		if (PARSE_CHECK_TARGET_END()) {
			RRR_MSG_0("Username field missing in CONNECT, packet was too short\n");
			return RRR_MQTT_SOFT_ERROR;
		}
		PARSE_UTF8(connect,username,1,username);
	}

	if (RRR_MQTT_P_CONNECT_GET_FLAG_PASSWORD(connect) != 0) {
		if (PARSE_CHECK_TARGET_END()) {
			RRR_MSG_0("Password field missing in CONNECT, packet was too short\n");
			return RRR_MQTT_SOFT_ERROR;
		}
		PARSE_UTF8(connect,password,1,password);
	}

	PARSE_END_PAYLOAD();
 }

int rrr_mqtt_parse_connack (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(connack);
	PARSE_BEGIN(connack);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(connack);

	PARSE_U8(connack,ack_flags);

	connack->session_present = RRR_MQTT_P_CONNACK_GET_FLAG_SESSION_PRESENT(connack);

	if (RRR_MQTT_P_CONNACK_GET_FLAG_RESERVED(connack) != 0) {
		RRR_MSG_0("Reserved flags in CONNACK packet was not 0 but %u\n",
				RRR_MQTT_P_CONNACK_GET_FLAG_RESERVED(connack));
		return RRR_MQTT_SOFT_ERROR;
	}

	uint8_t reason_tmp;
	PARSE_U8_RAW(parse_state->start,parse_state->end,reason_tmp);

	PARSE_SAVE_AND_CHECK_REASON_STRUCT(connack,connack,reason_tmp);

	PARSE_PROPERTIES_IF_V5(connack,properties);

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(connack);
	PARSE_END_PAYLOAD();
}

int rrr_mqtt_parse_publish (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(publish);
	PARSE_BEGIN(publish);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(publish);

	publish->type_flags = session->type_flags;

	// Note : The separate dup variable overrides the value in type_flags. When
	//        the publish is assembled, the type_flag is modified to match the
	//        stored dup variable.
	publish->dup = RRR_MQTT_P_PUBLISH_GET_FLAG_DUP(session);

	RRR_DBG_3("PUBLISH flags (%u): DUP: %u, QOS: %u, RET: %u\n",
			session->packet->type_flags,
			publish->dup,
			RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish),
			RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish)
	);

	PARSE_VALIDATE_QOS(RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish));

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 0 && publish->dup != 0) {
		RRR_MSG_0("Received a PUBLISH packet of QoS 0, but DUP was non zero\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	// PARSE TOPIC
	PARSE_UTF8(publish,topic,1,topic);

	if (rrr_mqtt_topic_validate_name(publish->topic) != 0) {
		RRR_MSG_0("Invalid topic name '%s' in received PUBLISH packet, it will be rejected\n",
				publish->topic);
		return RRR_MQTT_SOFT_ERROR;
	}

	// If previous parse was incomplete, free the tree
	rrr_mqtt_topic_token_destroy(publish->token_tree_);
	if (rrr_mqtt_topic_tokenize(&publish->token_tree_, publish->topic) != 0) {
		RRR_MSG_0("Could not create topic token tree in rrr_mqtt_parse_publish\n");
		return RRR_MQTT_INTERNAL_ERROR;
	}

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) > 0) {
		PARSE_PACKET_ID(publish);
	}

	PARSE_PROPERTIES_IF_V5(publish,properties);

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(publish);

	PARSE_CHECK_ZERO_PAYLOAD();

	// TODO : Implement maximum size of payload. We still however require a client to actually
	//        send the data before we allocate huge amounts of memory

	// The memory of a large payload is continiously being read in. We don't do anything until the
	// complete packet has been read, after which we order the read data to be moved to the
	// assembled_data-member of the packet. Memory will after that be managed by the packet.

	// The rest is handled as overshoot by net transport
	if (session->buf_wpos >= session->target_size) {
		RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_MOVE_PAYLOAD_TO_PACKET);
		goto parse_done;
	}

	return RRR_MQTT_INCOMPLETE;

	PARSE_END_PAYLOAD();
}

// Parse PUBACK, PUBREC, PUBREL, PUBCOMP
int rrr_mqtt_parse_def_puback (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(def_puback);
	PARSE_BEGIN(def_puback);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(def_puback);
	PARSE_PACKET_ID(def_puback);
	PARSE_CHECK_NO_MORE_DATA();

	if (PARSE_CHECK_V5(def_puback)) {
		PARSE_U8(def_puback,reason_v5);

		if (RRR_MQTT_P_GET_TYPE(def_puback) == RRR_MQTT_P_TYPE_PUBACK ||
			RRR_MQTT_P_GET_TYPE(def_puback) == RRR_MQTT_P_TYPE_PUBREC
		) {
			PARSE_SAVE_AND_CHECK_REASON_STRUCT(def_puback,puback_pubrec,def_puback->reason_v5);
		}
		else if (RRR_MQTT_P_GET_TYPE(def_puback) == RRR_MQTT_P_TYPE_PUBREL ||
				RRR_MQTT_P_GET_TYPE(def_puback) == RRR_MQTT_P_TYPE_PUBCOMP
		) {
			PARSE_SAVE_AND_CHECK_REASON_STRUCT(def_puback,pubrel_pubcomp,def_puback->reason_v5);
		}
		else {
			RRR_BUG("Unknown packet type %u in rrr_mqtt_parse_def_puback\n",
					RRR_MQTT_P_GET_TYPE(def_puback));
		}

		PARSE_PROPERTIES_IF_V5(def_puback,properties);
	}

	if (!PARSE_CHECK_TARGET_END()) {
		RRR_MSG_0("Received %s which was too long\n", session->type_properties->name);
		return RRR_MQTT_SOFT_ERROR;
	}

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(def_puback);
	PARSE_END_PAYLOAD();
}

static int __rrr_mqtt_parse_subscribe_unsubscribe (
		struct rrr_mqtt_parse_session *session,
		struct parse_state *parse_state,
		struct rrr_mqtt_p_sub_usub *sub_usub,
		int has_topic_options // For SUBSCRIBE packet
) {
	PARSE_BEGIN(sub_usub);

	PARSE_PACKET_ID(sub_usub);
	PARSE_PROPERTIES_IF_V5(sub_usub,properties);

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(sub_usub);

	if (PARSE_CHECK_TARGET_END()) {
		RRR_MSG_0("Received SUBSCRIBE/UNSUBSCRIBE with zero payload\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	/* If we need several attempts to parse the SUBSCRIBE-packet, the subscriptions parsed in the
	 * previous rounds are parsed again and overwritten. We do however skip to our payload position
	 * checkpoint to avoid doing this with all of the subscriptions, only at most one should actually
	 * be overwritten. */
	while (!PARSE_CHECK_TARGET_END()) {
		PARSE_UTF8(sub_usub,data_tmp,1,topic);

		if (PARSE_PREV_PARSED_BYTES() == 0) {
			RRR_MSG_0("Received SUBSCRIBE/UNSUBSCRIBE with zero-length topic\n");
			return RRR_MQTT_SOFT_ERROR;
		}

		uint8_t subscription_flags = 0;
		uint8_t reserved = 0;
		uint8_t retain = 0;
		uint8_t rap = 0;
		uint8_t nl = 0;
		uint8_t qos = 0;

		if (has_topic_options) {
			PARSE_U8_RAW(parse_state->start,parse_state->end,subscription_flags);

			reserved = RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RESERVED(subscription_flags);
			retain = RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RETAIN(subscription_flags);
			rap = RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RAP(subscription_flags);
			nl = RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_NL(subscription_flags);
			qos = RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_QOS(subscription_flags);

			PARSE_VALIDATE_QOS(qos);
			PARSE_VALIDATE_ZERO_RESERVED(reserved);

			if (PARSE_CHECK_V5(sub_usub)) {
				PARSE_VALIDATE_RETAIN(retain);
			}
			else {
				PARSE_VALIDATE_ZERO_RESERVED(retain);
				PARSE_VALIDATE_ZERO_RESERVED(rap);
				PARSE_VALIDATE_ZERO_RESERVED(nl);
			}
		}

		struct rrr_mqtt_subscription *subscription = NULL;

		parse_state->ret = rrr_mqtt_subscription_new (&subscription, sub_usub->data_tmp, retain, rap, nl, qos);
		if (parse_state->ret != 0) {
			RRR_MSG_0("Could not allocate subscription in rrr_mqtt_parse_subscribe\n");
			return RRR_MQTT_INTERNAL_ERROR;
		}

		int ret_tmp = rrr_mqtt_subscription_collection_add_unique (sub_usub->subscriptions, &subscription, 1);

		// Destroy function checks for NULL
		rrr_mqtt_subscription_destroy(subscription);

		if (ret_tmp == RRR_MQTT_SUBSCRIPTION_REPLACED) {
			RRR_DBG_3("Duplicate topic filter '%s' in received mqtt SUBSCRIBE\n", sub_usub->data_tmp);
		}
		else if (ret_tmp != RRR_MQTT_SUBSCRIPTION_OK) {
			RRR_MSG_0("Error %i while adding subscription to collection in rrr_mqtt_parse_subscribe\n", ret_tmp);
			return RRR_MQTT_INTERNAL_ERROR;
		}

		PARSE_PAYLOAD_SAVE_CHECKPOINT();
	}

	goto parse_done;

	PARSE_END_PAYLOAD();
}

int rrr_mqtt_parse_subscribe (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(subscribe);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(subscribe);

	parse_state->ret = __rrr_mqtt_parse_subscribe_unsubscribe (
			session,
			parse_state,
			(struct rrr_mqtt_p_sub_usub *) subscribe,
			1
	);

	return parse_state->ret;
}

int rrr_mqtt_parse_unsubscribe (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(unsubscribe);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(unsubscribe);

	parse_state->ret = __rrr_mqtt_parse_subscribe_unsubscribe (
			session,
			parse_state,
			(struct rrr_mqtt_p_sub_usub *) unsubscribe,
			0
	);

	return parse_state->ret;
}

static int __rrr_mqtt_parse_suback_unsuback (
		struct rrr_mqtt_parse_session *session,
		struct parse_state *parse_state,
		struct rrr_mqtt_p_suback_unsuback *suback_unsuback,
		int no_payload
) {
	PARSE_BEGIN(suback_unsuback);
	PARSE_PACKET_ID(suback_unsuback);

	if (no_payload == 0) { // This check is redundant in practice, just here to clarify
		PARSE_PROPERTIES_IF_V5(suback_unsuback,properties);
	}

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(suback_unsuback);

	if (no_payload) {
		goto parse_done;
	}

	PARSE_GET_PAYLOAD_SIZE();

	if (parse_state->payload_length == 0) {
		RRR_MSG_0("No subscriptions acknowlegded, payload was empty while parsing SUBACK message\n");
		return RRR_MQTT_SOFT_ERROR;
	}
	// The rest is handled as overshoot by net transport
	if (session->buf_wpos >= session->target_size) {
		RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_MOVE_PAYLOAD_TO_PACKET);
		goto process_reasons;
	}
	return RRR_MQTT_INCOMPLETE;

	process_reasons:

	suback_unsuback->acknowledgements = (void*) (session->buf + session->payload_pos);
	suback_unsuback->acknowledgements_size = parse_state->payload_length;

	if (suback_unsuback->acknowledgements_size == 0) {
		RRR_MSG_0("Zero payload in received SUBACK packet while parsing\n");
		return RRR_MQTT_SOFT_ERROR;
	}

	for (ssize_t i = 0; i < suback_unsuback->acknowledgements_size; i++) {
		const struct rrr_mqtt_p_reason *reason_struct = NULL;

		if (PARSE_CHECK_V5(suback_unsuback)) {
			uint8_t reason = RRR_MQTT_SUBACK_GET_FLAGS_ALL(suback_unsuback,i);

			// This will also catch invalid QoS
			reason_struct = rrr_mqtt_p_reason_get_v5(reason);
			if (reason_struct == NULL) {
				RRR_MSG_0("Unknown v5 reason %u for subscription index %li in SUBACK message\n",
						reason, i);
				return RRR_MQTT_SOFT_ERROR;
			}
		}
		else {
			uint8_t qos = RRR_MQTT_SUBACK_GET_FLAGS_QOS(suback_unsuback,i);
			uint8_t reason = RRR_MQTT_SUBACK_GET_FLAGS_REASON(suback_unsuback,i);
			uint8_t reserved = RRR_MQTT_SUBACK_GET_FLAGS_RESERVED(suback_unsuback,i);

			if (reserved != 0) {
				RRR_MSG_0("Reserved bits in v31 reason for subscription index %li in SUBACK message was not 0\n", i);
				return RRR_MQTT_SOFT_ERROR;
			}
			if (reason == 1 && qos != 0) {
				RRR_MSG_0("Failure was set for subscription index %li in v31 SUBACK but QoS was not 0\n", i);
				return RRR_MQTT_SOFT_ERROR;
			}

			PARSE_VALIDATE_QOS(qos);

			if (reason != 0) {
				reason_struct = rrr_mqtt_p_reason_get_v5(0x80);
			}
			else {
				// Use V5 reason getter because V31 reason 1 and 2 are for errors
				reason_struct = rrr_mqtt_p_reason_get_v5(qos);
			}
		}

		if (	(RRR_MQTT_P_GET_TYPE(suback_unsuback) == RRR_MQTT_P_TYPE_SUBACK && reason_struct->for_suback == 0) ||
				(RRR_MQTT_P_GET_TYPE(suback_unsuback) == RRR_MQTT_P_TYPE_UNSUBACK && reason_struct->for_unsuback == 0)
		) {
			RRR_MSG_0("Received unknown reason '%s' in %s (un)subscription acknowledgment with index %li\n",
					reason_struct->description,
					RRR_MQTT_P_GET_TYPE_NAME(suback_unsuback),
					i
			);
			return RRR_MQTT_SOFT_ERROR;
		}
	}

	PARSE_END_PAYLOAD();
}

int rrr_mqtt_parse_suback (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(suback);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(suback);

	parse_state->ret = __rrr_mqtt_parse_suback_unsuback (
			session,
			parse_state,
			(struct rrr_mqtt_p_suback_unsuback *) suback,
			0
	);

	return parse_state->ret;
}

int rrr_mqtt_parse_unsuback (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(unsuback);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(unsuback);

	// V3.1 does not have payload in UNSUBACK
	int no_payload = (PARSE_CHECK_V5(unsuback) ? 0 : 1);

	parse_state->ret = __rrr_mqtt_parse_suback_unsuback (
			session,
			parse_state,
			(struct rrr_mqtt_p_suback_unsuback *) unsuback,
			no_payload
	);

	return parse_state->ret;
}

int rrr_mqtt_parse_pingreq (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(pingreq);
	PARSE_BEGIN(pingreq);

	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(pingreq);

	PARSE_END_NO_HEADER(pingreq);
}

int rrr_mqtt_parse_pingresp (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(pingresp);
	PARSE_BEGIN(pingresp);

	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(pingresp);

	PARSE_END_NO_HEADER(pingresp);
}

int rrr_mqtt_parse_disconnect (struct rrr_mqtt_parse_session *session) {
	PARSE_INIT(disconnect);
	PARSE_BEGIN(disconnect);
	PARSE_REQUIRE_PROTOCOL_VERSION();
	PARSE_ALLOCATE(disconnect);

	if (session->protocol_version->id < 5) {
		// Non-zero length NOT allowed for V3.1
		if (session->target_size - session->variable_header_pos != 0) {
			RRR_MSG_0("Received MQTT V3.1 DISCONNECT packet with non-zero remaining length %li\n",
					session->target_size - session->variable_header_pos);
			return RRR_MQTT_SOFT_ERROR;
		}
		goto parse_done;
	}
	else if (session->target_size - session->variable_header_pos == 0) {
		// Zero or non-zero length allowed for V5
		goto parse_done;
	}

	PARSE_PREPARE(1);
	disconnect->reason_v5 = *((uint8_t*) parse_state->start);

	if (session->target_size - session->variable_header_pos == 1) {
		// Allowed to skip disconnect property length if there are no properties
		goto parse_done;
	}

	PARSE_PROPERTIES_IF_V5(disconnect,properties);

	PARSE_END_HEADER_BEGIN_PAYLOAD_AT_CHECKPOINT(disconnect);
	PARSE_END_PAYLOAD();
}

int rrr_mqtt_parse_auth (struct rrr_mqtt_parse_session *session) {
	int ret = 0;
	return ret;
}


#define RRR_MQTT_PARSE_GET_TYPE(p)			(((p)->type & ((uint8_t) 0xF << 4)) >> 4)
#define RRR_MQTT_PARSE_GET_TYPE_FLAGS(p)	((p)->type & ((uint8_t) 0xF))

// Return value through parse status only. Internal error not allowed.
void rrr_mqtt_packet_parse (
		struct rrr_mqtt_parse_session *session
) {
	/*
	 * We might return 0 on error if the error is data-related and it's
	 * the client's fault. In that case, we only set the error status flag.
	 * On other horrendous errors, we return 1.
	 */

	int ret_tmp = 0;

	if (session->buf == NULL) {
		RRR_BUG("buf was NULL in rrr_mqtt_packet_parse\n");
	}
	if (RRR_MQTT_PARSE_IS_ERR(session)) {
		RRR_BUG("rrr_mqtt_packet_parse called with error flag set, connection should have been closed.\n");
	}
	if (RRR_MQTT_PARSE_IS_COMPLETE(session)) {
		RRR_BUG("rrr_mqtt_packet_parse called while parsing was complete\n");
	}

	if (session->buf_wpos < 2) {
		// Incomplete
		goto out;
	}

	if (!RRR_MQTT_PARSE_FIXED_HEADER_IS_DONE(session)) {
		const struct rrr_mqtt_p_header *header = (const struct rrr_mqtt_p_header *) session->buf;

		if (RRR_MQTT_PARSE_GET_TYPE(header) == 0) {
			RRR_MSG_0("Received 0 header type in rrr_mqtt_packet_parse\n");
			RRR_MQTT_PARSE_STATUS_SET_ERR(session);
			goto out;
		}

		const struct rrr_mqtt_p_type_properties *properties = rrr_mqtt_p_get_type_properties(RRR_MQTT_PARSE_GET_TYPE(header));

		RRR_DBG_3("Received mqtt packet of type %u name %s\n",
				properties->type_id, properties->name);

		if (properties->has_reserved_flags != 0 && RRR_MQTT_PARSE_GET_TYPE_FLAGS(header) != properties->flags) {
			RRR_MSG_0("Invalid reserved flags %u received in mqtt packet of type %s\n",
					RRR_MQTT_PARSE_GET_TYPE_FLAGS(header),
					properties->name
			);
			RRR_MQTT_PARSE_STATUS_SET_ERR(session);
			goto out;
		}

		uint32_t remaining_length = 0;
		ssize_t bytes_parsed = 0;
		if ((ret_tmp = __rrr_mqtt_parse_variable_int (
				&remaining_length,
				session->buf + (sizeof(header->type)),
				session->buf + session->buf_wpos,
				&bytes_parsed
		)) != 0) {
			if (ret_tmp == RRR_MQTT_INCOMPLETE) {
				/* Not enough bytes were read */
				goto out;
			}
			else {
				RRR_MSG_0("Parse error in packet fixed header remaining length of type %s, return was %i\n",
						properties->name, ret_tmp);
				RRR_MQTT_PARSE_STATUS_SET_ERR(session);
				goto out;
			}
		}

		session->variable_header_pos = sizeof(header->type) + bytes_parsed;
		session->target_size = sizeof(header->type) + bytes_parsed + remaining_length;
		session->type = RRR_MQTT_PARSE_GET_TYPE(header);
		session->type_flags = RRR_MQTT_PARSE_GET_TYPE_FLAGS(header);
		session->type_properties = properties;

		if (session->target_size <= 0) {
			RRR_MSG_1("Invalid target size %li while parsing packet\n");
			RRR_MQTT_PARSE_STATUS_SET_ERR(session);
			goto out;
		}

		RRR_DBG_3 ("parsed a packet fixed header of type %s total bytes received %li/%li\n",
				properties->name, session->buf_wpos, session->target_size);

		RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_FIXED_HEADER_DONE);
	}

	if (!RRR_MQTT_PARSE_VARIABLE_HEADER_IS_DONE(session)) {
		session->header_parse_attempts++;
		if (session->header_parse_attempts > 10) {
			RRR_MSG_0("Could not parse packet of type %s after 10 attempts, input might be too short or CONNECT missing\n",
					session->type_properties->name);
			RRR_MQTT_PARSE_STATUS_SET_ERR(session);
			goto out;
		}
	}

//	printf ("calling parse for type %s total bytes received %li/%li\n",
//			session->type_properties->name, session->buf_size, session->target_size);

	if ((ret_tmp = session->type_properties->parse(session)) != RRR_MQTT_OK) {
		if (ret_tmp == RRR_MQTT_INCOMPLETE) {
			/* Not enough bytes were read or CONNECT is not yet handled (protocol version not set) */
			goto out;
		}
		else {
			RRR_MSG_0("Error from mqtt parse function of type %s\n",
					session->type_properties->name);
			RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_ERR);
			goto out;
		}
	}

	if (RRR_MQTT_PARSE_STATUS_PAYLOAD_IS_DONE(session)) {
		session->packet->received_size = session->buf_wpos;
		RRR_MQTT_PARSE_STATUS_SET(session,RRR_MQTT_PARSE_STATUS_COMPLETE);
	}

	out:
	return;
}

void rrr_mqtt_packet_parse_session_extract_packet (
		struct rrr_mqtt_p **packet,
		struct rrr_mqtt_parse_session *session
) {
	if (session->packet == NULL || !RRR_MQTT_PARSE_STATUS_PAYLOAD_IS_DONE(session)) {
		RRR_BUG("Invalid preconditions for rrr_mqtt_packet_parse_extract_packet\n");
	}

	session->packet->type_flags = session->type_flags;
	*packet = session->packet;
	session->packet = NULL;
}
