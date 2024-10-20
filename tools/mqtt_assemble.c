#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../build_timestamp.h"
#include "../src/main.h"
#include "../src/lib/version.h"
#include "../src/lib/rrr_strerror.h"
#include "../src/lib/allocator.h"
#include "../src/lib/random.h"
#include "../src/lib/mqtt/mqtt_parse.h"
#include "../src/lib/mqtt/mqtt_packet.h"
#include "../src/lib/mqtt/mqtt_assemble.h"
#include "../src/lib/mqtt/mqtt_payload.h"
#include "../src/lib/mqtt/mqtt_subscription.h"
#include "../src/lib/cmdlineparser/cmdline.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("mqtt_assemble");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,        '\0',    "type",                 "{PACKET TYPE}"},
	{0,                            's',    "single-byte-fuzz",     "[-s|--single-byte-fuzz]"},
	{0,                            'm',    "multi-byte-fuzz",      "[-m|--multi-byte-fuzz]"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_tools_mqtt_assemble_data {
	int do_single_byte_fuzz;
	int do_multi_byte_fuzz;
};

struct rrr_tools_mqtt_assemble_header {
	uint8_t type_and_flags;
	uint8_t remaining_length;
};

static void rrr_tools_mqtt_assemble_fuzz_single_byte(void *data, rrr_length data_size) {
	rrr_length wpos;
	uint8_t byte;

	wpos = rrr_rand() % data_size;
	byte = rrr_rand();

	RRR_MSG_ERR("Fuzz at wpos: %04" PRIrrrl "/%04" PRIrrrl " to 0x%02x\n",
	     wpos, data_size, byte);

	((char *) data)[wpos] = byte;
}

static void rrr_tools_mqtt_assemble_fuzz_multi_byte(void *data, rrr_length data_size) {
	rrr_length amount = data_size / 16;
	if (amount == 0)
		amount = rrr_rand() & 0xff;

	for (rrr_length i = 0; i < amount; i++) {
		rrr_tools_mqtt_assemble_fuzz_single_byte(data, data_size);
	}
}

static int rrr_tools_mqtt_assemble_output (
		const struct rrr_tools_mqtt_assemble_data *data,
		struct rrr_mqtt_p *p
) {
	int ret = 0;

	char *p_data = NULL;
	char *f_data = NULL;
	char *f_data_pos;
	rrr_length p_length;
	struct rrr_tools_mqtt_assemble_header header = {0};
	rrr_length payload_size = 0;
	rrr_length total_size = 0;

	RRR_MQTT_P_GET_ASSEMBLER(p) (
			&p_data,
			&p_length,
			p
	);

	if (p_length == 0) {
		RRR_FREE_IF_NOT_NULL(p_data);
	}

	p->_assembled_data = p_data;
	p->assembled_data_size = p_length;

	p_data = NULL;

	if (p->payload != NULL)
		payload_size = p->payload->size;

	// Support only one byte vint here
	assert(p->assembled_data_size + payload_size < 0x80);
	header.remaining_length = p->assembled_data_size + payload_size;
	header.type_and_flags = (uint8_t) RRR_MQTT_P_GET_TYPE_AND_FLAGS(p);

	total_size = 2 + p->assembled_data_size + payload_size;

	if ((f_data = f_data_pos = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_ERR("Failed to allocate final packet data\n");
		ret = 1;
		goto out;
	}

	memcpy(f_data_pos, &header, 2);
	f_data_pos += 2;

	memcpy(f_data_pos, p->_assembled_data, p->assembled_data_size);
	f_data_pos += p->assembled_data_size;

	if (p->payload != NULL) {
		memcpy(f_data_pos, p->payload->payload_start, payload_size);
		f_data_pos += payload_size;
	}

	assert(f_data_pos == f_data + total_size);

	if (data->do_single_byte_fuzz) {
		rrr_tools_mqtt_assemble_fuzz_single_byte(f_data, total_size);
	}

	if (data->do_multi_byte_fuzz) {
		rrr_tools_mqtt_assemble_fuzz_multi_byte(f_data, total_size);
	}

	if (write(1, f_data, total_size) != total_size) {
		RRR_MSG_ERR("Failed to output packet: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(p_data);
	RRR_FREE_IF_NOT_NULL(f_data);
	return ret;
}

static int rrr_tools_mqtt_assemble_generate (
		struct rrr_mqtt_p **result,
		const char *type
) {
	int ret = 0;

	struct rrr_mqtt_p *p = NULL;
	static const struct rrr_mqtt_p_protocol_version protocol_version = {
		.id = 4,
		.name = "MQTT"
	};

	if (strcmp(type, "publish") == 0) {
		if (rrr_mqtt_p_new_publish (
				(struct rrr_mqtt_p_publish **) &p,
				"topic",
				"data",
				4,
				&protocol_version
		) != 0) {
			RRR_MSG_ERR("Failed to make publish packet\n");
			ret = 1;
			goto out;
		}

		RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(p, 2);
	}
	else if (strcmp(type, "puback") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBACK, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate puback packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "pubrec") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBREC, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate pubrec packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "pubrel") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBREL, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate pubrel packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "pubcomp") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBCOMP, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate pubcomp packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "pingreq") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PINGREQ, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate pingreq packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "pingresp") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PINGRESP, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate pingresp packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "subscribe") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_SUBSCRIBE, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate subscribe packet\n");
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_p_subscribe *sub = (struct rrr_mqtt_p_subscribe *) p;

		if (rrr_mqtt_subscription_collection_push_unique_str (
				sub->subscriptions,
				"topic/filter/+/#",
				0,
				0,
				0,
				0
		) != 0) {
			RRR_MSG_ERR("Failed to put to subscription collection\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "suback") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_UNSUBACK, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate subscribe packet\n");
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) p;

		if (rrr_mqtt_subscription_collection_new(&suback->subscriptions_) != 0) {
			RRR_MSG_ERR("Failed to make subscription collection\n");
			ret = 1;
			goto out;
		}

		if (rrr_mqtt_subscription_collection_push_unique_str (
				suback->subscriptions_,
				"topic/filter/+/#",
				0,
				0,
				0,
				0
		) != 0) {
			RRR_MSG_ERR("Failed to put to subscription collection\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "unsubscribe") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_UNSUBSCRIBE, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate unsubscribe packet\n");
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_p_unsubscribe *unsub = (struct rrr_mqtt_p_unsubscribe *) p;

		if (rrr_mqtt_subscription_collection_push_unique_str (
				unsub->subscriptions,
				"topic/filter/+/#",
				0,
				0,
				0,
				0
		) != 0) {
			RRR_MSG_ERR("Failed to put to subscription collection\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "unsuback") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_UNSUBACK, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate subscribe packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "connect") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_CONNECT, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate connect packet\n");
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_p_connect *connect = (struct rrr_mqtt_p_connect *) p;

		RRR_MQTT_P_CONNECT_SET_FLAG_CLEAN_START(connect);
		connect->client_identifier = strdup("CLIENT IDENTIFIER");

		RRR_MQTT_P_CONNECT_SET_FLAG_WILL(connect);
		connect->will_topic = strdup("will/topic");
		if (rrr_nullsafe_str_new_or_replace_empty(&connect->will_message) != 0) {
			RRR_MSG_ERR("Failed to create connect will message nullsafe\n");
			ret = 1;
			goto out;
		}
		if (rrr_nullsafe_str_append_asprintf(connect->will_message, "%s", "WILL MESSAGE") != 0) {
			RRR_MSG_ERR("Failed to set connect will message\n");
			ret = 1;
			goto out;
		}

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&connect->properties,
				0x16,
				"PROPERTY",
				8
		) != 0) {
			RRR_MSG_ERR("Failed to push connect property\n");
			ret = 1;
			goto out;
		}

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&connect->will_properties,
				23,
				"WILL PROPERTY",
				13
		) != 0) {
			RRR_MSG_ERR("Failed to push connect will property\n");
			ret = 1;
			goto out;
		}

		RRR_MQTT_P_CONNECT_SET_FLAG_USER_NAME(connect);
		RRR_MQTT_P_CONNECT_SET_FLAG_PASSWORD(connect);
		connect->username = strdup("username");
		connect->password = strdup("password");
	}
	else if (strcmp(type, "disconnect") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_DISCONNECT, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate disconnect packet\n");
			ret = 1;
			goto out;
		}
	}
	else if (strcmp(type, "connack") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_CONNACK, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate connack packet\n");
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_p_connack *connack = (struct rrr_mqtt_p_connack *) p;

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&connack->properties,
				0x16,
				"PROPERTY",
				8
		) != 0) {
			RRR_MSG_ERR("Failed to push connack property\n");
			ret = 1;
			goto out;
		}
	}
	else {
		RRR_MSG_ERR("Unknown packet type '%s'\n", type);
		ret = 1;
		goto out;
	}

	*result = p;
	p = NULL;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(p);
	return ret;
}

static int rrr_tools_mqtt_assemble_generate_and_output (
		struct rrr_tools_mqtt_assemble_data *data,
		const char *type
) {
	int ret = 0;

	struct rrr_mqtt_p *p = NULL;

	if (rrr_tools_mqtt_assemble_generate(&p, type) != 0) {
		ret = 1;
		goto out;
	}

	p->packet_identifier = 0x102;

	if (rrr_tools_mqtt_assemble_output(data, p) != 0) {
		ret = 1;
		goto out;
	}

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(p);
	return ret;
}

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_tools_mqtt_assemble_data data = {0};
	struct cmd_data cmd;

	rrr_strerror_init();
	if (rrr_allocator_init() != 0) {
		goto out_cleanup_strerror;
	}

	if (rrr_log_init() != 0) {
		goto out_cleanup_allocator;
	}

	cmd_init(&cmd, cmd_rules, argc, argv);

	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_cmd;
	}

	if (cmd_exists(&cmd, "single-byte-fuzz", 0)) {
		data.do_single_byte_fuzz = 1;
	}

	if (cmd_exists(&cmd, "multi-byte-fuzz", 0)) {
		data.do_multi_byte_fuzz = 1;
	}

	if (strcmp(argv[1], "all") == 0) {
		if (rrr_tools_mqtt_assemble_generate_and_output(&data, "connect") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "connack") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "publish") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "puback") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "pubrec") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "pubrel") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "pubcomp") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "subscribe") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "suback") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "unsubscribe") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "unsuback") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "pingreq") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "pingresp") ||
		    rrr_tools_mqtt_assemble_generate_and_output(&data, "disconnect") != 0
		) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	else {
		if (rrr_tools_mqtt_assemble_generate_and_output(&data, argv[1]) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	out:
	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_cleanup_strerror:
		rrr_strerror_cleanup();

		return ret;
}
