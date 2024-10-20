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

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_mqtt_p_protocol_version protocol_version = {
		.id = 4,
		.name = "MQTT"
	};
	struct rrr_tools_mqtt_assemble_data data = {0};
	struct cmd_data cmd;

	struct rrr_mqtt_p *p = NULL;

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

	if (strcmp(argv[1], "publish") == 0) {
		if (rrr_mqtt_p_new_publish (
				(struct rrr_mqtt_p_publish **) &p,
				"topic",
				"data",
				4,
				&protocol_version
		) != 0) {
			RRR_MSG_ERR("Failed to make publish packet\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(p, 2);
	}
	else if (strcmp(argv[1], "subscribe") == 0) {
		if ((p = rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_SUBSCRIBE, &protocol_version)) == NULL) {
			RRR_MSG_ERR("Failed to allocate subscribe packet\n");
			ret = EXIT_FAILURE;
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
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	else {
		RRR_MSG_ERR("Unknown packet type '%s'\n", argv[1]);
		goto out;
	}

	p->packet_identifier = 0x102;

	if (rrr_tools_mqtt_assemble_output(&data, p) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	out:
		RRR_MQTT_P_DECREF(p);
	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_cleanup_strerror:
		rrr_strerror_cleanup();

		return ret;
}
