#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../build_timestamp.h"
#include "../src/main.h"
#include "../src/lib/version.h"
#include "../src/lib/mqtt/mqtt_parse.h"
#include "../src/lib/mqtt/mqtt_packet.h"
#include "../src/lib/mqtt/mqtt_assemble.h"
#include "../src/lib/mqtt/mqtt_payload.h"
#include "../src/lib/rrr_strerror.h"
#include "../src/lib/cmdlineparser/cmdline.h"
#include "../src/lib/allocator.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("mqtt_assemble");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,        '\0',    "type",                 "{PACKET TYPE}"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_tools_mqtt_assemble_header {
	uint8_t type_and_flags;
	uint8_t remaining_length;
};

static int rrr_tools_mqtt_assemble_output(struct rrr_mqtt_p *p) {
	int ret = 0;

	char *p_data = NULL;
	rrr_length p_length;
	struct rrr_tools_mqtt_assemble_header header = {0};
	rrr_length payload_size = 0;

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

	if (write(1, &header, 2) != 2) {
		RRR_MSG_ERR("Failed to output packet header: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (write(1, p->_assembled_data, p->assembled_data_size) != p->assembled_data_size) {
		RRR_MSG_ERR("Failed to output packet assembled data: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (p->payload != NULL && write(1, p->payload->payload_start, payload_size) != payload_size) {
		RRR_MSG_ERR("Failed to output packet payload data: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(p_data);
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
	struct rrr_mqtt_p *p = NULL;

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

		((struct rrr_mqtt_p_publish *) p)->packet_identifier = 0x102;
		RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(p, 2);
	}
	else {
		RRR_MSG_ERR("Unknown packet type '%s'\n", argv[1]);
		goto out;
	}

	if (rrr_tools_mqtt_assemble_output(p) != 0) {
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
