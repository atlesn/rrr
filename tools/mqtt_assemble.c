#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../src/lib/mqtt/mqtt_parse.h"
#include "../src/lib/mqtt/mqtt_packet.h"
#include "../src/lib/mqtt/mqtt_assemble.h"
#include "../src/lib/mqtt/mqtt_payload.h"
#include "../src/lib/rrr_strerror.h"
#include "../src/lib/allocator.h"

#define PARSE_BYTE_BY_BYTE

const char *rrr_default_log_prefix = "mqtt_parse.c";

struct rrr_tools_mqtt_assemble_header {
	uint8_t type_and_flags;
	uint8_t remaining_length;
};

int main(int argc, const char **argv) {
	int ret = EXIT_SUCCESS;

	char *p_data = NULL;
	rrr_length p_length;
	struct rrr_mqtt_p_protocol_version protocol_version = {
		.id = 4,
		.name = "MQTT"
	};
	struct rrr_mqtt_p *p = NULL;
	struct rrr_tools_mqtt_assemble_header header = {0};
	rrr_length payload_size = 0;

	rrr_strerror_init();

	if (argc != 2) {
		usage:
		RRR_MSG_ERR("Usage: %s {publish}\n", argv[0]);
		return EXIT_FAILURE;
	}

	rrr_config_init (
			0,  /* debuglevel */
			0,  /* debuglevel_on_exit */
			0,   /* start_interval */
			0,   /* no_watcdog_timers */
			0,   /* no_thread_restart */
			0,   /* rfc5424_loglevel_output */
			0,   /* output_buffer_warn_limit */
			0,   /* do_journald_output */
			"./" /* run_directory */
	);
	rrr_log_init();

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
		goto usage;
	}

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
		ret = EXIT_FAILURE;
		goto out;
	}

	if (write(1, p->_assembled_data, p->assembled_data_size) != p->assembled_data_size) {
		RRR_MSG_ERR("Failed to output packet assembled data: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (p->payload != NULL && write(1, p->payload->payload_start, payload_size) != payload_size) {
		RRR_MSG_ERR("Failed to output packet payload data: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	out:
		RRR_MQTT_P_DECREF(p);
		rrr_log_cleanup();
		RRR_FREE_IF_NOT_NULL(p_data);
		rrr_strerror_cleanup();
		return ret;
}
