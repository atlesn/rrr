#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../src/lib/mqtt/mqtt_parse.h"
#include "../src/lib/mqtt/mqtt_packet.h"
#include "../src/lib/rrr_strerror.h"

// #define PARSE_BYTE_BY_BYTE

const char *rrr_default_log_prefix = "mqtt_parse.c";

int main(int argc, const char **argv) {
	int ret = EXIT_SUCCESS;

	int fd = 0;
	ssize_t bytes;
#ifdef PARSE_BYTE_BY_BYTE
	char tmp[1];
#else
	char tmp[1024];
#endif
	char *buf = NULL;
	size_t buf_size = 0;
	size_t buf_pos = 0;
	struct rrr_mqtt_parse_session parse_session = {0};
	struct rrr_mqtt_p_protocol_version protocol_version = {
		.id = 4,
		.name = "MQTT"
	};

	rrr_strerror_init();

	if (argc > 2) {
		RRR_MSG_0("Usage: %s [packet file]\n", argv[0]);
		return EXIT_FAILURE;
	}
	else if (argc == 2) {
		if ((fd = open(argv[1], O_RDONLY)) < 0) {
			RRR_MSG_0("Failed to open %s: %s\n", argv[1], rrr_strerror(errno));
			return EXIT_FAILURE;
		}
	}

	rrr_config_init (
			71,   /* debuglevel */
			0,   /* debuglevel_on_exit */
			0,   /* start_interval */
			0,   /* no_watcdog_timers */
			0,   /* no_thread_restart */
			0,   /* rfc5424_loglevel_output */
			0,   /* output_buffer_warn_limit */
			0,   /* do_journald_output */
			"./" /* run_directory */
	);
	rrr_log_init();
	rrr_mqtt_parse_session_init(&parse_session);

	int attempts = 0;
	while ((bytes = read(fd, (void *) tmp, sizeof(tmp))) > 0) {
		RRR_DBG_1("Read %lli bytes\n", (long long int) bytes);
		if (buf_pos + bytes > buf_size) {
			buf = realloc(buf, buf_size + sizeof(tmp));
			buf_size += sizeof(tmp);
		}
		memcpy(buf + buf_pos, tmp, bytes);
		buf_pos += bytes;

		parse:

		if (++attempts == 10) {
			RRR_MSG_ERR("Too many attempts\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		rrr_mqtt_parse_session_update (
			&parse_session,
			buf,
			buf_pos,
			&protocol_version
		);
	
		rrr_mqtt_packet_parse(&parse_session);

		if (RRR_MQTT_PARSE_IS_ERR(&parse_session)) {
			RRR_DBG_1("Bail, status: %i\n", parse_session.status);
			ret = EXIT_FAILURE;
			goto out;
		}

		if (RRR_MQTT_PARSE_IS_COMPLETE(&parse_session)) {
			RRR_DBG_1("Complete, status: %i\n", parse_session.status);

			if (parse_session.type == RRR_MQTT_P_TYPE_PUBLISH) {
				struct rrr_mqtt_p_publish *pub = (struct rrr_mqtt_p_publish *) parse_session.packet;

				RRR_DBG_1("Publish: Identifier: %u\n", pub->packet_identifier);
				RRR_DBG_1("         Topic     : %s\n", pub->topic);
				RRR_DBG_1("         QoS       : %u\n", RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(pub));
			}

			assert (buf_pos >= parse_session.target_size);

			size_t rest = buf_pos - parse_session.target_size;
			if (rest > 0) {
				RRR_DBG_1("Overshoot %llu bytes\n", (unsigned long long int) rest);
				memmove(buf, buf + parse_session.target_size, rest);
				buf_pos = rest;
			}
			else {
				buf_pos = 0;
			}

			rrr_mqtt_parse_session_destroy(&parse_session);
			rrr_mqtt_parse_session_init(&parse_session);

			attempts = 0;

			if (buf_pos > 0) {
				goto parse;
			}
		}
	}

	out:
		rrr_mqtt_parse_session_destroy(&parse_session);
		rrr_log_cleanup();
		if (buf)
			free(buf);
		rrr_strerror_cleanup();
		return ret;
}
