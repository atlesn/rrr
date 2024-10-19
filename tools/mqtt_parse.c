#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/lib/mqtt/mqtt_parse.h"
#include "../src/lib/mqtt/mqtt_packet.h"

const char *rrr_default_log_prefix = "mqtt_parse.c";

int main() {
	int ret = 0;

	ssize_t bytes;
	const char tmp[1024];
	char *buf = NULL;
	size_t buf_size = 0;
	size_t buf_pos = 0;
	struct rrr_mqtt_parse_session parse_session = {0};
	struct rrr_mqtt_p_protocol_version protocol_version = {
		.id = 4,
		.name = "MQTT"
	};

	rrr_config_init (
			71,  /* debuglevel */
			71,  /* debuglevel_on_exit */
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

	while ((bytes = read(0, (void *) tmp, sizeof(tmp))) > 0) {
		printf("Read %lli bytes\n", (long long int) bytes);
		if (buf_pos + bytes > buf_size) {
			buf = realloc(buf, buf_size + sizeof(tmp));
			buf_size += sizeof(tmp);
		}
		memcpy(buf + buf_pos, tmp, bytes);
		buf_pos += bytes;

		rrr_mqtt_parse_session_update (
			&parse_session,
			buf,
			buf_pos,
			&protocol_version
		);

		rrr_mqtt_packet_parse(&parse_session);
	}

	printf("Status: %i\n", parse_session.status);

	out:
	rrr_mqtt_parse_session_destroy(&parse_session);
	rrr_log_cleanup();
	if (buf)
		free(buf);
	return EXIT_SUCCESS;
}
