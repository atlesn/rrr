/*

Block Device Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../cmdlineparser/cmdline.h"
#include "init.h"
#include "defaults.h"
#include "blocks.h"
#include "write.h"
#include "io.h"
#include "validate.h"
#include "session.h"
#include "read.h"
#include "clear.h"
#include "update.h"
#include "../include/bdl.h"

int bdl_write_block (
		struct bdl_session *session, const char *data, unsigned long int data_length,
		uint64_t appdata, uint64_t timestamp, unsigned long int faketimestamp
);

int bdl_clear_dev (struct bdl_session *session, int *result) {
	return clear_dev(&session->device, result);
}

int bdl_validate_dev (struct bdl_session *session, int *result) {
	return validate_dev(&session->device, result);
}

int bdl_read_blocks (
		struct bdl_session *session,
		uint64_t timestamp_gteq, unsigned long int limit
) {
	return read_blocks(&session->device, timestamp_gteq, limit);
}

int bdl_write_block (
		struct bdl_session *session, const char *data, unsigned long int data_length,
		uint64_t appdata, uint64_t timestamp, unsigned long int faketimestamp
) {
	return write_put_block(
		&session->device,
		data, data_length,
		appdata,
		timestamp,
		faketimestamp
	);
}

int bdl_read_update_application_data (
	struct bdl_session *session,
	uint64_t timestamp_min,
	uint64_t application_data_and,
	struct bdl_update_info (*test)(void *arg, struct bdl_update_callback_data *update_data),
	void *arg,
	int *result
) {
	return update_application_data (&session->device, timestamp_min, application_data_and, test, arg, result);
}

int bdl_init_dev (
		struct bdl_session *session,
		unsigned long int blocksize, unsigned long int header_pad, char padchar
) {
	if (blocksize == 0) {
		blocksize = BDL_DEFAULT_BLOCKSIZE;
	}
	if (header_pad == 0) {
		header_pad = BDL_DEFAULT_HEADER_PAD;
	}

	if (blocksize > BDL_MAXIMUM_BLOCKSIZE) {
		fprintf(stderr, "Error: Blocksize was too large, maximum is %i\n", BDL_MAXIMUM_BLOCKSIZE);
		return 1;
	}
	if (blocksize < BDL_MINIMUM_BLOCKSIZE) {
		fprintf(stderr, "Error: Blocksize was too small, minimum is %i\n", BDL_MINIMUM_BLOCKSIZE);
		return 1;
	}
	if (blocksize % BDL_BLOCKSIZE_DIVISOR != 0) {
		fprintf(stderr, "Error: Blocksize needs to be dividable by %i\n", BDL_BLOCKSIZE_DIVISOR);
		return 1;
	}
	if (header_pad < BDL_MINIMUM_HEADER_PAD) {
		fprintf(stderr, "Error: Header pad was too small, minimum is %i\n", BDL_MINIMUM_HEADER_PAD);
		return 1;
	}
	if (header_pad % BDL_HEADER_PAD_DIVISOR != 0) {
		fprintf(stderr, "Error: Header pad needs to be dividable by %i\n", BDL_HEADER_PAD_DIVISOR);
		return 1;
	}

	return init_dev(&session->device, blocksize, header_pad, padchar);
}

void help() {
	printf ("Command was help\n");
}

int bdl_interpret_command (struct bdl_session *session, int argc, const char *argv[]) {
	struct cmd_data cmd_data;

	if (cmd_parse(&cmd_data, argc, argv, CMD_CONFIG_DEFAULTS) != 0) {
		return 1;
	}

	// TODO : Write recover procedure and auto recover from hintblocks

	if (argc == 1 || cmd_match(&cmd_data, "help")) {
		help();
	}
	else if (cmd_match(&cmd_data, "open")) {
		// Start a session, and write commands line by line (from STDIN)
		const char *device_path = cmd_get_value(&cmd_data, "dev");

		if (device_path == NULL) {
			fprintf(stderr, "Error: Device argument was missing for open command, use 'open dev=DEVICE'\n");
			return 1;
		}

		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (session->usercount != 0) {
			fprintf (stderr, "Error: A device was already open\n");
			return 1;
		}

		if (bdl_start_session(session, device_path, 0) != 0) {
			fprintf (stderr, "Error while opening device for session use\n");
			return 1;
		}
	}
	else if (cmd_match(&cmd_data, "close")) {
		if (session->usercount == 0) {
			fprintf (stderr, "Attempted to close while no device was open\n");
			return 1;
		}

		bdl_close_session(session);

	}
	else if (cmd_match(&cmd_data, "clear")) {
		const char *device_string = cmd_get_value(&cmd_data, "dev");

		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (bdl_start_session (session, device_string, 0) != 0) {
			fprintf (stderr, "Could not start session for clear command\n");
			return 1;
		}

		int result;
		if (clear_dev(&session->device, &result) != 0) {
			fprintf (stderr, "Error while clearing device\n");
			bdl_close_session(session);
			return 1;
		}

		if (result == 0) {
			printf ("Device was cleared\n");
		}
		else {
			fprintf (stderr, "Device was not valid, must be initialized\n");
		}

		bdl_close_session(session);
	}
	else if (cmd_match(&cmd_data, "validate")) {
		const char *device_string = cmd_get_value(&cmd_data, "dev");


		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (bdl_start_session (session, device_string, 0) != 0) {
			fprintf (stderr, "Could not start session for validate command\n");
			return 1;
		}

		int result;
		if (validate_dev(&session->device, &result) != 0) {
			fprintf (stderr, "Error while validating device\n");
			bdl_close_session(session);
			return 1;
		}

		if (result == 0) {
			printf ("Device was valid\n");
		}
		else {
			printf ("Device was not valid, must be initialized\n");
		}

		bdl_close_session(session);
	}
	else if (cmd_match(&cmd_data, "read")) {
		const char *device_string = cmd_get_value(&cmd_data, "dev");
		const char *timestamp_gteq_string = cmd_get_value(&cmd_data, "ts_gteq");
		const char *limit_string = cmd_get_value(&cmd_data, "limit");

		uint64_t timestamp_gteq = 0;
		unsigned long int limit = 0;

		if (timestamp_gteq_string != NULL) {
			if (cmd_convert_uint64_10(&cmd_data, "ts_gteq")) {
				fprintf(stderr, "Error: Could not interpret timestamp greater or equal argument, use ts_gteq=POSITIVE INTEGER\n");
				return 1;
			}
			timestamp_gteq = cmd_get_uint64(&cmd_data, "ts_gteq");
		}
		if (limit_string != NULL) {
			if (cmd_convert_integer_10 (&cmd_data, "limit") != 0) {
				fprintf (stderr, "Error: Could not interpret limit argument, use limit=POSITIVE INTEGER\n");
				return 1;
			}

			long int limit_tmp = cmd_get_integer(&cmd_data, "limit");
			if (limit_tmp < 0) {
				fprintf (stderr, "Error: Limit argument was less than zero\n");
				return 1;
			}

			limit = limit_tmp;
		}

		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (bdl_start_session (session, device_string, 0) != 0) {
			fprintf (stderr, "Could not start session for read command\n");
			return 1;
		}

		if (read_blocks(&session->device, timestamp_gteq, limit) != 0) {
			fprintf (stderr, "Error while reading blocks\n");
			bdl_close_session(session);
			return 1;
		}

		bdl_close_session(session);
	}
	else if (cmd_match(&cmd_data, "write")) {
		const char *device_string = cmd_get_value(&cmd_data, "dev");
		const char *appdata_string = cmd_get_value(&cmd_data, "appdata");
		const char *timestamp_string = cmd_get_value(&cmd_data, "timestamp");
		const char *faketimestamp_string = cmd_get_value(&cmd_data, "faketimestamp");
		const char *data = cmd_get_last_argument(&cmd_data);

		// TODO : Create synced write argument, sync after every write

		uint64_t appdata = 0;
		uint64_t timestamp = 0;
		unsigned long int faketimestamp = 0;

		if (data == NULL || *data == '\0') {
			fprintf(stderr, "Error: Data argument was missing for write command, use 'write dev=DEVICE [...] DATA'\n");
			return 1;
		}
		if (appdata_string != NULL) {
			if (cmd_convert_hex_64(&cmd_data, "appdata") != 0) {
				fprintf(stderr, "Error: Could not interpret pad charachter argument, use padchar=HEXNUMBER 1 BYTE\n");
				return 1;
			}

			appdata = cmd_get_hex_64(&cmd_data, "appdata");
		}
		if (timestamp_string != NULL) {
			if (cmd_convert_uint64_10(&cmd_data, "timestamp") != 0) {
				fprintf(stderr, "Error: Could not interpret timestamp argument, use timestamp=NUM\n");
				return 1;
			}

			timestamp = cmd_get_uint64(&cmd_data, "timestamp");
		}
		if (faketimestamp_string != NULL) {
			if (cmd_convert_integer_10(&cmd_data, "faketimestamp") != 0) {
				fprintf(stderr, "Error: Could not interpret faketimestamp argument, use faketimestamp=NUM\n");
				return 1;
			}

			int faketimestamp_tmp = cmd_get_integer(&cmd_data, "faketimestamp");

			if (faketimestamp_tmp < 0) {
				fprintf (stderr, "Error: Fake timestamp was negative\n");
				return 1;
			}

			faketimestamp = faketimestamp_tmp;
		}

		// Check that the user hasn't specified anything funny at the command line
		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (bdl_start_session(session, device_string, 0) != 0) {
			fprintf (stderr, "Could not start session for write command\n");
			return 1;
		}

		if (write_put_block(
				&session->device,
				data, strlen(data)+1,
				appdata,
				timestamp,
				faketimestamp
		) != 0) {
			bdl_close_session(session);
			return 1;
		}

		bdl_close_session(session);
	}
	else if (cmd_match(&cmd_data, "init")) {
		const char *device_string = cmd_get_value(&cmd_data, "dev");
		const char *bs_string = cmd_get_value(&cmd_data, "bs");
		const char *hpad_string = cmd_get_value(&cmd_data, "hpad");
		const char *padchar_string = cmd_get_value(&cmd_data, "padchar");

		unsigned long int blocksize = BDL_DEFAULT_BLOCKSIZE;
		unsigned long int header_pad = BDL_DEFAULT_HEADER_PAD;
		char padchar = BDL_DEFAULT_PAD_CHAR;

		// Parse block size argument
		if (bs_string != NULL) {
			if (cmd_convert_integer_10(&cmd_data, "bs")) {
				fprintf(stderr, "Error: Could not interpret block size argument, use bs=NUMBER\n");
				return 1;
			}

			long int blocksize_tmp = cmd_get_integer(&cmd_data, "bs");

			if (blocksize_tmp < 0) {
				fprintf (stderr, "Error: Blocksize cannot be negative\n");
				return 1;
			}

			blocksize = blocksize_tmp;
		}

		// Parse header pad argument
		if (hpad_string != NULL) {
			if (cmd_convert_integer_10(&cmd_data, "hpad")) {
				fprintf(stderr, "Error: Could not interpret header pad size argument, use hpad=NUMBER\n");
				return 1;
			}

			long int header_pad_tmp = cmd_get_integer(&cmd_data, "hpad");

			if (header_pad_tmp < 0) {
				fprintf (stderr, "Error: Header pad cannot be negative\n");
				return 1;
			}

			header_pad = header_pad_tmp;
		}

		// Parse pad characher argument
		if (padchar_string != NULL) {
			if (cmd_convert_hex_byte(&cmd_data, "padchar")) {
				fprintf(stderr, "Error: Could not interpret pad charachter argument, use padchar=HEXNUMBER 1 BYTE\n");
				return 1;
			}

			padchar = cmd_get_hex_byte(&cmd_data, "padchar");
		}

		// Check that the user hasn't specified anything funny at the command line
		if (cmd_check_all_args_used(&cmd_data)) {
			return 1;
		}

		if (bdl_start_session (session, device_string, 0) != 0) {
			fprintf (stderr, "Error while starting session for init command\n");
			return 1;
		}

		/* Don't call init_dev directly as we need to perform more checks */
		if (bdl_init_dev(session, blocksize, header_pad, padchar)) {
			fprintf (stderr, "Device intialization failed\n");
			bdl_close_session(session);
			return 1;
		}
		bdl_close_session(session);
	}
	else {
		fprintf (stderr, "Unknown command\n");
		return 1;
	}

	return 0;
}
