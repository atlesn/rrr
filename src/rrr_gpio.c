/*

Read Route Record

Copyright (C) 2026 Atle Solbakken atle@goliathdns.no

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

#include "lib/rrr_types.h"
#include "main.h"
#include "lib/log.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/allocator.h"
#include "lib/rrr_strerror.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/util/posix.h"

#include "lib/gpio/rrr_gpio.h"

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,         '\0',   "chip",                  "{GPIO CHIP}"},
        {CMD_ARG_FLAG_NO_FLAG,         '\0',   "line",                  "{LINE NUMBER}"},
        {CMD_ARG_FLAG_NO_FLAG,         '\0',   "value",                 "{on|off}"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_gpio");

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	const char *chip_path;
	const char *line_offset_str;
	const char *value_str;
	uint64_t line_offset;
	int value;
	struct cmd_data cmd;
	struct rrr_gpio_ctx *ctx = NULL;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}

	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 3) != 0) {
		goto out_cleanup_signal;
	}

	chip_path = cmd_get_value(&cmd, "chip", 0);
	line_offset_str = cmd_get_value(&cmd, "line", 0);
	value_str = cmd_get_value(&cmd, "value", 0);

	if (!chip_path || !line_offset_str || !value_str) {
		RRR_MSG_0("Invalid command line, check help\n");
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (cmd_convert_uint64_10(line_offset_str, &line_offset) != 0) {
		RRR_MSG_0("Invalid value '%s' for line, must be numeric\n", line_offset_str);
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (strcmp(value_str, "on") == 0) {
		value = 1;
	}
	else if (strcmp(value_str, "off") == 0) {
		value = 0;
	}
	else {
		RRR_MSG_0("Unknown value '%s', must be either 'on' or 'off'\n", value_str);
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_gpio_set_line(&ctx, chip_path, rrr_uint_from_biglength_bug_const(line_offset), value) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	for (int i = 0; i < 5; i++) {
		rrr_posix_usleep(1 * 1000 * 1000);
		int value;
		if (rrr_gpio_get_line(&ctx, &value, chip_path, rrr_uint_from_biglength_bug_const(line_offset)) != 0) {
			ret = EXIT_FAILURE;
			goto out_destroy_ctx;
		}
		printf("Value is %i\n", value);
		if (rrr_gpio_set_line(&ctx, chip_path, rrr_uint_from_biglength_bug_const(line_offset), !value) != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_signal;
		}
		printf("Set to %i\n", !value);
	}

	out_destroy_ctx:
		rrr_gpio_ctx_destroy(&ctx);
	out_cleanup_signal:
		// rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		// rrr_signal_handler_remove(signal_handler);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
		cmd_destroy(&cmd);
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
