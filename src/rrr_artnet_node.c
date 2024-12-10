/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>

#include "main.h"
#include "lib/log.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/allocator.h"
#include "lib/rrr_strerror.h"
#include "lib/event/event.h"
#include "lib/event/event_collection.h"
#include "lib/event/event_collection_struct.h"
#include "lib/cmdlineparser/cmdline.h"

#include "lib/artnet/rrr_artnet.h"

static volatile int artnet_error = 0;
static volatile int main_running = 1;
static volatile int sigusr2 = 0;

static int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_artnet_node");

struct artnet_callback_data {
	int i;
};

static void artnet_failure_callback (void *arg) {
	struct artnet_callback_data *callback_data = arg;

	(void)(callback_data);

	RRR_MSG_0("Error received from ArtNet framework\n");

	artnet_error = 1;
}

static void artnet_incorrect_mode_callback (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		enum rrr_artnet_mode active_mode,
		enum rrr_artnet_mode required_mode
) {
	(void)(node);
	(void)(universe_i);
	(void)(active_mode);
	(void)(required_mode);

	assert(0 && "Incorrect mode callback not implemented");
}

static int main_periodic(RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct artnet_callback_data *callback_data = arg;

	(void)(callback_data);

	RRR_DBG_1("Main periodic\n");

	if (artnet_error)
		return RRR_EVENT_ERR;
	if (!main_running)
		return RRR_EVENT_EXIT;

	return RRR_EVENT_OK;
}

static int main_loop(void) {
	int ret = 0;

	struct rrr_event_queue *queue;
	struct rrr_event_collection events = {0};
	struct rrr_artnet_node *node;
	struct artnet_callback_data callback_data = {0};

	if ((ret = rrr_event_queue_new(&queue)) != 0) {
		RRR_MSG_0("Failed to create event queue in %s\n", __func__);
		goto out;
	}

	rrr_event_collection_init(&events, queue);

	if ((ret = rrr_artnet_node_new (
			&node,
			RRR_ARTNET_NODE_TYPE_DEVICE
	)) != 0) {
		RRR_MSG_0("Failed to create ArtNet node in %s\n", __func__);
		goto out_destroy_events;
	}

	if ((ret = rrr_artnet_events_register (
			node,
			queue,
			artnet_failure_callback,
			artnet_incorrect_mode_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to register ArtNet events in %s\n", __func__);
		goto out_destroy;
	}

	if ((ret = rrr_event_dispatch (
			queue,
			1 * 1000 * 1000 /* 1 second */,
			main_periodic,
			&callback_data
	)) != RRR_EVENT_OK) {
		RRR_MSG_0("Error from event dispatch in %s: %i\n", __func__, ret);
		ret = 1;
		goto out_destroy;
	}

	out_destroy:
		rrr_artnet_node_destroy(node);
	out_destroy_events:
		rrr_event_collection_clear(&events);
		rrr_event_queue_destroy(queue);
	out:
		return ret;
}

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler;
	struct cmd_data cmd;

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

	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 0) != 0) {
		goto out_cleanup_signal;
	}

	RRR_DBG_1("Starting ArtNet node\n");

	if (main_loop() != 0)
		ret = EXIT_FAILURE;

	rrr_signal_default_signal_actions_register();
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
		cmd_destroy(&cmd);
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
