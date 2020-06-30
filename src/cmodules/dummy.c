/*
 * Licensed under RRR MODULE LICENSE VERSION 1.
 *
 * Copyright 2020 Atle Solbakken <atle@goliathdns.no>
 *
 * This file may be expanded, modified and customized and re-licensed under
 * the terms of either
 *  - GPL version 3 or later
 *  or
 *  - RRR MODULE LICENCE VERSION 1 or later
 *  .
 *
 * The new author(s) own(s) full copyright of the newly licensed file. A
 * new copyright notice appropriate for one of the above mentioned licenses
 * must be applied in the place of this copyright notice.
 *
 * When re-licensing the file, this copyright notice, including reference
 * to the original author MUST be removed.
 */

#include <string.h>
#include <stdlib.h>

#include "cmodule.h"
#include "log.h"
#include "posix.h"

struct dummy_data {
	char *custom_setting;
};

static struct dummy_data dummy_data = {0};

int config(RRR_CONFIG_ARGS) {
	struct dummy_data *data = &dummy_data;

	int ret = 0;

	ctx->application_ptr = data;

	RRR_MSG_1("cmodule in config()\n");

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("cmodule_custom_setting", custom_setting);

	if (data->custom_setting == NULL || *(data->custom_setting) == '\0') {
		RRR_MSG_0("Could not find setting 'cmodule_custom_setting' in configuration\n");
		ret = 1;
		goto out;
	}

	RRR_MSG_1("Custom setting: %s\n", data->custom_setting);

	out:
	return ret;
}

int source(RRR_SOURCE_ARGS) {
	(void)(ctx);
	(void)(message_addr);

	rrr_free(message);

	return 0;
}

int process(RRR_PROCESS_ARGS) {
	RRR_DBG_2("cmodule process timestamp %" PRIu64 "\n", message->timestamp);

	return rrr_send_and_free(ctx, message, message_addr);
}

int cleanup(RRR_CLEANUP_ARGS) {
	struct dummy_data *data = ctx->application_ptr;

	RRR_MSG_1("cmodule cleanup\n");

	RRR_FREE_IF_NOT_NULL(data->custom_setting);

	ctx->application_ptr = NULL;

	return 0;
}
