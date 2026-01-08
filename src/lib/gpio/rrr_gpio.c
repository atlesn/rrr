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

Original code: Copyright 2023 Kent Gibson <warthog618@gmail.com>

*/

#include "rrr_gpio.h"
#include "../log.h"
#include "../rrr_strerror.h"

#include <gpiod.h>
#include <errno.h>

struct rrr_gpio_request {
	struct gpiod_line_request *request;
};

static struct gpiod_line_request *__rrr_gpio_request_output_line (
		const char *chip_path,
		unsigned int offset,
		enum gpiod_line_value value,
		const char *consumer
) {
	struct gpiod_request_config *req_cfg = NULL;
	struct gpiod_line_request *request = NULL;
	struct gpiod_line_settings *settings;
	struct gpiod_line_config *line_cfg;
	struct gpiod_chip *chip;
	int tmp = 0;

	if ((chip = gpiod_chip_open(chip_path)) == NULL) {
		RRR_MSG_0("Failed to open GPIO chip '%s': %s\n",
			chip_path, rrr_strerror(errno));
		return NULL;
	}

	if ((settings = gpiod_line_settings_new()) == NULL) {
		RRR_MSG_0("Failed to create line settings in %s\n", __func__);
		goto close_chip;
	}

	tmp |= gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
	tmp |= gpiod_line_settings_set_output_value(settings, value);

	if (tmp != 0) {
		RRR_MSG_0("Failed to set settings in %s\n", __func__);
		goto free_settings;
	}

	if ((line_cfg = gpiod_line_config_new()) == NULL) {
		RRR_MSG_0("Failed to create line config in %s\n", __func__);
		goto free_settings;
	}

	if (gpiod_line_config_add_line_settings(line_cfg, &offset, 1, settings) != 0) {
		RRR_MSG_0("Failed to add to line config in %s\n", __func__);
		goto free_line_config;
	}

	if (consumer) {
		if ((req_cfg = gpiod_request_config_new()) == NULL) {
			RRR_MSG_0("Failed to create request config in %s\n", __func__);
			goto free_line_config;
		}

		gpiod_request_config_set_consumer(req_cfg, consumer);
	}

	if ((request = gpiod_chip_request_lines(chip, req_cfg, line_cfg)) == NULL) {
		RRR_MSG_0("Line request failed in %s\n", __func__);
		goto free_request_config;
	}

free_request_config:
	if (req_cfg != NULL)
		gpiod_request_config_free(req_cfg);

free_line_config:
	gpiod_line_config_free(line_cfg);

free_settings:
	gpiod_line_settings_free(settings);

close_chip:
	gpiod_chip_close(chip);

	return request;
}

int rrr_gpio_set_line(const char *chip_path, unsigned int line_offset, int value) {
	enum gpiod_line_value line_value = value ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE;

	int ret = 0;

	struct gpiod_line_request *request;

	if ((request = __rrr_gpio_request_output_line(chip_path, line_offset, line_value, "toggle-line-value")) == NULL) {
		RRR_MSG_0("Failed to request GPIO line on device %s\n", chip_path);
		ret = 1;
		goto out;
	}

	if (gpiod_line_request_set_value(request, line_offset, line_value) != 0) {
		RRR_MSG_0("Failed to set value for line %u on GPIO device %s\n", line_offset, chip_path);
		ret = 1;
		goto cleanup;
	}

	cleanup:
		gpiod_line_request_release(request);
	out:
		return ret;
}
