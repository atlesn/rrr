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
#include "../util/linked_list.h"
#include "../log.h"
#include "../rrr_strerror.h"
#include "../allocator.h"

#include <gpiod.h>
#include <errno.h>

#define RRR_GPIO_LINE_MAX 256

struct rrr_gpio_device {
	RRR_LL_NODE(struct rrr_gpio_device);
	char *chip;
	struct gpiod_line_request *request;
	unsigned int lines[RRR_GPIO_LINE_MAX];
	enum gpiod_line_value values[RRR_GPIO_LINE_MAX];
	size_t line_count;
};

struct rrr_gpio_device_collection {
	RRR_LL_HEAD(struct rrr_gpio_device);
};

struct rrr_gpio_ctx {
	struct rrr_gpio_device_collection devices;
};

static struct gpiod_line_request *__rrr_gpio_request_output_line (
		const char *chip_path,
		unsigned int *lines,
		size_t line_count,
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
	tmp |= gpiod_line_settings_set_output_value(settings, GPIOD_LINE_VALUE_INACTIVE);

	if (tmp != 0) {
		RRR_MSG_0("Failed to set settings in %s\n", __func__);
		goto free_settings;
	}

	if ((line_cfg = gpiod_line_config_new()) == NULL) {
		RRR_MSG_0("Failed to create line config in %s\n", __func__);
		goto free_settings;
	}

	if (gpiod_line_config_add_line_settings(line_cfg, lines, line_count, settings) != 0) {
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

static void __rrr_gpio_device_destroy(struct rrr_gpio_device *device) {
	rrr_free(device->chip);
	if (device->request)
		gpiod_line_request_release(device->request);
	rrr_free(device);
}

static int __rrr_gpio_device_new(struct rrr_gpio_device **device, const char *chip) {
	int ret = 0;

	struct rrr_gpio_device *result;

	if ((result = rrr_allocate_zero(sizeof(*result))) == NULL) {
		RRR_MSG_0("Failed to allocate device in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((result->chip = rrr_strdup(chip)) == NULL) {
		RRR_MSG_0("Failed to allocate chip path in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	*device = result;

	goto out;
	out_free:
		rrr_free(result);
	out:
		return ret;
}

static int __rrr_gpio_device_init (struct rrr_gpio_device *device) {
	int ret = 0;

	if (device->request) {
		gpiod_line_request_release(device->request);
		device->request = NULL;
	}

	if ((device->request = __rrr_gpio_request_output_line(device->chip, device->lines, device->line_count, "rrr-gpio")) == NULL) {
		RRR_MSG_0("Failed to request GPIO line on device %s\n", device->chip);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_gpio_device_line_ensure (struct rrr_gpio_device *device, unsigned int line) {
	int ret = 0;

	size_t i;

	for (i = 0; i < device->line_count; i++) {
		if (device->lines[i] == line) {
			goto out;
		}
	}

	if (device->line_count == RRR_GPIO_LINE_MAX) {
		RRR_MSG_0("Maximum number of GPIO lines per device exceeded\n");
		ret = 1;
		goto out;
	}

	device->lines[device->line_count] = line;

	device->line_count++;

	if ((ret = __rrr_gpio_device_init(device)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_gpio_device_line_set (struct rrr_gpio_device *device, unsigned int line, enum gpiod_line_value value) {
	int ret = 0;

	size_t i;

	if ((ret = __rrr_gpio_device_line_ensure(device, line)) != 0) {
		goto out;
	}

	for (i = 0; i < device->line_count; i++) {
		if (device->lines[i] == line) {
			device->values[i] = value;
			goto out;
		}
	}

	RRR_BUG("Line not found");

	out:
	return ret;
}

static int __rrr_gpio_ctx_new(struct rrr_gpio_ctx **ctx) {
	int ret = 0;

	struct rrr_gpio_ctx *result;

	if ((result = rrr_allocate_zero(sizeof(*result))) == NULL) {
		RRR_MSG_0("Failed to allocate ctx in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*ctx = result;

	out:
	return ret;
}

static struct rrr_gpio_device *__rrr_gpio_ctx_device_ensure (struct rrr_gpio_ctx *ctx, const char *chip) {
	struct rrr_gpio_device *new_device;

	RRR_LL_ITERATE_BEGIN(&ctx->devices, struct rrr_gpio_device);
		if (strcmp(node->chip, chip) == 0)
			return node;
	RRR_LL_ITERATE_END();

	if (__rrr_gpio_device_new(&new_device, chip) != 0) {
		return NULL;
	}

	RRR_LL_APPEND(&ctx->devices, new_device);

	return new_device;
}

void rrr_gpio_ctx_destroy(struct rrr_gpio_ctx **ctx) {
	if (*ctx == NULL)
		return;
	RRR_LL_DESTROY(&(*ctx)->devices, struct rrr_gpio_device, __rrr_gpio_device_destroy(node));
	rrr_free(*ctx);
	*ctx = NULL;
}

int rrr_gpio_set_line(struct rrr_gpio_ctx **ctx, const char *chip_path, unsigned int line_offset, int value) {
	enum gpiod_line_value line_value = value ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE;

	int ret = 0;

	struct rrr_gpio_device *device;

	if (*ctx == NULL) {
		if ((ret = __rrr_gpio_ctx_new(ctx)) != 0) {
			goto out;
		}
	}

	if ((device = __rrr_gpio_ctx_device_ensure (*ctx, chip_path)) == NULL) {
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_gpio_device_line_set(device, line_offset, line_value)) != 0) {
		goto out;
	}

	for (size_t i = 0; i < device->line_count; i++) {
		if (gpiod_line_request_set_value(device->request, device->lines[i], device->values[i]) != 0) {
			RRR_MSG_0("Failed to set value for line %u on GPIO device %s\n", line_offset, chip_path);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

int rrr_gpio_get_line(struct rrr_gpio_ctx **ctx, int *value, const char *chip_path, unsigned int line_offset) {
	int ret = 0;

	struct rrr_gpio_device *device;

	if (*ctx == NULL) {
		if ((ret = __rrr_gpio_ctx_new(ctx)) != 0) {
			goto out;
		}
	}

	if ((device = __rrr_gpio_ctx_device_ensure (*ctx, chip_path)) == NULL) {
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_gpio_device_line_ensure(device, line_offset)) != 0) {
		goto out;
	}

	*value = gpiod_line_request_get_value(device->request, line_offset) == GPIOD_LINE_VALUE_ACTIVE ? 1 : 0;

	out:
	return ret;
}
