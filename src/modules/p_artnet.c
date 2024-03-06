/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/artnet/rrr_artnet.h"

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/array.h"

#define ARTNET_MAX_UNIVERSES 16
#define ARTNET_DEFAULT_UNIVERSES 1
#define ARTNET_DATA_TIMEOUT_S 10
#define ARTNET_DEFAULT_FADE_SPEED 5
#define ARTNET_MIN_FADE_SPEED 1
#define ARTNET_MAX_FADE_SPEED 10

#define ARTNET_TAG_CMD "artnet_cmd"
#define ARTNET_TAG_UNIVERSE "artnet_universe"
#define ARTNET_TAG_DMX_DATA "artnet_dmx_data"
#define ARTNET_TAG_DMX_CHANNEL "artnet_dmx_channel"
#define ARTNET_TAG_FADE_SPEED "artnet_fade_speed"

#define ARTNET_CMD_START "start"
#define ARTNET_CMD_STOP "stop"
#define ARTNET_CMD_SET "set"
#define ARTNET_CMD_FADE "fade"

struct artnet_universe {
	int active;
	uint64_t last_data_time;
};

struct artnet_data {
	struct rrr_instance_runtime_data *thread_data;
	rrr_setting_uint message_ttl_seconds;
	struct rrr_poll_helper_counters counters;
	struct rrr_artnet_node *node;

	rrr_setting_uint universes;
	rrr_setting_uint fade_speed;

	int do_demo;

	struct artnet_universe artnet_universe_states[ARTNET_MAX_UNIVERSES];
};

static int artnet_universe_new (struct artnet_universe **result) {
	int ret = 0;

	*result = NULL;

	struct artnet_universe *universe;

	if ((universe = rrr_allocate_zero (sizeof(*universe))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*result = universe;

	out:
	return ret;
}

static void artnet_universe_destroy (void *universe) {
	rrr_free(universe);
}

static int artnet_data_init (struct artnet_data *data, struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	if ((ret = rrr_artnet_node_new(&data->node)) != 0) {
		RRR_MSG_0("Failed to create artnet node in artnet instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out;
	}

	data->thread_data = thread_data;

	out:
	return ret;
}

static int artnet_universes_init (
		struct artnet_data *data
) {
	int ret = 0;

	for (uint8_t i = 0; i < data->universes; i++) {
		struct artnet_universe *universe;

		if ((ret = artnet_universe_new (&universe)) != 0) {
			goto out;
		}

		rrr_artnet_set_private_data (
				data->node,
				i,
				universe,
				artnet_universe_destroy
		);
	}

	out:
	return ret;
}

static void artnet_data_cleanup(void *arg) {
	struct artnet_data *data = arg;

	if (data->node != NULL) {
		rrr_artnet_node_destroy(data->node);
	}
}

static int artnet_process_cmd (
		struct artnet_data *data,
		const struct rrr_array *array
) {
	char *cmd = NULL;
	unsigned long long universe = 0;
	unsigned long long dmx_channel = 0;
	unsigned long long fade_speed = data->fade_speed;
	uint64_t dmx_count = 0;
	const struct rrr_type_value *dmx_data;

	struct artnet_universe *universe_data;
	const rrr_artnet_dmx_t *dmx_dummy;
	uint16_t dmx_count_max = 0;

	int ret = 0;

	if ((ret = rrr_array_get_value_str_by_tag (&cmd, array, ARTNET_TAG_CMD)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " ARTNET_TAG_CMD " in message to artnet instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	if (rrr_array_has_tag (array, ARTNET_TAG_UNIVERSE) && (ret = rrr_array_get_value_ull_by_tag (&universe, array, ARTNET_TAG_UNIVERSE)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " ARTNET_TAG_UNIVERSE " in message to artnet instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	if (rrr_array_has_tag (array, ARTNET_TAG_DMX_CHANNEL) && (ret = rrr_array_get_value_ull_by_tag (&dmx_channel, array, ARTNET_TAG_DMX_CHANNEL)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " ARTNET_TAG_DMX_CHANNEL " in message to artnet instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	if (rrr_array_has_tag (array, ARTNET_TAG_FADE_SPEED) && (ret = rrr_array_get_value_ull_by_tag (&fade_speed, array, ARTNET_TAG_FADE_SPEED)) != 0) {
		RRR_MSG_0("Warning: Failed to get value " ARTNET_TAG_FADE_SPEED " in message to artnet instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 0;
		goto out;
	}

	RRR_DBG_3("artnet instance %s received command '%s' for universe %llu manipulate channel %llu fade speed %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			cmd,
			universe,
			dmx_channel,
			fade_speed
	);

	if (universe > ARTNET_MAX_UNIVERSES - 1) {
		RRR_MSG_0("Warning: Value " PRIu64 " in field " ARTNET_TAG_UNIVERSE " in message to artnet instance %s exceeds maximum of %u\n",
				universe, INSTANCE_D_NAME(data->thread_data), ARTNET_MAX_UNIVERSES - 1);
		ret = 0;
		goto out;
	}

	rrr_artnet_universe_get_dmx(&dmx_dummy, &dmx_count_max, data->node, (uint8_t) universe);
	rrr_artnet_universe_get_private_data ((void **) &universe_data, data->node, (uint8_t) universe);

	dmx_count = dmx_count_max;

	if ((dmx_data = rrr_array_value_get_by_tag_const (array, ARTNET_TAG_DMX_DATA)) != NULL) {
		if (dmx_data->total_stored_length == 0) {
			RRR_DBG_3("DMX data length is zero in field " ARTNET_TAG_DMX_DATA " in message to artnet instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			data = NULL;
		}
		else {
			if (dmx_data->total_stored_length > dmx_count_max) {
				RRR_MSG_0("Warning: DMX length %" PRIrrrl " exceeds maximum of %u in field " ARTNET_TAG_DMX_DATA " in message to artnet instance %s\n",
						dmx_data->total_stored_length, dmx_count_max, INSTANCE_D_NAME(data->thread_data));
				goto out;
			}
			dmx_count = (uint16_t) dmx_data->total_stored_length;
		}
	}

	if (rrr_artnet_universe_check_range(data->node, (uint8_t) universe, dmx_channel, dmx_count) != 0) {
		RRR_MSG_0("Warning: Range check failed for fields " ARTNET_TAG_DMX_CHANNEL " and/or " ARTNET_TAG_DMX_DATA " in message to artnet instance %s. Maximum number of channels is %u.\n",
				INSTANCE_D_NAME(data->thread_data), dmx_count_max);
		goto out;
	}

	if (fade_speed < ARTNET_MIN_FADE_SPEED || fade_speed > ARTNET_MAX_FADE_SPEED) {
		RRR_MSG_0("Warning: Range check failed for field " ARTNET_TAG_FADE_SPEED " in artnet instance %s. Valid range is %i-%i.\n",
				INSTANCE_D_NAME(data->thread_data), ARTNET_MIN_FADE_SPEED, ARTNET_MAX_FADE_SPEED);
		goto out;
	}

	if (strcmp(cmd, ARTNET_CMD_START) == 0) {
		rrr_artnet_universe_set_mode(data->node, (uint8_t) universe, RRR_ARTNET_MODE_MANAGED);
		universe_data->active = 1;
	}
	else if (strcmp(cmd, ARTNET_CMD_STOP) == 0) {
		rrr_artnet_universe_set_mode(data->node, (uint8_t) universe, RRR_ARTNET_MODE_STOPPED);
		universe_data->active = 0;
	}
	else if (strcmp(cmd, ARTNET_CMD_SET) == 0) {
		if (dmx_data) {
			rrr_artnet_universe_set_dmx_abs_raw(data->node, (uint8_t) universe, (uint16_t) dmx_channel, (uint16_t) dmx_count, (rrr_artnet_dmx_t *) dmx_data->data);
		}
		else {
			rrr_artnet_universe_set_dmx_abs(data->node, (uint8_t) universe, (uint16_t) dmx_channel, (uint16_t) dmx_count, 0);
		}
		universe_data->active = 1;
	}
	else if (strcmp(cmd, ARTNET_CMD_FADE) == 0) {
		if (dmx_data) {
			rrr_artnet_universe_set_dmx_fade_raw(data->node, (uint8_t) universe, (uint16_t) dmx_channel, (uint16_t) dmx_count, (uint8_t) fade_speed, (rrr_artnet_dmx_t *) dmx_data->data);
		}
		else {
			rrr_artnet_universe_set_dmx_fade(data->node, (uint8_t) universe, (uint16_t) dmx_channel, (uint16_t) dmx_count, (uint8_t) fade_speed, 0);
		}
		universe_data->active = 1;
	}
	else {
		RRR_MSG_0("Warning: Invalid value %s for field " ARTNET_TAG_CMD " in message to artnet instance %s\n",
				cmd, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	universe_data->last_data_time = rrr_time_get_64();

	out:
	RRR_FREE_IF_NOT_NULL(cmd);
	return ret;
}

static int artnet_poll_callback (RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct artnet_data *data = thread_data->private_data;

	const struct rrr_msg_msg *message = entry->message;
	struct rrr_array array_tmp = {0};

	int ret = 0;

	if (!MSG_IS_ARRAY(message)) {
		RRR_MSG_0("Warning: artnet instance %s received a message which was not an array message. Dropping it.\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	uint16_t array_version;
	if ((ret = rrr_array_message_append_to_array (
			&array_version,
			&array_tmp,
			message
	)) != 0) {
		RRR_MSG_0("Failed to get array from message in artnet instance %s.\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_DBG_2("artnet instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	if ((ret = artnet_process_cmd (data, &array_tmp)) != 0) {
		goto out;
	}

	out:
	RRR_POLL_HELPER_COUNTERS_UPDATE_POLLED(data);
	rrr_msg_holder_unlock(entry);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int artnet_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(data);

	return rrr_poll_do_poll_delete (amount, thread_data, artnet_poll_callback);
}

static int artnet_parse_config (struct artnet_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("artnet_universes", universes, ARTNET_DEFAULT_UNIVERSES);

	if (data->universes > ARTNET_MAX_UNIVERSES) {
		RRR_MSG_0("Setting artnet_universes out of range in artnet instance %s. Valid range is 0-16.\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("artnet_fade_speed", fade_speed, ARTNET_DEFAULT_FADE_SPEED);

	if (data->fade_speed < ARTNET_MIN_FADE_SPEED || data->fade_speed > ARTNET_MAX_FADE_SPEED) {
		RRR_MSG_0("Setting artnet_fade_speed out of range in artnet instance %s. Valid range is 5-1000.\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("artnet_demo", do_demo, 1 /* Default is enabled */);

	out:
	return ret;
}

static void artnet_failure_callback (void *arg) {
	struct artnet_data *data = arg;

	RRR_MSG_0("An artnet library function failed in artnet instance %s\n", INSTANCE_D_NAME(data->thread_data));

	rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
}

static void artnet_incorrect_mode_callback (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		enum rrr_artnet_mode current_mode,
		enum rrr_artnet_mode required_mode
) {
	if (current_mode == RRR_ARTNET_MODE_STOPPED) {
		/* We will not switch mode to managed until a start command is received */
		return;
	}
	rrr_artnet_universe_set_mode(node, universe_i, required_mode);
}

#define ARTNET_ITERATE_STOP RRR_READ_SOFT_ERROR

static int artnet_periodic_universe_cb (
		uint8_t universe_i,
		enum rrr_artnet_mode mode,
		void *private_data,
		void *private_arg
) {
	struct artnet_universe *universe = private_data;
	struct artnet_data *data = private_arg;

	if (universe_i >= data->universes) {
		assert(universe == NULL);
		return ARTNET_ITERATE_STOP;
	}

	assert(universe != NULL);

	const uint64_t data_timeout_limit = rrr_time_get_64() - ARTNET_DATA_TIMEOUT_S * 1000 * 1000;


	if (universe->active) {
		if (universe->last_data_time < data_timeout_limit) {
			RRR_DBG_1("artnet instance %s data timeout after %u seconds for universe %u\n",
					INSTANCE_D_NAME(data->thread_data), ARTNET_DATA_TIMEOUT_S, universe_i);
			universe->active = 0;
		}
		else if (mode != RRR_ARTNET_MODE_MANAGED) {
			RRR_DBG_1("artnet instance %s set mode MANAGED on universe %u\n",
					INSTANCE_D_NAME(data->thread_data), universe_i);
			rrr_artnet_universe_set_mode(data->node, universe_i, RRR_ARTNET_MODE_MANAGED);
		}
	}

	// Note : Trap any setting of active to 0 from above code
	if (!universe->active) {
		if (data->do_demo && mode != RRR_ARTNET_MODE_DEMO) {
			RRR_DBG_1("artnet instance %s set mode DEMO on universe %u\n",
					INSTANCE_D_NAME(data->thread_data), universe_i);
			rrr_artnet_universe_set_mode(data->node, universe_i, RRR_ARTNET_MODE_DEMO);
		}
		else if (mode != RRR_ARTNET_MODE_IDLE && mode != RRR_ARTNET_MODE_STOPPED) {
			RRR_DBG_1("artnet instance %s set mode STOPPED on universe %u\n",
					INSTANCE_D_NAME(data->thread_data), universe_i);
			rrr_artnet_universe_set_mode(data->node, universe_i, RRR_ARTNET_MODE_STOPPED);
		}
	}

	return 0;
}

static int artnet_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data;

	int ret = 0;

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		ret = RRR_EVENT_EXIT;
		goto out;
	}
	rrr_thread_watchdog_time_update(thread);

	if ((ret = rrr_artnet_universe_iterate (
			data->node,
			artnet_periodic_universe_cb,
			data
	)) != 0) {
		if (ret != ARTNET_ITERATE_STOP) {
			ret = RRR_EVENT_EXIT;
			goto out;
		}
		ret = 0;
	}

	out:
	return ret;
}

static int artnet_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("artnet thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (artnet_data_init(data, thread_data) != 0) {
		goto out_message;
	}

	if (artnet_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("artnet instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	if (rrr_artnet_events_register (
			data->node,
			INSTANCE_D_EVENTS(thread_data),
			artnet_failure_callback,
			artnet_incorrect_mode_callback,
			data
	) != 0) {
		RRR_MSG_0("Failed to register artnet events in artnet instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_cleanup;
	}

	rrr_artnet_set_fade_speed(data->node, (uint8_t) data->fade_speed);

	if (artnet_universes_init (data) != 0) {
		RRR_MSG_0("Failed to initialize universes in artnet instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_cleanup;
	}

	rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000, // 1 second
			artnet_periodic
	);

	return 0;

	out_cleanup:
	artnet_data_cleanup(data);
	out_message:
	return 1;
}

void artnet_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct artnet_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	RRR_DBG_1 ("Thread artnet %p exiting\n", thread);

	artnet_data_cleanup(data);

	rrr_event_receiver_reset(INSTANCE_D_EVENTS_H(thread_data));

	*deinit_complete = 1;
}

struct rrr_instance_event_functions event_functions = {
	artnet_event_broker_data_available
};

static const char *module_name = "artnet";

__attribute__((constructor)) void construct(void) {
}

void load(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->event_functions = event_functions;
	data->init = artnet_init;
	data->deinit = artnet_deinit;
}

void unload(void) {
	RRR_DBG_1 ("Destroy artnet module\n");
}

