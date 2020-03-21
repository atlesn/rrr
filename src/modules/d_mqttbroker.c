/*

Read Route Record

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "../lib/mqtt_broker.h"
#include "../lib/mqtt_common.h"
#include "../lib/mqtt_session_ram.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/ip.h"
#include "../lib/stats_instance.h"
#include "../global.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT 1883
#define RRR_MQTT_DEFAULT_SERVER_KEEP_ALIVE 30
#define RRR_MQTT_CLIENT_STATS_INTERVAL_MS 1000

struct mqtt_broker_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_fifo_buffer local_buffer;
	struct rrr_mqtt_broker_data *mqtt_broker_data;
	rrr_setting_uint server_port;
	rrr_setting_uint max_keep_alive;
	rrr_setting_uint retry_interval;
	rrr_setting_uint close_wait_time;
};

static void data_cleanup(void *arg) {
	struct mqtt_broker_data *data = arg;
	rrr_fifo_buffer_invalidate(&data->local_buffer);
}

static int data_init (
		struct mqtt_broker_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	data->thread_data = thread_data;

	ret |= rrr_fifo_buffer_init(&data->local_buffer);

	if (ret != 0) {
		RRR_MSG_ERR("Could not initialize fifo buffer in mqtt broker data_init\n");
		goto out;
	}

	out:
	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

// TODO : Provide more configuration arguments
static int parse_config (struct mqtt_broker_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint mqtt_port = 0;
	rrr_setting_uint max_keep_alive = 0;
	rrr_setting_uint retry_interval = 0;
	rrr_setting_uint close_wait_time = 0;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_port, config, "mqtt_server_port")) == 0) {
		// OK
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mqtt_server_port setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		mqtt_port = RRR_MQTT_DEFAULT_SERVER_PORT;
		ret = 0;
	}
	data->server_port = mqtt_port;

	if ((ret = rrr_instance_config_read_unsigned_integer(&max_keep_alive, config, "mqtt_server_max_keep_alive")) == 0) {
		if (max_keep_alive > 0xffff) {
			RRR_MSG_ERR("mqtt_server_max_keep_alive was too big for instance %s, max is 65535\n", config->name);
			ret = 1;
			goto out;
		}
		if (max_keep_alive < 1) {
			RRR_MSG_ERR("mqtt_server_max_keep_alive was too small for instance %s, min is 1\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mqtt_server_max_keep_alive setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		max_keep_alive = RRR_MQTT_DEFAULT_SERVER_KEEP_ALIVE;
		ret = 0;
	}
	data->max_keep_alive = max_keep_alive;

	if ((ret = rrr_instance_config_read_unsigned_integer(&retry_interval, config, "mqtt_server_retry_interval")) == 0) {
		if (retry_interval > 0xffff) {
			RRR_MSG_ERR("mqtt_server_retry_interval was too big for instance %s, max is 65535\n", config->name);
			ret = 1;
			goto out;
		}
		if (retry_interval < 1) {
			RRR_MSG_ERR("mqtt_server_retry_interval was too small for instance %s, min is 1\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mqtt_server_retry_interval setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		retry_interval = 1;
		ret = 0;
	}
	data->retry_interval = retry_interval;

	if ((ret = rrr_instance_config_read_unsigned_integer(&close_wait_time, config, "mqtt_server_close_wait_time")) == 0) {
		if (close_wait_time > 0xffff) {
			RRR_MSG_ERR("mqtt_server_close_wait_time was too big for instance %s, max is 65535\n", config->name);
			ret = 1;
			goto out;
		}
		if (close_wait_time < 1) {
			RRR_MSG_ERR("mqtt_server_close_wait_time was too small for instance %s, min is 1\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing mqtt_server_close_wait_time setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		close_wait_time = 1;
		ret = 0;
	}
	data->close_wait_time = close_wait_time;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void update_stats (struct mqtt_broker_data *data, struct rrr_stats_instance *stats) {
	if (stats->stats_handle == 0) {
		return;
	}

	struct rrr_mqtt_broker_stats broker_stats;
	rrr_mqtt_broker_get_stats (&broker_stats, data->mqtt_broker_data);

	rrr_stats_instance_post_unsigned_base10_text(stats, "connections_active", 0, broker_stats.connections_active);
	rrr_stats_instance_post_unsigned_base10_text(stats, "sessions_in_memory", 0, broker_stats.session_stats.in_memory_sessions);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_connected", 0, broker_stats.total_connections_accepted);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_disconnected", 0, broker_stats.total_connections_closed);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_received", 0, broker_stats.session_stats.total_publish_received);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_not_forwarded", 0, broker_stats.session_stats.total_publish_not_forwarded);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_forwarded", 0, broker_stats.session_stats.total_publish_forwarded);

	// This will always be zero for the broker, nothing is delivered locally. Keep it here nevertheless to avoid accidently activating it.
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_delivered", 0, broker_stats.session_stats.total_publish_delivered);
}

static void *thread_entry_mqtt (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct mqtt_broker_data* data = thread_data->private_data = thread_data->private_memory;

	int init_ret = 0;
	if ((init_ret = data_init(data, thread_data)) != 0) {
		RRR_MSG_ERR("Could not initalize data in mqtt broker instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_DBG_1 ("mqtt broker thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Configuration parse failed for mqtt broker instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	struct rrr_mqtt_common_init_data init_data = {
			INSTANCE_D_NAME(thread_data),
			data->retry_interval * 1000 * 1000,
			data->close_wait_time * 1000 * 1000,
			RRR_MQTT_COMMON_MAX_CONNECTIONS
	};

	if (rrr_mqtt_broker_new (
			&data->mqtt_broker_data,
			&init_data,
			data->max_keep_alive,
			rrr_mqtt_session_collection_ram_new,
			NULL
		) != 0) {
		RRR_MSG_ERR("Could not create new mqtt broker\n");
		goto out_message;
	}

	pthread_cleanup_push(rrr_mqtt_broker_destroy_void, data->mqtt_broker_data);
	pthread_cleanup_push(rrr_mqtt_broker_notify_pthread_cancel_void, data->mqtt_broker_data);

	RRR_DBG_1 ("mqtt broker started thread %p\n", thread_data);

	if (rrr_mqtt_broker_listen_ipv4_and_ipv6(data->mqtt_broker_data, data->server_port) != 0) {
		RRR_MSG_ERR("Could not start network in mqtt broker instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_broker;
	}

	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	uint64_t prev_stats_time = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		uint64_t time_now = rrr_time_get_64();
		rrr_update_watchdog_time(thread_data->thread);

		if (rrr_mqtt_broker_synchronized_tick(data->mqtt_broker_data) != 0) {
			RRR_MSG_ERR("Error from MQTT broker while running tasks\n");
			break;
		}

		if (time_now > (prev_stats_time + RRR_MQTT_CLIENT_STATS_INTERVAL_MS * 1000)) {
			update_stats(data, stats);
			prev_stats_time = rrr_time_get_64();
		}

		usleep (5000); // 50 ms
	}

	// If clients run on the same machine, we hope they close the connection first
	// to await TCP timeout
	usleep(500000); // 500 ms

	out_destroy_broker:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);

	out_message:
		RRR_DBG_1 ("Thread mqtt broker %p exiting\n", thread_data->thread);
		pthread_cleanup_pop(1);
		RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
		pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mqtt,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "mqtt_broker";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_NETWORK;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	RRR_DBG_1 ("Destroy mqtt broker module\n");
}

