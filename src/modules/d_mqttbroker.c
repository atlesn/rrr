/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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
#include <strings.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "../lib/log.h"

#include "../lib/mqtt/mqtt_broker.h"
#include "../lib/mqtt/mqtt_common.h"
#include "../lib/mqtt/mqtt_session_ram.h"
#include "../lib/mqtt/mqtt_acl.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN 1883
#define RRR_MQTT_DEFAULT_SERVER_PORT_TLS 8883
#define RRR_MQTT_DEFAULT_SERVER_KEEP_ALIVE 30
#define RRR_MQTT_CLIENT_STATS_INTERVAL_MS 1000

struct mqtt_broker_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_fifo_buffer local_buffer;
	struct rrr_mqtt_broker_data *mqtt_broker_data;
	rrr_setting_uint server_port_plain;
	rrr_setting_uint server_port_tls;
	rrr_setting_uint max_keep_alive;
	rrr_setting_uint retry_interval;
	rrr_setting_uint close_wait_time;
	char *password_file;
	char *acl_file;
	char *permission_name;

	int do_require_authentication;
	int do_disconnect_on_v31_publish_deny;
	struct rrr_mqtt_acl acl;

	int do_transport_plain;
	int do_transport_tls;

	struct rrr_net_transport_config net_transport_config;
};

static void mqttbroker_data_cleanup(void *arg) {
	struct mqtt_broker_data *data = arg;
	rrr_fifo_buffer_clear(&data->local_buffer);
	RRR_FREE_IF_NOT_NULL(data->password_file);
	RRR_FREE_IF_NOT_NULL(data->acl_file);
	RRR_FREE_IF_NOT_NULL(data->permission_name);
	rrr_mqtt_acl_entry_collection_clear(&data->acl);
	rrr_net_transport_config_cleanup(&data->net_transport_config);
}

static int mqttbroker_data_init (
		struct mqtt_broker_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	data->thread_data = thread_data;

	ret |= rrr_fifo_buffer_init(&data->local_buffer);

	if (ret != 0) {
		RRR_MSG_0("Could not initialize fifo buffer in mqtt broker data_init\n");
		goto out;
	}

	out:
	if (ret != 0) {
		mqttbroker_data_cleanup(data);
	}

	return ret;
}

// TODO : Provide more configuration arguments
static int mqttbroker_parse_config (struct mqtt_broker_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT("mqtt_broker_port", server_port_plain, RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT("mqtt_broker_port_tls", server_port_tls, RRR_MQTT_DEFAULT_SERVER_PORT_TLS);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_broker_max_keep_alive", max_keep_alive, RRR_MQTT_DEFAULT_SERVER_KEEP_ALIVE);
	if (data->max_keep_alive > 0xffff) {
		RRR_MSG_0("mqtt_broker_max_keep_alive was too big for instance %s, max is 65535\n", config->name);
		ret = 1;
		goto out;
	}
	if (data->max_keep_alive < 1) {
		RRR_MSG_0("mqtt_broker_max_keep_alive was too small for instance %s, min is 1\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_broker_retry_interval", retry_interval, 1);
	if (data->retry_interval > 0xffff) {
		RRR_MSG_0("mqtt_broker_retry_interval was too big for instance %s, max is 65535\n", config->name);
		ret = 1;
		goto out;
	}
	if (data->retry_interval < 1) {
		RRR_MSG_0("mqtt_broker_retry_interval was too small for instance %s, min is 1\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_broker_close_wait_time", close_wait_time, 1);
	if (data->close_wait_time > 0xffff) {
		RRR_MSG_0("mqtt_broker_close_wait_time was too big for instance %s, max is 65535\n", config->name);
		ret = 1;
		goto out;
	}
	if (data->close_wait_time < 1) {
		RRR_MSG_0("mqtt_broker_close_wait_time was too small for instance %s, min is 1\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_broker_password_file", password_file);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_broker_permission_name", permission_name);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_broker_acl_file", acl_file);

	if (data->permission_name == NULL || *(data->permission_name) == '\0') {
		RRR_FREE_IF_NOT_NULL(data->permission_name);
		if ((data->permission_name = strdup("mqtt")) == NULL) {
			RRR_MSG_0("Could not allocate memory for permission name in mqttbroker_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_broker_require_authentication", do_require_authentication, 0);

	if (!rrr_instance_config_setting_exists(config, "mqtt_broker_require_authentication")) {
		if (data->password_file != NULL) {
			data->do_require_authentication = 1;
		}
		else {
			data->do_require_authentication = 0;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_broker_v31_disconnect_on_publish_deny", do_disconnect_on_v31_publish_deny, 0);

	if ((rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"mqtt_broker",
			1,
			RRR_NET_TRANSPORT_PLAIN
	)) != 0) {
		goto out;
	}

	data->do_transport_plain = (data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH ||
								data->net_transport_config.transport_type == RRR_NET_TRANSPORT_PLAIN
	);
	data->do_transport_tls = (	data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH ||
								data->net_transport_config.transport_type == RRR_NET_TRANSPORT_TLS
	);

	if (rrr_settings_exists(config->settings, "mqtt_broker_port") && !data->do_transport_plain) {
		RRR_MSG_0("mqtt_broker_port was set but plain transport method was not enabled in mqtt broker instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (rrr_settings_exists(config->settings, "mqtt_broker_port_tls") && !data->do_transport_tls) {
		RRR_MSG_0("mqtt_broker_port_tls was set but TLS transport method was not enabled in mqtt broker instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// We require certificate for listening
	if (data->net_transport_config.tls_certificate_file == NULL && data->do_transport_tls != 0) {
		RRR_MSG_0("TLS certificate not specified in mqtt_broker_tls_certificate_file but mqtt_transport_type was 'both' or 'tls' for mqtt broker instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void mqttbroker_update_stats (struct mqtt_broker_data *data, struct rrr_stats_instance *stats) {
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

static int mqttbroker_parse_acl (struct mqtt_broker_data *data) {
	int ret = 0;

	if (data->acl_file == NULL) {
		if (rrr_mqtt_acl_entry_collection_push_allow_all(&data->acl) != 0) {
			RRR_MSG_0("Could not push default entry in mqttbroker_parse_acl\n");
			ret = 1;
		}
		goto out;
	}

	if (*(data->acl_file) == '\0') {
		RRR_MSG_0("ACL filename was empty\n");
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_acl_entry_collection_populate_from_file(&data->acl, data->acl_file) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_mqttbroker (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct mqtt_broker_data *data = thread_data->private_data = thread_data->private_memory;

	int init_ret = 0;
	if ((init_ret = mqttbroker_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initialize data in mqtt broker instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_DBG_1 ("mqtt broker thread data is %p\n", thread_data);

	pthread_cleanup_push(mqttbroker_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (mqttbroker_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for mqtt broker instance '%s'\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (mqttbroker_parse_acl(data) != 0) {
		RRR_MSG_0("ACL file parse failed for mqtt broker instance '%s'\n", INSTANCE_D_NAME(thread_data));
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
			data->password_file,
			data->permission_name,
			&data->acl,
			data->do_require_authentication,
			data->do_disconnect_on_v31_publish_deny,
			rrr_mqtt_session_collection_ram_new,
			NULL
	) != 0) {
		RRR_MSG_0("Could not create new mqtt broker\n");
		goto out_message;
	}

	pthread_cleanup_push(rrr_mqtt_broker_destroy_void, data->mqtt_broker_data);
	pthread_cleanup_push(rrr_mqtt_broker_notify_pthread_cancel_void, data->mqtt_broker_data);

	RRR_DBG_1 ("mqtt broker started thread %p\n", thread_data);

	int listen_handle_plain = 0;
	int listen_handle_tls = 0;

	if (data->do_transport_plain) {
		RRR_DBG_1("MQTT broker instance %s starting plain listening on port %i\n",
				INSTANCE_D_NAME(thread_data), data->server_port_plain);

		// We're not allowed to pass in TLS parameters when starting plain mode,
		// create temporary config struct with TLS parameters set to NULL
		struct rrr_net_transport_config net_transport_config_tmp = {
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_PLAIN
		};

		// In case transport type is set to BOTH, we must reset
		if (rrr_mqtt_broker_listen_ipv4_and_ipv6 (
				&listen_handle_plain,
				data->mqtt_broker_data,
				&net_transport_config_tmp,
				data->server_port_plain
		) != 0) {
			RRR_MSG_0("Could not start plain network transport in mqtt broker instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_broker;
		}
	}
	if (data->do_transport_tls) {
		RRR_DBG_1("MQTT broker instance %s starting TLS listening on port %i\n",
				INSTANCE_D_NAME(thread_data), data->server_port_tls);

		// In case transport type is set to BOTH, we set it to TLS
		struct rrr_net_transport_config net_transport_config_tmp = data->net_transport_config;

		// Only change temporary struct
		net_transport_config_tmp.transport_type = RRR_NET_TRANSPORT_TLS;

		if (rrr_mqtt_broker_listen_ipv4_and_ipv6 (
				&listen_handle_plain,
				data->mqtt_broker_data,
				&net_transport_config_tmp, // <-- Pass in *temporary* struct
				data->server_port_tls
		) != 0) {
			RRR_MSG_0("Could not start tls network transport in mqtt broker instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_broker;
		}
	}

	// DO NOT use signed, let it overflow
	unsigned long int consecutive_nothing_happened = 0;

	uint64_t prev_stats_time = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		uint64_t time_now = rrr_time_get_64();
		rrr_thread_update_watchdog_time(thread_data->thread);

		int plain_something_happened = 0;
		int tls_something_happened = 0;

		if (listen_handle_plain) {
			if (rrr_mqtt_broker_synchronized_tick(&plain_something_happened, data->mqtt_broker_data, listen_handle_plain) != 0) {
				RRR_MSG_ERR("Error from MQTT broker while running plain transport tasks\n");
				break;
			}
		}
		if (listen_handle_tls) {
			if (rrr_mqtt_broker_synchronized_tick(&tls_something_happened, data->mqtt_broker_data, listen_handle_tls) != 0) {
				RRR_MSG_ERR("Error from MQTT broker while running TLS transport tasks\n");
				break;
			}
		}

		if (plain_something_happened + tls_something_happened == 0) {
			consecutive_nothing_happened++;
		}
		else {
			consecutive_nothing_happened = 0;
		}

		if (consecutive_nothing_happened > 5000) {
//			printf("Broker long sleep %lu\n", consecutive_nothing_happened);
			rrr_posix_usleep(50000); // 50 ms
		}
		if (consecutive_nothing_happened > 50) {
//			printf("Broker short sleep %lu\n", consecutive_nothing_happened);
			rrr_posix_usleep(2000); // 2ms
		}

		if (time_now > (prev_stats_time + RRR_MQTT_CLIENT_STATS_INTERVAL_MS * 1000)) {
			mqttbroker_update_stats(data, INSTANCE_D_STATS(thread_data));
			prev_stats_time = rrr_time_get_64();
		}
	}

	// If clients run on the same machine, we hope they close the connection first
	// to await TCP timeout
	rrr_posix_usleep(500000); // 500 ms

	out_destroy_broker:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);

	out_message:
		RRR_DBG_1 ("Thread mqtt broker %p exiting\n", thread_data->thread);
		pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mqttbroker,
		NULL,
		NULL,
		NULL,
		NULL,
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

