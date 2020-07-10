/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include "../lib/http/http_session.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/log.h"
#include "../lib/array.h"

#define RRR_HTTPSERVER_DEFAULT_PORT_PLAIN		80
#define RRR_HTTPSERVER_DEFAULT_PORT_TLS			443

struct httpserver_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_net_transport_config net_transport_config;

	rrr_setting_uint port_plain;
	rrr_setting_uint port_tls;
};

static void httpserver_data_cleanup(void *arg) {
	struct httpserver_data *data = arg;
	rrr_net_transport_config_cleanup(&data->net_transport_config);
}

static int httpserver_data_init (
		struct httpserver_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	goto out;
//	out_cleanup_data:
//		httpserver_data_cleanup(data);
	out:
		return ret;
}

static int httpserver_parse_config (
		struct httpserver_data *data,
		struct rrr_instance_config *config
) {
	int ret = 0;

	if (rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"http_server",
			1,
			RRR_NET_TRANSPORT_PLAIN
	) != 0) {
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_port_tls", port_tls, RRR_HTTPSERVER_DEFAULT_PORT_TLS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_port_plain", port_plain, RRR_HTTPSERVER_DEFAULT_PORT_PLAIN);

	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_server_port_tls",
			if (data->net_transport_config.transport_type != RRR_NET_TRANSPORT_TLS &&
				data->net_transport_config.transport_type != RRR_NET_TRANSPORT_BOTH
			) {
				RRR_MSG_0("Setting http_server_port_tls is set for httpserver instance %s but TLS transport is not configured.\n",
						config->name);
				ret = 1;
				goto out;
			}
	);

	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_server_port_plain",
			if (data->net_transport_config.transport_type != RRR_NET_TRANSPORT_PLAIN &&
				data->net_transport_config.transport_type != RRR_NET_TRANSPORT_BOTH
			) {
				RRR_MSG_0("Setting http_server_port_plain is set for httpserver instance %s but plain transport is not configured.\n",
						config->name);
				ret = 1;
				goto out;
			}
	);

	out:
	return ret;
}

static void *thread_entry_httpserver (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct httpserver_data *data = thread_data->private_data = thread_data->private_memory;

	if (httpserver_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in httpserver instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpserver thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(httpserver_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (httpserver_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("httpserver started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		rrr_posix_usleep(150000);
	}

	out_message:
	RRR_DBG_1 ("Thread httpserver %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_httpserver,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "httpserver";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_SOURCE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy httpserver module\n");
}
