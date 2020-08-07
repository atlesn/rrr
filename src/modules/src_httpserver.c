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

#include "../lib/log.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/map.h"
#include "../lib/http/http_session.h"
#include "../lib/http/http_server.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip_defines.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
//#include "../ip_util.h"

#define RRR_HTTPSERVER_DEFAULT_PORT_PLAIN		80
#define RRR_HTTPSERVER_DEFAULT_PORT_TLS			443

struct httpserver_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_net_transport_config net_transport_config;

	rrr_setting_uint port_plain;
	rrr_setting_uint port_tls;

	struct rrr_map http_fields_accept;

	int do_http_fields_accept_any;
	int do_allow_empty_messages;
};

static void httpserver_data_cleanup(void *arg) {
	struct httpserver_data *data = arg;
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_map_clear(&data->http_fields_accept);
}

static int httpserver_data_init (
		struct httpserver_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

static int httpserver_parse_config (
		struct httpserver_data *data,
		struct rrr_instance_config_data *config
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

	if ((ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->http_fields_accept, config, "http_server_fields_accept", "->")) != 0) {
		RRR_MSG_0("Could not parse setting http_server_fields_accept for instance %s\n",
				config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_fields_accept_any", do_http_fields_accept_any, 0);

	if (RRR_MAP_COUNT(&data->http_fields_accept) > 0 && data->do_http_fields_accept_any != 0) {
		RRR_MSG_0("Setting http_server_fields_accept in instance %s was set while http_server_fields_accept_any was 'yes', this is an invalid configuration.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_allow_empty_messages", do_allow_empty_messages, 0);

	out:
	return ret;
}

static int httpserver_start_listening (struct httpserver_data *data, struct rrr_http_server *http_server) {
	int ret = 0;

	if (data->net_transport_config.transport_type == RRR_NET_TRANSPORT_PLAIN ||
		data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH
	) {
		if ((ret = rrr_http_server_start_plain(http_server, data->port_plain)) != 0) {
			RRR_MSG_0("Could not start listening in plain mode on port %u in httpserver instance %s\n",
					data->port_plain, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
	}

	if (data->net_transport_config.transport_type == RRR_NET_TRANSPORT_TLS ||
		data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH
	) {
		if ((ret = rrr_http_server_start_tls (
				http_server,
				data->port_tls,
				&data->net_transport_config,
				0
		)) != 0) {
			RRR_MSG_0("Could not start listening in TLS mode on port %u in httpserver instance %s\n",
					data->port_tls, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

struct httpserver_worker_process_field_callback {
	struct rrr_array *array;
	struct httpserver_data *parent_data;
};

static int httpserver_worker_process_field_callback (
		const struct rrr_http_field *field,
		void *arg
) {
	struct httpserver_worker_process_field_callback *callback_data = arg;

	int ret = RRR_HTTP_OK;

	struct rrr_type_value *value_tmp = NULL;
	int do_add_field = 0;
	const char *name_to_use = field->name;

	if (callback_data->parent_data->do_http_fields_accept_any) {
		do_add_field = 1;
	}
	else if (RRR_MAP_COUNT(&callback_data->parent_data->http_fields_accept) > 0) {
		RRR_MAP_ITERATE_BEGIN(&callback_data->parent_data->http_fields_accept);
			if (strcmp(node_tag, field->name) == 0) {
				do_add_field = 1;
				if (node->value != NULL && node->value_size > 0 && *(node->value) != '\0') {
					// Do name translation
					name_to_use = node->value;
					RRR_LL_ITERATE_LAST();
				}
			}
		RRR_MAP_ITERATE_END();
	}

	if (do_add_field != 1) {
		goto out;
	}

	if (field->content_type != NULL && strcmp(field->content_type, RRR_MESSAGE_MIME_TYPE) == 0) {
		if (rrr_type_value_allocate_and_import_raw (
				&value_tmp,
				&rrr_type_definition_msg,
				field->value,
				field->value + field->value_size,
				strlen(name_to_use),
				name_to_use,
				field->value_size,
				1 // <-- We only support one message per field
		) != 0) {
			RRR_MSG_0("Failed to import RRR message from HTTP field\n");
			ret = 1;
			goto out;
		}

		RRR_LL_APPEND(callback_data->array, value_tmp);
		value_tmp = NULL;
	}
	else if (field->value != NULL && field->value_size > 0) {
		ret = rrr_array_push_value_str_with_tag_with_size (
				callback_data->array,
				name_to_use,
				field->value,
				field->value_size
		);
	}
	else {
		ret = rrr_array_push_value_u64_with_tag (
				callback_data->array,
				name_to_use,
				0
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Error while pushing field to array in __rrr_http_server_worker_process_field_callback\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	out:
	if (value_tmp != NULL) {
		rrr_type_value_destroy(value_tmp);
	}
	return ret;
}

struct httpserver_write_message_callback_data {
	struct rrr_array *array;
};

// NOTE : Worker thread CTX in httpserver_write_message_callback
static int httpserver_write_message_callback (
		struct rrr_msg_msg_holder *new_entry,
		void *arg
) {
	struct httpserver_write_message_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_msg_msg *new_message = NULL;

	if (RRR_LL_COUNT(callback_data->array) > 0) {
		ret = rrr_array_new_message_from_collection (
				&new_message,
				callback_data->array,
				rrr_time_get_64(),
				NULL,
				0
		);
	}
	else {
		ret = rrr_msg_msg_new_empty (
				&new_message,
				MSG_TYPE_MSG,
				MSG_CLASS_DATA,
				rrr_time_get_64(),
				0,
				0
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create message in httpserver_write_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	new_entry->message = new_message;
	new_entry->data_length = MSG_TOTAL_SIZE(new_message);
	new_message = NULL;

	out:
	rrr_msg_msg_holder_unlock(new_entry);
	return ret;
}

struct httpserver_receive_callback_data {
	struct httpserver_data *parent_data;
};

static int httpserver_receive_callback_options (
		const struct rrr_http_part *part,
		const char *data_ptr,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		struct httpserver_receive_callback_data *callback_data
) {
	(void)(part);
	(void)(data_ptr);
	(void)(sockaddr);
	(void)(socklen);
	(void)(callback_data);

	return RRR_HTTP_OK;
}

static int httpserver_receive_callback_get_post (
		const struct rrr_http_part *part,
		const char *data_ptr,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		struct httpserver_receive_callback_data *receive_callback_data
) {
	int ret = RRR_HTTP_OK;

	(void)(data_ptr);

	struct rrr_array array_tmp = {0};

	struct httpserver_worker_process_field_callback field_callback_data = {
			&array_tmp,
			receive_callback_data->parent_data
	};

	if ((ret = rrr_http_part_fields_iterate_const (
			part,
			httpserver_worker_process_field_callback,
			&field_callback_data
	)) != RRR_HTTP_OK) {
		goto out;
	}

	if (RRR_LL_COUNT(&array_tmp) == 0 && receive_callback_data->parent_data->do_allow_empty_messages == 0) {
		RRR_DBG_3("No data fields received from HTTP client, not creating RRR message\n");
		goto out;
	}

	struct httpserver_write_message_callback_data write_callback_data = {
			&array_tmp
	};

//	char buf[256];
//	rrr_ip_to_str(buf, sizeof(buf), (struct sockaddr *) sockaddr, socklen);
//	printf("http server write entry: %s family %i socklen %i\n", buf, sockaddr->sa_family, socklen);

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER(receive_callback_data->parent_data->thread_data),
			INSTANCE_D_HANDLE(receive_callback_data->parent_data->thread_data),
			sockaddr,
			socklen,
			RRR_IP_TCP,
			httpserver_write_message_callback,
			&write_callback_data
	)) != 0) {
		RRR_MSG_0("Error while saving message in httpserver_receive_callback\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

// NOTE : Worker thread CTX in httpserver_receive_callback
static int httpserver_receive_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct httpserver_receive_callback_data *receive_callback_data = arg;

	(void)(overshoot_bytes);
	(void)(response_part);

	if (request_part->request_method == RRR_HTTP_METHOD_OPTIONS) {
		return httpserver_receive_callback_options (
				request_part,
				data_ptr,
				sockaddr,
				socklen,
				receive_callback_data
		);
	}

	return httpserver_receive_callback_get_post (
			request_part,
			data_ptr,
			sockaddr,
			socklen,
			receive_callback_data
	);
}

static void *thread_entry_httpserver (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpserver_data *data = thread_data->private_data = thread_data->private_memory;

	if (httpserver_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in httpserver instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpserver thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(httpserver_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (httpserver_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("httpserver started thread %p\n", thread_data);

	struct rrr_http_server *http_server = NULL;

	if (rrr_http_server_new(&http_server) != 0) {
		RRR_MSG_0("Could not create HTTP server in httpserver instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	// TODO : There are occasional (?) reports from valgrind that http_server is
	//        not being freed upon program exit.

	pthread_cleanup_push(rrr_http_server_destroy_void, http_server);

	if (httpserver_start_listening(data, http_server) != 0) {
		goto out_cleanup_httpserver;
	}

	unsigned int accept_count_total = 0;
	uint64_t prev_stats_time = rrr_time_get_64();

	struct httpserver_receive_callback_data callback_data = {
			data
	};

	while (rrr_thread_check_encourage_stop(thread) != 1) {
		rrr_thread_update_watchdog_time(thread);

		int accept_count = 0;

		if (rrr_http_server_tick (
				&accept_count,
				http_server,
				httpserver_receive_callback,
				&callback_data
		) != 0) {
			RRR_MSG_0("Failure in main loop in httpserver instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (accept_count == 0) {
			rrr_posix_usleep(25000); // 25 ms
		}
		else {
			accept_count_total += accept_count;
		}

		uint64_t time_now = rrr_time_get_64();
		if (time_now > prev_stats_time + 1000000) {
			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 1, "accepted", accept_count_total);

			accept_count_total = 0;

			prev_stats_time = time_now;
		}
	}

	out_cleanup_httpserver:
	pthread_cleanup_pop(1);

	out_message:
	RRR_DBG_1 ("Thread httpserver %p exiting\n", thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config_data *config) {
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

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_SOURCE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy httpserver module\n");
}
