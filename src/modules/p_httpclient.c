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

#include "../lib/http/http_client.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/log.h"

#define RRR_HTTP_CLIENT_USER_AGENT "RRR/" PACKAGE_VERSION

struct httpclient_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_http_client_data http_client_data;
	struct rrr_ip_buffer_entry_collection defer_queue;

	int do_drop_on_error;
	rrr_setting_uint send_timeout_us;
};

static int httpclient_send_request_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	(void)(data);
	(void)(response_code);
	(void)(response_argument);
	(void)(chunk_idx);
	(void)(chunk_total);
	(void)(data_start);
	(void)(data_size);

	// Note : Don't mix up rrr_http_client_data and httpclient_data

	struct httpclient_data *httpclient_data = arg;

	int ret = RRR_HTTP_OK;

	if (response_code < 200 || response_code > 299) {
		RRR_BUG("BUG: Invalid response %i propagated from http framework to httpclient module\n", response_code);
	}

	RRR_DBG_1("HTTP response from server in httpclient instance %s: %i %s\n",
			INSTANCE_D_NAME(httpclient_data->thread_data),
			response_code,
			(response_argument != NULL ? response_argument : "(no response string)")
	);

	return ret;
}

static int httpclient_send_request_locked (
		struct httpclient_data *data,
		struct rrr_ip_buffer_entry *entry
) {
	struct rrr_message *message = entry->message;

	int ret = RRR_HTTP_OK;

	RRR_DBG_3("httpclient instance %s sending message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(data->thread_data), message->timestamp);

	(void)(message);

	if (data->send_timeout_us != 0) {
		if (rrr_time_get_64() > entry->send_time + data->send_timeout_us) {
			RRR_DBG_1("Send timeout for message in httpclient instance %s, dropping it.\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	}

	if ((ret = rrr_http_client_send_request (
			&data->http_client_data,
			httpclient_send_request_callback,
			data
	)) != 0) {
		RRR_MSG_0("Error while sending HTTP request in httpclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));

		if (data->do_drop_on_error) {
			RRR_DBG_1("Dropping message per configuration after error in httpclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_OK;
		}

		goto out;
	}

	out:
	return ret;
}

static int httpclient_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
//	printf ("httpclient got entry %p\n", entry);

	struct httpclient_data *data = thread_data->private_data;
	struct rrr_message *message = entry->message;

	RRR_DBG_3("httpclient instance %s received message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	// Important : Set send_time for correct timeout behavior
	entry->send_time = rrr_time_get_64();

	int ret = RRR_FIFO_OK;

	if ((ret = httpclient_send_request_locked(data, entry)) != 0) {
		if (ret == RRR_HTTP_SOFT_ERROR) {
			RRR_MSG_0("Soft error while sending message in httpclient instance %s, deferring message\n",
					INSTANCE_D_NAME(thread_data));
			ret = 0;
			goto out_defer;
		}
		RRR_MSG_0("Hard error while sending message in httpclient instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	goto out;
	out_defer:
		rrr_ip_buffer_entry_incref_while_locked(entry);
		RRR_LL_APPEND(&data->defer_queue, entry);
		rrr_ip_buffer_entry_unlock(entry);
		return RRR_FIFO_SEARCH_STOP;
	out:
		rrr_ip_buffer_entry_unlock(entry);
		return ret;
}

static void httpclient_data_cleanup(void *arg) {
	struct httpclient_data *data = arg;
	rrr_http_client_data_cleanup(&data->http_client_data);
	rrr_ip_buffer_entry_collection_clear(&data->defer_queue);
}

static int httpclient_data_init (
		struct httpclient_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	if ((ret = rrr_http_client_data_init(&data->http_client_data, RRR_HTTP_CLIENT_USER_AGENT)) != 0) {
		RRR_MSG_0("Could not initialize httpclient data in httpclient_data_init\n");
		ret = 1;
		goto out;
	}

	goto out;
//	out_cleanup_data:
//		httpclient_data_cleanup(data);
	out:
		return ret;
}

static int httpclient_parse_config (
		struct httpclient_data *data,
		struct rrr_instance_config *config
) {
	int ret = 0;

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_endpoint", http_client_data.endpoint);
	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_server", http_client_data.server);

	if (data->http_client_data.server == NULL || *(data->http_client_data.server) == '\0') {
		RRR_MSG_0("http_server configuration parameter missing for httpclient instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("http_drop_on_error", do_drop_on_error, 0);

	RRR_SETTINGS_PARSE_OPTIONAL_UNSIGNED("http_send_timeout_ms", send_timeout_us, 0);
	// Remember to mulitply to get useconds. Zero means no timeout.
	data->send_timeout_us *= 1000;

	out:
	return ret;
}

static void *thread_entry_httpclient (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll;

	if (httpclient_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initalize thread_data in httpclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpclient thread thread_data is %p\n", thread_data);

	rrr_poll_collection_init(&poll);
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll);
	pthread_cleanup_push(httpclient_data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (httpclient_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders (&poll, thread_data);

	RRR_DBG_1 ("httpclient started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		if (RRR_LL_COUNT(&data->defer_queue) > 0) {
			int ret_tmp = RRR_HTTP_OK;

			RRR_LL_ITERATE_BEGIN(&data->defer_queue, struct rrr_ip_buffer_entry);
				rrr_ip_buffer_entry_lock(node);
				if ((ret_tmp = httpclient_send_request_locked(data, node)) != RRR_HTTP_OK) {
					if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
						// Let soft error propagate
					}
					else {
						RRR_MSG_0("Hard error while iterating defer queue in httpclient instance %s\n",
								INSTANCE_D_NAME(thread_data));
						ret_tmp = RRR_HTTP_HARD_ERROR;
					}
					RRR_LL_ITERATE_LAST(); // Don't break, unlock first
				}
				else {
					RRR_LL_ITERATE_SET_DESTROY();
				}
				rrr_ip_buffer_entry_unlock(node);
			RRR_LL_ITERATE_END_CHECK_DESTROY(&data->defer_queue, 0; rrr_ip_buffer_entry_decref(node));

			if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
				rrr_posix_usleep(500000); // 500ms to avoid spamming server when there are errors
			}
		}
		else {
			if (rrr_poll_do_poll_delete (thread_data, &poll, httpclient_poll_callback, 50) != 0) {
				RRR_MSG_ERR("Error while polling in httpclient instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}
	}

	out_message:
	RRR_DBG_1 ("Thread httpclient %p exiting\n", thread_data->thread);

	//pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_httpclient,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "httpclient";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy httpclient module\n");
}

