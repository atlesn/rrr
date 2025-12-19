/*

Read Route Record

Copyright (C) 2025 Atle Solbakken atle@goliathdns.no

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
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/rrr_strerror.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/cmodule/cmodule_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"
#include "../lib/rvalib.h"

#define RRR_CMODULE_NATIVE_CTX
#include "../cmodules/cmodule.h"

struct ffmpeg_data {
	struct rrr_instance_runtime_data *thread_data;

	char *source;
	char *filter_scale;
	char *output_directory;

	rrr_setting_uint duration_s;

	enum rrr_cmodule_process_mode process_mode;
};

static void ffmpeg_data_cleanup(void *arg) {
	struct ffmpeg_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->source);
	RRR_FREE_IF_NOT_NULL(data->filter_scale);
	RRR_FREE_IF_NOT_NULL(data->output_directory);
}

static int ffmpeg_data_init(struct ffmpeg_data *data, struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;
	data->thread_data = thread_data;
	if (ret != 0) {
		ffmpeg_data_cleanup(data);
	}
	return ret;
}

static int ffmpeg_parse_config (struct ffmpeg_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ffmpeg_source", source);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ffmpeg_filter_scale", filter_scale);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ffmpeg_output_directory", output_directory);

	if (data->output_directory == NULL || *(data->output_directory) == '\0') {
		RRR_MSG_0("ffmpeg_output_directory configuration parameter missing for ffmpeg instance %s\n", config->name_debug);
		ret = 1;
		goto out;
	}

	// Undocumented parameter for testing, stop processing after the given amount of seconds
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ffmpeg_duration_s", duration_s, 0);

	out:
	return ret;
}

static int ffmpeg_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	assert(0 && "Not implemented");
}

static int ffmpeg_tick_callback (RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS) {
	struct ffmpeg_data *data = private_arg;

	(void)(worker);
	(void)(data);

	*something_happened = 0;

	return 0;
}

static int ffmpeg_fork_init_wrapper (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
) {
	struct ffmpeg_data *data = private_arg;

	int ret = 0;

	if (data->process_mode == RRR_CMODULE_PROCESS_MODE_DEFAULT) {
		callbacks->process_callback = ffmpeg_process_callback;
		callbacks->process_callback_arg = data;
	}

	callbacks->custom_tick_callback = ffmpeg_tick_callback;
	callbacks->custom_tick_callback_arg = data;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		// Don't goto out, run cleanup functions
	}

	out:
	return ret;
}

static int ffmpeg_fork (void *arg) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ffmpeg_data *data = thread_data->private_data;

	int ret = 0;

	if (ffmpeg_parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}

	rrr_cmodule_helper_config(thread_data, data->process_mode);
	
	if (rrr_cmodule_helper_worker_forks_start_deferred_callback_set (
			thread_data,
			ffmpeg_fork_init_wrapper,
			data
	) != 0) {
		RRR_MSG_0("Error while starting ffmpeg worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}
	out:
	return ret;
}

static void *thread_entry_ffmpeg (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ffmpeg_data *data = thread_data->private_data = thread_data->private_memory;

	if (ffmpeg_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in ffmpeg instance %s\n", INSTANCE_D_NAME(thread_data));
		return NULL;
	}

	RRR_DBG_1 ("ffmpeg thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(ffmpeg_data_cleanup, data);

	data->process_mode = rrr_message_broker_senders_count (INSTANCE_D_BROKER_ARGS(thread_data)) > 0
		? RRR_CMODULE_PROCESS_MODE_DEFAULT
		: RRR_CMODULE_PROCESS_MODE_NONE;

	if (rrr_thread_start_condition_helper_fork(thread, ffmpeg_fork, thread_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("ffmpeg instance %s started thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data
	);

	out_message:
	RRR_DBG_1 ("ffmpeg instance %s stopping thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	pthread_cleanup_pop(1);

	return NULL;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_ffmpeg,
		NULL
};

static const char *module_name = "ffmpeg";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->event_functions = rrr_cmodule_helper_event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ffmpeg module\n");
}

