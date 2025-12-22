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
#include "../lib/messages/msg_addr.h"
#include "../lib/ip/ip.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/cmodule/cmodule_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/posix.h"
#include "../lib/rvalib.h"
#include "../lib/array.h"

#define RRR_CMODULE_NATIVE_CTX
#include "../cmodules/cmodule.h"

enum ffmpeg_filename_format_t {
	FFMPEG_FILENAME_FORMAT_COUNTER,
	FFMPEG_FILENAME_FORMAT_TIMESTAMP
};

struct ffmpeg_data {
	struct rrr_instance_runtime_data *thread_data;

	char *source;
	char *filter_scale;
	char *output_directory;
	char *filename_format_str;

	rrr_setting_uint duration_s;
	rrr_setting_uint rounds;
	int report_messages;

	enum rrr_cmodule_process_mode process_mode;
	enum ffmpeg_filename_format_t filename_format;
};

enum ffmpeg_thread_index {
	THREAD_READER,
	THREAD_DECODER,
	THREAD_ENCODER,
	THREAD_COUNT
};

struct ffmpeg_worker_data {
	volatile int stop_now;
	volatile int thread_exited;
	volatile int flush_now;
	struct ffmpeg_data *ffmpeg_data;
        struct rrr_cmodule_worker *worker;
	RVASharedContext shctx;
	RVAInputContext ictx;
	RVAReaderContext rctx;
	RVADecoderContext dctx;
	RVAGeneratorContext gctx;
	RVAEncoderContext ectx;
	RVAThreadContext threads[THREAD_COUNT];
};

static char ffmpeg_log_prefix[512] = {'f', 'f', 'm', 'p', 'e', 'g', '\0'};
static enum ffmpeg_filename_format_t ffmpeg_filename_format = FFMPEG_FILENAME_FORMAT_COUNTER;
static char ffmpeg_logbuf[1024];
static size_t ffmpeg_logbuf_pos;
static pthread_mutex_t ffmpeg_logbuf_lock = PTHREAD_MUTEX_INITIALIZER;

static void ffmpeg_data_cleanup(void *arg) {
	struct ffmpeg_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->source);
	RRR_FREE_IF_NOT_NULL(data->filter_scale);
	RRR_FREE_IF_NOT_NULL(data->output_directory);
	RRR_FREE_IF_NOT_NULL(data->filename_format_str);
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
		RRR_MSG_0("ffmpeg_output_directory configuration parameter missing for ffmpeg instance %s\n",
			config->name_debug);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ffmpeg_filename_format", filename_format_str);

	if (data->filename_format_str != NULL && *(data->filename_format_str) != '\0') {
		if (strcmp(data->filename_format_str, "counter") == 0) {
			data->filename_format = FFMPEG_FILENAME_FORMAT_COUNTER;
		}
		else if (strcmp(data->filename_format_str, "timestamp") == 0) {
			data->filename_format = FFMPEG_FILENAME_FORMAT_TIMESTAMP;
		}
		else {
			RRR_MSG_0("Unknown value '%s' for ffmpeg_filename_format for ffmpeg instance %s\n",
				data->filename_format_str, config->name_debug);
			ret = 1;
			goto out;
		}
	}
	else {
		data->filename_format = FFMPEG_FILENAME_FORMAT_COUNTER;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ffmpeg_duration_s", duration_s, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ffmpeg_rounds", rounds, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ffmpeg_report_messages", report_messages, 0);

	out:
	return ret;
}

static int ffmpeg_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	assert(0 && "Not implemented");
}

static int ffmpeg_tick_callback (RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS) {
	struct ffmpeg_worker_data *data = private_arg;

	(void)(worker);
	(void)(data);

	int done = 0;

	*something_happened = 0;

	if (rva_tick(&done, data->threads, THREAD_COUNT, &data->stop_now, &data->thread_exited) != 0)
		return 1;
	
	if (done) {
		RRR_DBG_1("Encoding done in worker fork of ffmpeg instance %s\n", INSTANCE_D_NAME(data->ffmpeg_data->thread_data));
		rrr_event_dispatch_exit(rrr_cmodule_worker_get_event_queue(data->worker));
	}

	return 0;
}

static void ffmpeg_log_av (
		void *avcl, int avlevel, const char *fmt, va_list args
) {
	static const uint8_t level_map[] = {
		[AV_LOG_ERROR] = RRR_DEBUGLEVEL_ERROR,
		[AV_LOG_WARNING] = RRR_DEBUGLEVEL_ERROR,
		[AV_LOG_INFO] = RRR_DEBUGLEVEL_INFO,
		[AV_LOG_DEBUG] = RRR_DEBUGLEVEL_DEBUG
	};

	assert(avlevel >= 0 && (size_t) avlevel <= sizeof(level_map)/sizeof(*level_map) && "AV log level out of range");

	// XXX [atle 2025-12-22]: This looks messy by showing ffmpeg internals, simply print config name.
	// AVClass *avc = avcl ? *(AVClass **) avcl : NULL;
	// const char *prefix = avc ? avc->item_name(avcl) : "ffmpeg";
	const char *prefix = rrr_config_global.log_prefix;
	uint8_t level = level_map[avlevel];

	if (level == RRR_DEBUGLEVEL_ERROR) {
		rrr_log_vprintf(__FILE__, __LINE__, level, prefix, fmt, args);
		return;
	}

	if (!(rrr_config_global.debuglevel & level))
		return;

	pthread_mutex_lock(&ffmpeg_logbuf_lock);

	ffmpeg_logbuf_pos += vsnprintf(ffmpeg_logbuf + ffmpeg_logbuf_pos, sizeof(ffmpeg_logbuf) - ffmpeg_logbuf_pos, fmt, args);

	if (ffmpeg_logbuf_pos >= sizeof(ffmpeg_logbuf)) {
		sprintf(ffmpeg_logbuf + sizeof(ffmpeg_logbuf) - 2, "\n");
		goto flush;
	}

	if (strchr(ffmpeg_logbuf, '\n') != NULL) {
		goto flush;
	}

	pthread_mutex_unlock(&ffmpeg_logbuf_lock);

	return;

	flush:
	ffmpeg_logbuf[sizeof(ffmpeg_logbuf) - 1] = '\0';
	rrr_log_printf(__FILE__, __LINE__, level, prefix, "%s", ffmpeg_logbuf);
	ffmpeg_logbuf_pos = 0;

	pthread_mutex_unlock(&ffmpeg_logbuf_lock);
}

static void ffmpeg_log_av_f (
		const char *fmt, ...
) {
	va_list args;
	va_start(args, fmt);
	ffmpeg_log_av(NULL, AV_LOG_INFO, fmt, args);
	va_end(args);
}

static void ffmpeg_log_rva (
		RVALogLevel rvalevel, const char *fmt, va_list args
) {
	static const uint8_t level_map[] = {
		[RVA_LOG_LEVEL_ERROR] = RRR_DEBUGLEVEL_ERROR,
		[RVA_LOG_LEVEL_INFO] = RRR_DEBUGLEVEL_INFO
	};

	assert(rvalevel >= 0 && (size_t) rvalevel <= sizeof(level_map)/sizeof(*level_map) && "RVA log level out of range");

	const char *prefix = rrr_config_global.log_prefix;
	uint8_t level = level_map[rvalevel];

	if (level != RRR_DEBUGLEVEL_ERROR && !(rrr_config_global.debuglevel & level))
		return;

	rrr_log_vprintf(__FILE__, __LINE__, level, prefix, fmt, args);
}

static int ffmpeg_report_callback(const char *filename, void *arg) {
	int ret = 0;

	struct ffmpeg_worker_data *worker_data = arg;

	struct rrr_msg_addr msg_addr;
	struct rrr_msg_msg *msg = NULL;
	struct rrr_array array = {0};

	if (strncmp(filename, "file:", 5) == 0) {
		filename += 5;
	}

	RRR_DBG_1("File completion report for '%s' in worker %s of ffmpeg instance %s\n",
		filename, worker_data->worker->name, INSTANCE_D_NAME(worker_data->ffmpeg_data->thread_data));

	if (!worker_data->ffmpeg_data->report_messages)
		goto out;

	if (rrr_array_push_value_str_with_tag(&array, "ffmpeg_filename", filename) != 0) {
		RRR_MSG_0("Failed to push filename to array in %s\n", __func__);
		goto fail;
	}

	if (rrr_array_new_message_from_array(&msg, &array, rrr_time_get_64(), NULL, 0) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto fail;
	}

	rrr_msg_addr_init(&msg_addr);

	if (rrr_cmodule_worker_send_message_and_address_to_parent(worker_data->worker, msg, &msg_addr) != 0) {
		RRR_MSG_0("Failed to send report message to parent in worker %s of ffmpeg instance %s\n",
			worker_data->worker->name, INSTANCE_D_NAME(worker_data->ffmpeg_data->thread_data));
		goto fail;
	}

	goto out;
	fail:
		ret = 1;
	out:
		RRR_FREE_IF_NOT_NULL(msg);
		rrr_array_clear(&array);
		return ret;
}

static void ffmpeg_filename_generator(char *dst, size_t size, const char *prefix, uint8_t index, const char *suffix) {
	switch (ffmpeg_filename_format) {
		case FFMPEG_FILENAME_FORMAT_COUNTER: {
			snprintf(dst, size, "file:%s%04u%s", prefix, index, suffix);
		} break;
		case FFMPEG_FILENAME_FORMAT_TIMESTAMP: {
			struct rrr_timespec utc;
			rrr_time_utc(&utc);
			snprintf(dst, size, "file:%s%04d-%02d-%02dZ%02d:%02d:%02d%s",
				prefix, utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second, suffix);
		} break;
		default:
			assert(0 && "Unknown format");
	};
	dst[size - 1] = '\0';
}

static int ffmpeg_fork_init_wrapper (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
) {
	struct ffmpeg_data *data = private_arg;

	int ret = 0;

	snprintf(ffmpeg_log_prefix, sizeof(ffmpeg_log_prefix), "%s", rrr_config_global.log_prefix);
	ffmpeg_log_prefix[sizeof(ffmpeg_log_prefix) - 1] = '\0';
	ffmpeg_filename_format = data->filename_format;

	struct ffmpeg_worker_data worker_data = {
		.ffmpeg_data = data,
		.worker = worker
	};

	assert(data->source == NULL && "FFmpeg source URL not implemented");

	if (chdir(data->output_directory) != 0) {
		RRR_MSG_0("Failed to change working directory to %s in worker %s of ffmpeg instance %s: %s\n",
			data->output_directory, worker->name, INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (rva_open_shared(&worker_data.shctx) != 0) {
		RRR_MSG_0("Failed to open shared context in worker %s of ffmpeg instance %s\n",
			worker->name, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	av_log_set_callback(ffmpeg_log_av);
	rva_set_log_callback(ffmpeg_log_rva);
	rva_set_filename_generator(ffmpeg_filename_generator);

	AVRational time_base = {1, 25};

	rva_init_generator(
			&worker_data.gctx,
			&worker_data.threads[THREAD_DECODER],
			&worker_data.stop_now,
			&worker_data.thread_exited,
			1920,
			1080,
			&worker_data.shctx.frame_buf,
			time_base
	);

	rva_init_encoder(
			&worker_data.ectx,
			&worker_data.threads[THREAD_ENCODER],
			&worker_data.stop_now,
			&worker_data.thread_exited,
			"out-",
			".mp4",
			&worker_data.flush_now,
			&worker_data.shctx.frame_buf,
			time_base,
			rrr_int_from_biglength_bug_const(worker_data.ffmpeg_data->duration_s),
			rrr_int_from_biglength_bug_const(worker_data.ffmpeg_data->rounds)
	);

	worker_data.ectx.report_callback = ffmpeg_report_callback;
	worker_data.ectx.report_callback_arg = &worker_data;

	if (rva_start(worker_data.threads, THREAD_COUNT) != 0) {
		RRR_MSG_0("Failed to start RVA threads in worker %s fork of ffmpeg instance %s\n",
			worker->name, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (data->process_mode == RRR_CMODULE_PROCESS_MODE_DEFAULT) {
		callbacks->process_callback = ffmpeg_process_callback;
		callbacks->process_callback_arg = &worker_data;
	}

	callbacks->custom_tick_callback = ffmpeg_tick_callback;
	callbacks->custom_tick_callback_arg = &worker_data;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		// Don't goto out, run cleanup functions
	}

	out:
		RRR_DBG_1("ffmpeg worker %s exiting\n", worker->name);
		rva_stop(worker_data.threads, THREAD_COUNT, &worker_data.stop_now);
		rva_close_input(&worker_data.ictx);
		rva_close_shared(&worker_data.shctx);
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

