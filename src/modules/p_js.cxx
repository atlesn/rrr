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

extern "C" {

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
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"

}; // extern "C"

#include "../lib/event/Event.hxx"
#include "../lib/js/Message.hxx"
#include "../lib/js/Config.hxx"
#include "../lib/js/Timeout.hxx"
#include "../lib/js/Js.hxx"
#include "../lib/util/Readfile.hxx"

extern "C" {

struct js_data {
	struct rrr_instance_runtime_data *thread_data;
	char *js_file;
};

static void js_data_cleanup(void *arg) {
	struct js_data *data = (struct js_data *) arg;

	RRR_FREE_IF_NOT_NULL(data->js_file);
}

static void js_data_init(struct js_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static int js_parse_config (struct js_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("js_file", js_file);

	if (data->js_file == NULL || *(data->js_file) == '\0') {
		RRR_MSG_0("js_file configuration parameter missing for js instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

}; // extern "C"

class js_run_data {
	private:
	RRR::Event::Collection event_collection;
	RRR::JS::CTX &ctx;
	RRR::JS::Isolate &isolate;
	RRR::JS::PersistentStorage &persistent_storage;
	RRR::JS::Function config;
	RRR::JS::Function source;
	RRR::JS::Function process;
	RRR::JS::MessageDrop message_drop;
	RRR::JS::MessageFactory msg_factory;
	RRR::JS::ConfigFactory cfg_factory;
	RRR::JS::TimeoutFactory timeout_factory;
	RRR::JS::EventQueue event_queue;
	std::shared_ptr<RRR::JS::Program> program;

	int64_t prev_status_time = 0;
	rrr_biglength memory_entries = 0;
	rrr_biglength memory_size = 0;
	uint64_t processed = 0;
	uint64_t processed_total = 0;

	bool need_status(int64_t *diff) {
		int64_t now = (int64_t) rrr_time_get_64();
		*diff = now - prev_status_time;
		if (*diff > 1 * 1000 * 1000) { // 1 Second
			prev_status_time = now;
			return true;
		}
		return false;
	}

	static void drop(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, void *callback_arg) {
		js_run_data *run_data = (js_run_data *) callback_arg;

		if (rrr_cmodule_worker_send_message_and_address_to_parent (
				run_data->worker,
				msg,
				msg_addr
		) != 0) {
			throw E(std::string("Could not send messages to parent in ") + __func__ + " of JS instance " +
					INSTANCE_D_NAME(run_data->data->thread_data));
		}
	}

	public:
	struct js_data * const data;
	struct rrr_cmodule_worker * const worker;

	class E : public RRR::util::E {
		public:
		E(std::string msg) : RRR::util::E(msg){}
	};

	void status() {
		int64_t diff;
		if (!need_status(&diff)) {
			return;
		}

		double per_sec = ((double) processed) / ((double) diff / 1000000);
		processed = 0;

		RRR_DBG_1("JS instance %s processed per second %.2f total %" PRIu64 ", in mem %" PRIrrrbl " bytes %" PRIrrrbl "\n",
				INSTANCE_D_NAME(data->thread_data),
				per_sec,
				processed_total,
				memory_entries,
				memory_size
		);
	}
	void runGC() {
		persistent_storage.gc(&memory_entries, &memory_size);

		// Calls to make the GCing a little more aggressive
		isolate->LowMemoryNotification();
		while (!isolate->IdleNotificationDeadline(1)) {
		}
	}
	bool hasConfig() const {
		return !config.empty();
	}
	bool hasSource() const {
		return !source.empty();
	}
	bool hasProcess() const {
		return !process.empty();
	}
	void runConfig(struct rrr_instance_config_data *instance_config) {
		auto scope = RRR::JS::Scope(ctx);
		auto cfg = cfg_factory.new_external(ctx, instance_config);
		RRR::JS::Value arg(cfg.first());
		config.run(ctx, 1, &arg);
		ctx.trycatch_ok([](std::string msg) {
			throw E(std::string("Failed to run config function: ") + msg);
		});
	}
	void runSource() {
		auto scope = RRR::JS::Scope(ctx);
		auto message = msg_factory.new_external(ctx);
		RRR::JS::Value arg(message.first());
		source.run(ctx, 1, &arg);
		ctx.trycatch_ok([](std::string msg) {
			throw E(std::string("Failed to run source function: ") + msg);
		});
	}
	void runProcess(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr) {
		{
			auto scope = RRR::JS::Scope(ctx);
			processed++;
			processed_total++;
			auto message = msg_factory.new_external(ctx, msg, msg_addr);
			RRR::JS::Value arg(message.first());
			process.run(ctx, 1, &arg);
			ctx.trycatch_ok([](std::string msg) {
				throw E(std::string("Failed to run process function: ") + msg);
			});
		}
	}
	void runEvents() {
		auto scope = RRR::JS::Scope(ctx);
		ctx.trycatch_ok([](std::string msg) {
			throw E(std::string("Failed to run process function: ") + msg);
		});
	}
	template <typename L> js_run_data (
			struct js_data *data,
			struct rrr_cmodule_worker *worker,
			RRR::JS::Isolate &isolate,
			RRR::JS::CTX &ctx,
			RRR::JS::PersistentStorage &persistent_storage,
			L make_program
	) :
		event_collection(rrr_cmodule_worker_get_event_queue(worker)),
		isolate(isolate),
		ctx(ctx),
		persistent_storage(persistent_storage),
		data(data),
		worker(worker),
		message_drop(drop, this),
		msg_factory(ctx, persistent_storage, message_drop),
		cfg_factory(ctx, persistent_storage),
		timeout_factory(ctx, persistent_storage),
		event_queue(ctx, persistent_storage, event_collection),
		program(make_program(ctx))
	{
		msg_factory.register_as_global(ctx);
		cfg_factory.register_as_global(ctx);
		timeout_factory.register_as_global(ctx);

		try {
			program->compile(ctx);
		}
		catch (E e) {
			throw e;
		}

		if (!program->is_compiled()) {
			ctx.trycatch_ok([](std::string &&msg){
				throw E(std::string(msg));
			});
			throw E("Script or module was not compiled");
		}

		program->run(ctx);

		const struct rrr_cmodule_config_data *cmodule_config_data =
			rrr_cmodule_helper_config_data_get(data->thread_data);
		if (cmodule_config_data->config_function != NULL && *cmodule_config_data->config_function != '\0') {
			config = ctx.get_function(cmodule_config_data->config_function);
		}
		if (cmodule_config_data->source_function != NULL && *cmodule_config_data->source_function != '\0') {
			source = ctx.get_function(cmodule_config_data->source_function);
		}
		if (cmodule_config_data->process_function != NULL && *cmodule_config_data->process_function != '\0') {
			process = ctx.get_function(cmodule_config_data->process_function);
		}
	}
};

extern "C" {

static int js_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct js_data *data = (struct js_data *) private_arg;

	using namespace RRR::JS;

	ENV env("rrr-js");

	int ret = 0;

	try {
		auto isolate = Isolate(env);
		auto ctx = CTX(env, std::string(data->js_file));
		auto persistent_storage = PersistentStorage(ctx);
		auto scope = Scope(ctx);

		auto source = std::string(RRR::util::Readfile(std::string(data->js_file), 0, 0));

		js_run_data run_data (
				data,
				worker,
				isolate,
				ctx,
				persistent_storage,
				[data,source](CTX &ctx){
					return new RRR::JS::Script(std::string(data->js_file), source);
				}
		);

		callbacks->ping_callback_arg = (void *) &run_data;
		callbacks->configuration_callback_arg = (void *) &run_data;
		callbacks->process_callback_arg = (void *) &run_data;

		if ((ret = rrr_cmodule_worker_loop_start (
				worker,
				callbacks
		)) != 0) {
			RRR_MSG_0("Error from worker loop in %s\n", __func__);
				goto out;
		}
	}
	catch (RRR::util::Readfile::E e) {
		RRR_MSG_0("Failed while reading script %s: %s\n", data->js_file, *e);
		ret = 1;
		goto out;
	}
	catch (RRR::util::E e) {
		RRR_MSG_0("Failed while executing script %s: %s\n", data->js_file, *e);
		ret = 1;
		goto out;
	}
	catch (...) {
		RRR_MSG_0("Unknown exception in instance %s in %s\n", INSTANCE_D_NAME(data->thread_data), __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int js_ping_callback (RRR_CMODULE_PING_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	run_data->status();
	run_data->runGC();
	run_data->runEvents(); // TODO : Finer control of when timeouts and events run

	return 0;
}

static int js_configuration_callback (RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	int ret = 0;

	if (!run_data->hasConfig()) {
		RRR_DBG_1("Note: No configuration function set for cmodule instance %s\n",
				INSTANCE_D_NAME(run_data->data->thread_data));
		goto out;
	}

	try {
		run_data->runConfig(INSTANCE_D_CONFIG(run_data->data->thread_data));
	}
	catch (js_run_data::E e) {
		RRR_MSG_0("%s in instance %s\n", *e, INSTANCE_D_NAME(run_data->data->thread_data));
		ret = 1;
		goto out;
	}
	catch (...) {
		RRR_MSG_0("Unknown exception in instance %s in %s\n", INSTANCE_D_NAME(run_data->data->thread_data), __func__);
		ret = 1;
		goto out;
	}
	
	out:
	return ret;
}

static int js_process_callback (RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	int ret = 0;

	try {
		if (is_spawn_ctx) {
			if (!run_data->hasSource()) {
				RRR_BUG("BUG: Source function was NULL but we tried to source anyway in %s\n", __func__);
			}
			run_data->runSource();
		}
		else {
			if (!run_data->hasProcess()) {
				RRR_BUG("BUG: Process function was NULL but we tried to process anyway in %s\n", __func__);
			}
			run_data->runProcess(message, message_addr);
		}

		// Run any imminent events
		run_data->runEvents();
	}
	catch (RRR::util::E e) {
		RRR_MSG_0("%s in instance %s\n", *e, INSTANCE_D_NAME(run_data->data->thread_data));
		ret = 1;
		goto out;
	}
	catch (...) {
		RRR_MSG_0("Unknown exception in instance %s in %s\n", INSTANCE_D_NAME(run_data->data->thread_data), __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct js_fork_callback_data {
	struct rrr_instance_runtime_data *thread_data;
};

static int js_fork (void *arg) {
	struct js_fork_callback_data *callback_data = (struct js_fork_callback_data *) arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;
	struct js_data *data = (struct js_data *) thread_data->private_data;

	int ret = 0;

	if (js_parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_parse_config(thread_data, "js", "function") != 0) {
		ret = 1;
		goto out;
	}

	// Calback args are set in init wrapper function
	if (rrr_cmodule_helper_worker_forks_start_with_ping_callback (
			thread_data,
			js_init_wrapper_callback,
			data,
			js_ping_callback,
			NULL,
			js_configuration_callback,
			NULL,
			js_process_callback,
			NULL
	) != 0) {
		RRR_MSG_0("Error while starting cmodule worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_js (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) thread->private_data;
	struct js_data *data = (struct js_data *) thread_data->private_memory;
	thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("js thread thread_data is %p\n", thread_data);

	js_data_init(data, thread_data);

	pthread_cleanup_push(js_data_cleanup, data);

	struct js_fork_callback_data fork_callback_data = {
		thread_data
	};

	if (rrr_thread_start_condition_helper_fork(thread, js_fork, &fork_callback_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("js instance %s started thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_loop (
			thread_data
	);

	out_message:
	RRR_DBG_1 ("js instance %s stopping thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_js,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "cmodule";

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
	RRR_DBG_1 ("Destroy cmodule module\n");
}

}; // extern "C"
