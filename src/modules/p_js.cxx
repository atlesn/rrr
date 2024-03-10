/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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
#include "../lib/cmodule/cmodule_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/util/macro_utils.h"

}; // extern "C"

#include <filesystem>
#include <unordered_map>

#include "../lib/event/Event.hxx"
#include "../lib/js/Message.hxx"
#include "../lib/js/Config.hxx"
#include "../lib/js/Timeout.hxx"
#include "../lib/js/OS.hxx"
#include "../lib/js/Js.hxx"

extern "C" {

class js_run_data;

struct js_data {
	struct rrr_instance_runtime_data *thread_data;
	const js_run_data *run_data;
	char *js_file;
	char *js_module_name;
	struct rrr_cmodule_helper_run_data *cmodule_run_data;
};

static void js_data_cleanup(void *arg) {
	struct js_data *data = (struct js_data *) arg;

	RRR_FREE_IF_NOT_NULL(data->js_file);
	RRR_FREE_IF_NOT_NULL(data->js_module_name);
	if (data->cmodule_run_data != NULL)
		rrr_cmodule_helper_run_data_destroy(data->cmodule_run_data);
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

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("js_module_name", js_module_name);

	out:
	return ret;
}

}; // extern "C"

class js_run_data {
	private:
	RRR::Event::Collection event_collection;
	RRR::JS::CTX &ctx;
	RRR::JS::Isolate &isolate;
	RRR::JS::Scope scope;
	RRR::JS::PersistentStorage &persistent_storage;
	RRR::JS::Function config;
	RRR::JS::Function source;
	RRR::JS::Function process;
	RRR::JS::MessageDrop message_drop;
	RRR::JS::MessageFactory msg_factory;
	RRR::JS::ConfigFactory cfg_factory;
	RRR::JS::TimeoutFactory timeout_factory;
	RRR::JS::OSFactory os_factory;
	RRR::JS::EventQueue event_queue;

	std::shared_ptr<RRR::JS::Program> program;
	std::unordered_map<std::string,RRR::JS::Function> methods;

	int64_t start_time = 0;
	rrr_biglength memory_entries = 0;
	rrr_biglength memory_size = 0;
	uint64_t processed = 0;
	uint64_t processed_total = 0;

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

	template<typename L> void status (L l) {
		double average = ((double) processed_total) / ((double) (rrr_time_get_64() - start_time) / 1000000);

		l(
				processed,
				average,
				processed_total,
				memory_entries,
				memory_size
		);

		processed = 0;
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
	void runConfig(struct rrr_settings *settings, struct rrr_settings_used *settings_used) {
		auto scope = RRR::JS::Scope(ctx);
		auto cfg = cfg_factory.new_external(ctx, settings, settings_used);
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

	void runProcessDirectDispatch (RRR::JS::Value message, const char *method) {
		RRR::JS::Value args[] = {
			message
		};
		methods[method].run(ctx, 1, args);
	};

	void runProcessDefault (RRR::JS::Value message, const char *method) {
		RRR::JS::Value args[] = {
			message,
			method != NULL
				? (RRR::JS::Value) RRR::JS::String(ctx, method)
				: (RRR::JS::Value) RRR::JS::Undefined(ctx)
		};
		process.run(ctx, 2, args);
	};

	void runProcess(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, const char *method, enum rrr_cmodule_process_mode mode) {
		auto scope = RRR::JS::Scope(ctx);
		processed++;
		processed_total++;

		auto msg_value = (RRR::JS::Value) msg_factory.new_external(ctx, msg, msg_addr).first();

		if (mode == RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH) {
			runProcessDirectDispatch(msg_value, method);
		}
		else {
			runProcessDefault(msg_value, method);
		}

		ctx.trycatch_ok([](std::string msg) {
			throw E(std::string("Failed to run process function: ") + msg);
		});
	}
	void registerMethod(const char *name) {
		methods[name] = program->get_function(ctx, name);
	}
	static int methodCallback(const char *stack_name, const char *method_name, void *self) {
		js_run_data *run_data = reinterpret_cast<js_run_data*>(self);
		RRR_DBG_1("JS instance %s registering method %s from method definition %s\n",
			INSTANCE_D_NAME(run_data->data->thread_data), method_name, stack_name
		);
		run_data->registerMethod(method_name);
		return 0;
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
		scope(ctx),
		persistent_storage(persistent_storage),
		data(data),
		worker(worker),
		message_drop(drop, this),
		msg_factory(ctx, persistent_storage, message_drop),
		cfg_factory(ctx, persistent_storage),
		timeout_factory(ctx, persistent_storage),
		os_factory(ctx, persistent_storage),
		event_queue(ctx, persistent_storage, event_collection),
		program(make_program()),
		start_time((int64_t) rrr_time_get_64())
	{
		msg_factory.register_as_global(ctx);
		cfg_factory.register_as_global(ctx);
		timeout_factory.register_as_global(ctx);
		os_factory.register_as_global(ctx);

		if (!program->is_compiled()) {
			ctx.trycatch_ok([](std::string &&msg){
				throw E(std::string(msg));
			});
			throw E("Script or module was not compiled");
		}

		program->run(ctx);

		const struct rrr_cmodule_config_data *cmodule_config_data =
			rrr_cmodule_helper_config_data_get(data->thread_data);

		if (cmodule_config_data->config_method != NULL && *cmodule_config_data->config_method != '\0') {
			config = program->get_function(ctx, cmodule_config_data->config_method);
		}
		if (cmodule_config_data->source_method != NULL && *cmodule_config_data->source_method != '\0') {
			source = program->get_function(ctx, cmodule_config_data->source_method);
		}
		switch (cmodule_config_data->process_mode) {
			case RRR_CMODULE_PROCESS_MODE_DEFAULT:
				process = program->get_function(ctx, cmodule_config_data->process_method);
				break;
			case RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH:
				rrr_cmodule_helper_methods_iterate(data->thread_data, methodCallback, this);
				break;
			case RRR_CMODULE_PROCESS_MODE_NONE:
				break;
			default:
				assert(0);
		};
	}
};

extern "C" {

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
		struct rrr_settings *settings = rrr_cmodule_worker_get_settings(run_data->worker);
		struct rrr_settings_used *settings_used = rrr_cmodule_worker_get_settings_used(run_data->worker);

		run_data->runConfig(settings, settings_used);
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
			run_data->runProcess(message, message_addr, method, worker->process_mode);
		}
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

static int js_periodic_callback(RRR_CMODULE_PERIODIC_CALLBACK_ARGS) {
	struct js_run_data *run_data = (struct js_run_data *) private_arg;

	(void)(worker);

	try {
		run_data->runGC();

		// Assuming that the periodic function is called every second

		run_data->status([run_data](
				uint64_t per_sec,
				double per_sec_average,
				uint64_t processed_total,
				rrr_biglength memory_entries,
				rrr_biglength memory_size
		){
			RRR_DBG_1("JS instance %s processed per second %" PRIu64 " average %.2f total %" PRIu64 ", in mem %" PRIrrrbl " bytes %" PRIrrrbl "\n",
					INSTANCE_D_NAME(run_data->data->thread_data),
					per_sec,
					per_sec_average,
					processed_total,
					memory_entries,
					memory_size
			);

			struct rrr_stats_instance *stats = INSTANCE_D_STATS(run_data->data->thread_data);
			if (stats->stats_handle != 0) {
				rrr_stats_instance_post_unsigned_base10_text(stats, "in_mem_persistables", 0, memory_entries);
				rrr_stats_instance_post_unsigned_base10_text(stats, "in_mem_bytes", 0, memory_size);
			}
		});
	}
	catch (js_run_data::E e) {
		RRR_MSG_0("%s in instance %s\n", *e, INSTANCE_D_NAME(run_data->data->thread_data));
		return 1;
	}
	catch (...) {
		RRR_MSG_0("Unknown exception in instance %s in %s\n", INSTANCE_D_NAME(run_data->data->thread_data), __func__);
		return 1;
	}

	return 0;
}

static int js_stats_post_message_hook (RRR_INSTANCE_MESSAGE_HOOK_ARGUMENTS) {
	js_run_data *run_data = (js_run_data *) private_arg;

	int ret = 0;

	rrr_cmodule_worker_stats_message_write(run_data->worker, msg);

	out:
	return ret;
}

static int js_init_wrapper_callback (RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct js_data *data = (struct js_data *) private_arg;

	using namespace RRR::JS;

	ENV env("rrr-js");

	int ret = 0;

	try {
		auto isolate = Isolate(env);
		auto ctx = CTX(env, std::string(data->js_file));
		auto persistent_storage = PersistentStorage(ctx);

		js_run_data run_data (
				data,
				worker,
				isolate,
				ctx,
				persistent_storage,
				[&](){
					const auto absolute_path = std::filesystem::absolute(std::string(data->js_file)).string();

					if (data->js_module_name != NULL) {
						return std::dynamic_pointer_cast<RRR::JS::Program>(isolate.make_module<Module>(ctx, absolute_path));
					}

					auto script = RRR::JS::Script::make_shared(absolute_path);
					script->compile(ctx);
					return std::dynamic_pointer_cast<RRR::JS::Program>(script);
				}
		);

		rrr_stats_instance_set_post_message_hook (INSTANCE_D_STATS(data->thread_data), js_stats_post_message_hook, &run_data);

		callbacks->configuration_callback  = js_configuration_callback;
		callbacks->process_callback        = js_process_callback;
		callbacks->periodic_callback       = js_periodic_callback;

		callbacks->configuration_callback_arg  = (void *) &run_data;
		callbacks->process_callback_arg        = (void *) &run_data;
		callbacks->periodic_callback_arg       = (void *) &run_data;

		if ((ret = rrr_cmodule_worker_loop_start (
				worker,
				callbacks
		)) != 0) {
			RRR_MSG_0("Error from worker loop in %s\n", __func__);
				goto out;
		}
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

static int js_fork (void *arg) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) arg;
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
	if (rrr_cmodule_helper_worker_forks_start_deferred_callback_set (
			thread_data,
			js_init_wrapper_callback,
			data
	) != 0) {
		RRR_MSG_0("Error while starting cmodule worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int js_main_periodic_callback(RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS) {
	struct js_data *data = (struct js_data *) thread_data->private_memory;

	(void)(data);

	// Nothing to do for main tread

	return 0;
}

static int js_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) thread->private_data;
	struct js_data *data = (struct js_data *) thread_data->private_memory;

	thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("js thread thread_data is %p\n", thread_data);

	js_data_init(data, thread_data);

	if (rrr_thread_start_condition_helper_fork(thread, js_fork, thread_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("js instance %s started thread %p\n",
			INSTANCE_D_NAME(thread_data), thread_data);

	if (rrr_cmodule_helper_init_with_periodic (
			&data->cmodule_run_data,
			thread_data,
			js_main_periodic_callback
	) != 0) {
		RRR_MSG_0("Failed to initialize cmodule in js instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	return 0;

	out_message:
		js_data_cleanup(data);
		return 1;
}

static void js_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = (struct rrr_instance_runtime_data *) thread->private_data;
	struct js_data *data = (struct js_data *) thread_data->private_memory;

	RRR_DBG_1 ("js instance %s stopping thread %p\n",
		INSTANCE_D_NAME(thread_data), thread_data);

	rrr_cmodule_helper_deinit(thread_data);

	js_data_cleanup(data);

	*deinit_complete = 1;
}

static const char *module_name = "cmodule";

__attribute__((constructor)) void construct(void) {
}

void load(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = rrr_cmodule_helper_event_functions;
	data->init = js_init;
	data->deinit = js_deinit;
}

void unload(void) {
	RRR_DBG_1 ("Destroy cmodule module\n");
}

}; // extern "C"
