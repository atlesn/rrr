/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "../../lib/js/Js.hxx"
#include "../../lib/js/Message.hxx"
#include "../../lib/js//Persistent.hxx"

#include "testjs.hxx"

#include <stdio.h>
#include <string.h>
#include <memory>
#include <functional>
#include <filesystem>

extern "C" {
#	include "../../lib/log.h"
#	include "../../lib/util/rrr_time.h"
}

#include "../../lib/messages/Messages.hxx"
#include "../test.h"

template<typename T> static void run(RRR::JS::Isolate &isolate, RRR::JS::CTX &ctx, const std::string &in, T action) {
	using namespace RRR::JS;

	auto cwd = std::filesystem::current_path().string();
	auto program = std::function<std::shared_ptr<Program>()>([&](){
		return std::dynamic_pointer_cast<Program>(isolate.make_module<Module>(ctx, cwd, "-", in));
	})();

	if (program->is_compiled()) {
		printf("Compiled script %s, running\n", in.c_str());
		program->run(ctx);
	}

	if (ctx.trycatch_ok([](std::string &&msg){
		throw E(std::string(msg));
	})) {
		// OK
	}

	action(program);
}

static void drop(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, void *callback_arg) {
	printf("DROP!!!!\n");
}

int rrr_test_js (void) {
	using namespace RRR::JS;

	int ret = 0;

	try {
		auto env = ENV("js-test");
		auto isolate = Isolate(env);
		auto ctx = CTX(env, std::string(__FILE__));
		auto scope = Scope(ctx);
		auto persistent_storage = PersistentStorage(ctx);

		auto message_drop = MessageDrop(drop, nullptr);
		auto message_factory = MessageFactory(ctx, persistent_storage, message_drop);

		const char topic[] = "topic";
		const char data[] = "0123456789";
		auto msg = RRR::Messages::new_with_data (
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			topic,
			(rrr_u16) strlen(topic),
			data,
			(rrr_u32) strlen(data)
		);
		auto code = std::string("function func(message) { message.send(); }");

		run(isolate, ctx, code, [&ret,&ctx,&message_factory,&msg](auto program){
			auto func = program->get_function(ctx, "func");
			auto message = message_factory.new_external(ctx, msg.get(), nullptr);
			auto arg = Value(message.first());

			printf("Riun function\n");
			func.run(ctx, 1, &arg);

			ctx.trycatch_ok([](std::string msg) {
				throw E(std::string("Failed to run function: ") + msg);
			});
		});
	}
	catch (RRR::util::E &e) {
		TEST_MSG("Failed: %s\n", *e);
		ret = 1;
	}
	catch (...) {
		TEST_MSG("Failed, unknown exception\n");
		ret = 1;
	}

	return ret;
}
