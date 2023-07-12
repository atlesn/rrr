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
#include "../../lib/messages/msg_msg.h"

#include "testjs.hxx"

#include <stdio.h>
#include <string.h>

#include "../../lib/log.h"
#include "../test.h"

static void drop(const struct rrr_msg_msg *msg, const struct rrr_msg_addr *msg_addr, void *callback_arg) {
}

int rrr_test_js (void) {
	using namespace RRR::JS;

	auto env = ENV("js-test");
	auto isolate = Isolate(env);
	auto ctx = CTX(env, std::string(__FILE__));
	auto persistent_storage = PersistentStorage(ctx);

	auto message_drop = MessageDrop(drop, nullptr);
	auto message_factory = MessageFactory(ctx, persistent_storage, message_drop);

	int ret = 0;

	return ret;
}
