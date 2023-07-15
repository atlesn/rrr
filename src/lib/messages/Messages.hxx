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

#ifndef RRR_MESSAGES_HXX
#define RRR_MESSAGES_HXX

#include <memory>

#include "../util/E.hxx"

extern "C" {
#	include "msg_msg.h"
#	include "../allocator.h"
}

namespace RRR::Messages {
	class E : public RRR::util::E {
		public:
		E(const std::string &msg) : RRR::util::E(msg) {}
	};

	auto new_with_data (
			rrr_u8 type,
			rrr_u8 class_,
			rrr_u64 timestamp,
			const char *topic,
			rrr_u16 topic_length,
			const char *data,
			rrr_u32 data_length
	) {
		struct rrr_msg_msg *msg;
		auto ptr = std::unique_ptr<struct rrr_msg_msg, void(*)(struct rrr_msg_msg *)> (nullptr, [](auto msg){
			RRR_FREE_IF_NOT_NULL(msg);
		});

		if (rrr_msg_msg_new_with_data (&msg, type, class_, timestamp, topic, topic_length, data, data_length) != 0) {
			throw E(std::string("Error while creating message with data in ") + __func__);
		}

		ptr.reset(msg);

		return ptr;
	};
} // namespace RRR::Messages
#endif /* RRR_MESSAGES_HXX */
