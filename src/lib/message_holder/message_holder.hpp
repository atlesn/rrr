/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MESSAGE_HOLDER_HPP
#define RRR_MESSAGE_HOLDER_HPP

extern "C" {
#include "message_holder.h"
}

struct rrr_msg_holder;

namespace rrr::msg_holder {
	class unlocker {
		struct rrr_msg_holder *entry;
		public:
		unlocker(struct rrr_msg_holder *entry) : entry(entry) {}
		~unlocker() {
			rrr_msg_holder_unlock(entry);
		}
	};
};

#endif
