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

#pragma once

extern "C" {
#include "event_handle.h"
#include "event_collection_struct.h"

struct rrr_event_queue;
};

#include "../util/E.hxx"

#include <memory>
#include <string>

namespace RRR::Event {
	class E : public RRR::util::E {
		public:
		E(std::string msg) : RRR::util::E(msg) {}
	};

	class HandleBase {
		private:
		rrr_event_handle handle;

		public:
		HandleBase(struct rrr_event_handle handle) :
			handle(handle)
		{}
		virtual ~HandleBase() = default;
	};

	template <typename T, typename L> class Handle : public HandleBase {
		private:
		L callback;

		public:
		HandleBase(L callback) :
			callback(callback),
			type(type)
		{
		}
	};

	class Queue {
		private:
		struct rrr_event_queue *queue;
		struct rrr_event_collection collection;
		std::forward_list<std::weak_ptr<HandleBase>> handles;
		rrr_event_handle push_periodic(HandleBase *base, uint64_t interval_us);

		public:
		Queue(struct rrr_event_queue *queue);
		~Queue();
		template <typename T, typename L> std::shared_ptr<HandleBase> push_periodic (
				L callback,
				T arg
		) {

		}
	};
}; // namespace RRR::Event
