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
#include "event_handle_struct.h"
#include "event_collection_struct.h"

struct rrr_event_queue;
};

#include "../util/E.hxx"

#include <forward_list>
#include <memory>
#include <string>

namespace RRR::Event {
	class Collection;
	class CollectionActions;

	class E : public RRR::util::E {
		public:
		E(std::string msg) : RRR::util::E(msg) {}
	};

	class HandleBase {
		friend class Collection;

		CollectionActions &actions;

		private:
		rrr_event_handle handle;
		virtual void run() = 0;

		protected:
		void set_handle(rrr_event_handle handle);

		public:
		HandleBase(CollectionActions &actions);
		virtual ~HandleBase() = default;
		void base_run() noexcept;
		void set_interval(uint64_t interval_us);
		void add();
	};

	template <typename T, typename L> class Handle : public HandleBase {
		friend class Collection;

		private:
		L callback;
		T arg;

		protected:
		Handle(CollectionActions &actions, L callback, T arg) :
			HandleBase(actions),
			callback(callback),
			arg(arg)
		{
		}
		void run() {
			callback(arg);
		}
	};

	class CollectionActions {
		private:
		Collection &collection;

		public:
		CollectionActions(Collection &collection);
		void dispatch_break();
	};

	class Collection {
		friend class CollectionActions;

		private:
		struct rrr_event_queue *queue;
		struct rrr_event_collection collection;
		std::forward_list<std::weak_ptr<HandleBase>> handles;
		CollectionActions actions;

		rrr_event_handle push_periodic(HandleBase *base, uint64_t interval_us);

		protected:
		void dispatch_break();

		public:
		Collection(struct rrr_event_queue *queue);
		~Collection();
		template <typename T, typename L> std::shared_ptr<HandleBase> push_periodic (
				L callback,
				T arg,
				uint64_t interval_us
		) {
			auto ret = std::shared_ptr<HandleBase>(new Handle<T,L>(actions, callback, arg));
			ret->set_handle(push_periodic(ret.get(), interval_us));
			return ret;
		}
	};
}; // namespace RRR::Event
