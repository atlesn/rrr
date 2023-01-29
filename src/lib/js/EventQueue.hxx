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

#include "Persistent.hxx"
#include "../util/Time.hxx"

#include <v8.h>

extern "C" {
#include <string.h>
};

#include <set>

namespace RRR::JS {
	class Event {
		private:
		int64_t exec_time;
		std::weak_ptr<Persistable> object;
		void *arg;

		public:
		Event(std::weak_ptr<Persistable> object, int64_t exec_time, void *arg) :
			object(object),
			exec_time(exec_time),
			arg(arg)
		{
		}
		bool is_alive() const {
			return !object.expired();
		}
		void acknowledge() const {
			auto obj = object.lock();
			obj->acknowledge(arg);
		}
		int64_t get_exec_time() const {
			return exec_time;
		}
		virtual ~Event() = default;
	};

	class TimeoutEvent : public Event {
		public:
		TimeoutEvent(std::weak_ptr<Persistable> object, int64_t timeout, void *arg) :
			Event(object, RRR::util::time_get_i64() + timeout, arg)
		{
		}
	};

	class EventQueue : public PersistentSniffer {
		private:
		class CompareExecTime {
			public:
			bool operator()(const Event &a, const Event &b) const {
				return a.get_exec_time() < b.get_exec_time();
			}
		};
		std::set<Event, CompareExecTime> timeout_events;

		protected:
		bool accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) final;

		public:
		EventQueue(PersistentStorage &persistent_storage) {
			persistent_storage.register_sniffer(this);
		}
		constexpr static const char MSG_SET_TIMEOUT[] = "EventQueue/set_timeout";

		void run();
	};
}; // namespace RRR::JS
