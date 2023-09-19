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

#include "Js.hxx"
#include "Persistent.hxx"
#include "../event/Event.hxx"
#include "../util/Time.hxx"

#include <v8.h>

extern "C" {
#include <string.h>
};

#include <functional>
#include <set>
#include <functional>

namespace RRR::JS {
	class Event {
		private:
		int64_t exec_time;
		std::weak_ptr<Persistable> object;
		void *arg;
		char identifier[64];

		public:
		Event(std::weak_ptr<Persistable> object, int64_t exec_time, const char *identifier, void *arg) :
			object(object),
			exec_time(exec_time),
			arg(arg)
		{
			strncpy(this->identifier, identifier, sizeof(this->identifier));
			this->identifier[sizeof(this->identifier) - 1] = '\0';
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
		const char *get_identifier() const {
			return identifier;
		}
		virtual ~Event() = default;
	};

	class TimeoutEvent : public Event {
		public:
		TimeoutEvent(std::weak_ptr<Persistable> object, int64_t timeout, const char *identifier, void *arg) :
			Event(object, RRR::util::time_get_i64() + timeout, identifier, arg)
		{
		}
	};

	class EventQueue : public PersistentSniffer {
		private:
		constexpr static const uint64_t initial_interval_us = 1 * 1000;        // 1 millisecond
		constexpr static const uint64_t default_interval_us = 1 * 1000 * 1000; // 1 second
		static std::function<void(EventQueue *)> callback;
		class CompareExecTime {
			public:
			bool operator()(const Event &a, const Event &b) const {
				return a.get_exec_time() < b.get_exec_time();
			}
		};
		std::set<Event, CompareExecTime> timeout_events;
		CTX &ctx;
		RRR::Event::Collection &collection;
		std::shared_ptr<RRR::Event::HandleBase> handle;

		void dispatch();

		protected:
		bool accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) final;

		public:
		constexpr static const char MSG_SET_TIMEOUT[] = "EventQueue/set_timeout";

		EventQueue(CTX &ctx, PersistentStorage &persistent_storage, RRR::Event::Collection &collection);
		EventQueue(const EventQueue &) = delete;
	};
}; // namespace RRR::JS
