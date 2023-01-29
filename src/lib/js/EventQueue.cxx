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

#include "EventQueue.hxx"


namespace RRR::JS {
	bool EventQueue::accept(std::weak_ptr<Persistable> object, const char *identifier, void *arg) {
		if (strcmp(identifier, MSG_SET_TIMEOUT) == 0) {
			timeout_events.emplace(object, RRR::util::time_get_i64() + * (int64_t *) arg, arg);
			return true;
		}
		return false;
	}

	void EventQueue::run() {
		const int64_t now = RRR::util::time_get_i64();
		for (auto it = timeout_events.begin(); it != timeout_events.end();) {
			bool erase = false;
			if (!(*it).is_alive()) {
				erase = true;
			}
			else if (now > (*it).get_exec_time()) {
				(*it).acknowledge();
				erase = true;
			}
			
			if (erase) {
				timeout_events.erase(it);
			}
			else {
				// List is sorted by execution time, and no more timers has expired
				break;
			}
		}
	}
}; // namespace RRR::JS
