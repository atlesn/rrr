/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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


#ifndef RRR_POLL_HELPER_HPP
#define RRR_POLL_HELPER_HPP

#include <functional>

#include "log.h"
#include "exception.hpp"
#include "util/macro_utils.hpp"

extern "C" {
#include "poll_helper.h"
}

namespace rrr::poll_helper {
	struct amount {
		uint16_t a;
		amount(uint16_t a) : a(a) {
		}
		void take(uint16_t a) {
			if (a > this->a) {
				throw rrr::exp::bug("Underflow in " + RRR_FUNC + " (" + RRR_STR(a) + " > " + RRR_STR(this->a) + ")");
			}
			this->a -= a;
		}
	};

	template<typename T> class poll_delete_custom_arg_wrapper_callback_data {
		public:
		const std::function<void (struct rrr_msg_holder *, T)> callback;
		T arg;
		poll_delete_custom_arg_wrapper_callback_data(const std::function<void (struct rrr_msg_holder *, T)> callback, T arg) :
			callback(callback),
			arg(arg)
		{}
	};

	template<typename T> static inline int __poll_delete_wrapper(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
		class poll_delete_custom_arg_wrapper_callback_data<T> *callback_data = reinterpret_cast<class poll_delete_custom_arg_wrapper_callback_data<T> *>(arg);
		try {
			callback_data->callback(entry, callback_data->arg);
		}
		catch (rrr::exp::normal &e) {
			return e.num();
		}
		catch (rrr::exp::bug &e) {
			throw e;
		}
		catch (std::exception &e) {
			RRR_BUG("Unknown exception in %s, trigger abort: %s\n", __func__, e.what());
			return 1;
		}
		catch (...) {
			RRR_BUG("Unknown exception in %s, trigger abort\n", __func__);
			return 1;
		}
		return 0;
	}

	template<typename T> static inline void poll_delete_custom_arg (
			amount &a,
			struct rrr_instance_runtime_data *thread_data,
			const std::function<void (struct rrr_msg_holder *, T)> callback,
			T callback_arg
	) {
		class poll_delete_custom_arg_wrapper_callback_data<T> callback_data(callback, callback_arg);

		rrr:exp::check_and_throw (
			rrr_poll_do_poll_delete_custom_arg(&a.a, thread_data, __poll_delete_wrapper<T>, &callback_data),
			"Error in " + RRR_FUNC
		);
	}

	static inline void poll_delete (
			amount &a,
			struct rrr_instance_runtime_data *thread_data,
			const std::function<void (struct rrr_msg_holder *, struct rrr_instance_runtime_data *)> callback
	) {
		poll_delete_custom_arg<struct rrr_instance_runtime_data *>(a, thread_data, callback, thread_data);
	}
}

#endif /* RRR_POLL_HELPER_HPP */
