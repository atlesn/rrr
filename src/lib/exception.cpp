/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "exception.hpp"

extern "C" {
#include "read_constants.h"
}

namespace rrr::exp {
	int normal::num() noexcept {
		return RRR_READ_HARD_ERROR;
	}
	int hard::num() noexcept {
		return RRR_READ_HARD_ERROR;
	}
	int soft::num() noexcept {
		return RRR_READ_SOFT_ERROR;
	}
	int eof::num() noexcept {
		return RRR_READ_EOF;
	}
	int incomplete::num() noexcept {
		return RRR_READ_INCOMPLETE;
	}

	void check_and_throw (int ret, const std::string &msg) {
		if (ret == RRR_READ_OK) {
			return;
		}
		else if (ret == RRR_READ_SOFT_ERROR) {
			throw soft(msg);
		}

		throw hard(msg + " - Return was " + std::to_string(ret));
	}
};
