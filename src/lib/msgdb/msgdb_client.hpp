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

#ifndef RRR_MSGDB_CLIENT_HPP
#define RRR_MSGDB_CLIENT_HPP

#include <string.h>

extern "C" {
#include "msgdb_client.h"
}

namespace rrr::msgdb {
	class client {
		private:
		struct rrr_msgdb_client_conn conn;
		std::string socket_path;

		public:
		~client() {
			rrr_msgdb_client_close(&this->conn);
		}

		void socket_set(std::string socket_path) {
			this->socket_path = socket_path;
		}
	};
}

#endif /* MSGDB_CLIENT_HPP */
