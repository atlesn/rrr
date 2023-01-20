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

#include "Readfile.hxx"

extern "C" {
#include "readfile.h"
};

namespace RRR::util {
	Readfile::Readfile(std::string filename, size_t max_size, bool enoent_ok) {
		int ret = 0;

		char *data_ = nullptr;
		rrr_biglength size_ = 0;


		if ((ret = rrr_readfile_read (&data_, &size_, filename.c_str(), max_size, enoent_ok ? 1 : 0)) != 0) {
			throw E("Readfile failed");
		}

		data = size_ > 0
			? std::string(data_, rrr_size_from_biglength_bug_const(size_))
			: std::string();

		RRR_FREE_IF_NOT_NULL(data_);
	}

	Readfile::operator std::string() {
		return data;
	}
}; // namespace RRR::util
