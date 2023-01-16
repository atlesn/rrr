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
	Readfile::Readfile(std::string filename, size_t max_size, bool enoent_ok) :
	       	data(nullptr, Deleter<char>()),
		size(0)
	{
		char *data_ = nullptr;
		rrr_biglength size_ = 0;

		int ret = 0;

		if ((ret = rrr_readfile_read (&data_, &size_, filename.c_str(), max_size, enoent_ok ? 1 : 0)) != 0) {
			throw E("Readfile failed");
		}

		data.reset(data_);
		size = size_;
	}

	Readfile::operator std::string() {
		size_t size_;
		if (rrr_size_from_biglength_err(&size_, size) != 0) {
			throw E("Size error");
		}
		return size_ == 0 ? std::string() : std::string(*data, size_);
	}
}; // namespace RRR::util
