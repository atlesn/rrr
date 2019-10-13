/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_STRING_BUILDER_H
#define RRR_STRING_BUILDER_H

struct rrr_string_builder {
	ssize_t size;
	ssize_t wpos;
	char *buf;
};

#define RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder,str,err_str)		\
		do {if (rrr_string_builder_append((string_builder), str) != 0) {	\
			VL_MSG_ERR(err_str);											\
			ret = 1;														\
			goto out;														\
		}} while(0)

void rrr_string_builder_clear (struct rrr_string_builder *string_builder);
int rrr_string_builder_append (struct rrr_string_builder *string_builder, const char *str);

#endif /* RRR_STRING_BUILDER_H */
