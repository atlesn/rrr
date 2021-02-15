/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MACRO_UTILS_H
#define RRR_MACRO_UTILS_H

#define RRR_UNUSED(x) \
	((void)(x))

#define RRR_PASTE(x, y) x ## y
#define RRR_PASTE_3(x, y, z) x ## y ## z
#define RRR_PASTE_4(a, b, c, d) a ## b ## c ## d

#define RRR_QUOTE(value) #value

#define RRR_FREE_IF_NOT_NULL(arg) do{if((arg) != NULL){free(arg);(arg)=NULL;}}while(0)

/* Compile time checks */
#define RRR_ASSERT_DEBUG
#ifdef RRR_ASSERT_DEBUG
#define RRR_ASSERT(predicate,name) \
	do{char _assertion_failed_##name##_[2*!!(predicate)-1];_assertion_failed_##name##_[0]='\0';(void)(_assertion_failed_##name##_);}while(0);
#else
#define RRR_ASSERT(predicate,name)
#endif

#endif /* RRR_MACRO_UTILS_H */
