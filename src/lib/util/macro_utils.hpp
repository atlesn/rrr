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

#ifndef RRR_MACRO_UTILS_HPP
#define RRR_MACRO_UTILS_HPP

#define RRR_FUNC std::string(__func__)
#define RRR_STR(a) std::to_string(a)
#define RRR_EXP_TO_RET(func)                                   \
    do {try {                                                  \
        func;                                                  \
    }                                                          \
    catch (rrr::exp::bug &e) {                                 \
        throw e;                                               \
    }                                                          \
    catch (rrr::exp::normal &e) {                              \
        return e.num();                                        \
    }                                                          \
    catch (...) {                                              \
        RRR_MSG_0("Unknown exception in %s, triggering hard error\n", __func__); \
	return 1;                                              \
    }} while(0)                                                \

#endif /* RRR_MACRO_UTILS_HPP */
