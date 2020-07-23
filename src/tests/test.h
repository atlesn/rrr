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

#ifndef RRR_TEST_H
#define RRR_TEST_H

#define TEST_MSG(...) \
	do {printf (__VA_ARGS__);}while(0)

#define TEST_BEGIN(...) \
	do { printf("Testing %s: ", __VA_ARGS__); do

#define TEST_RESULT(ok) \
	while(0); printf("%s\n", (ok) ? "passed" : "failed");} while (0)

#endif /* RRR_TEST_H */
