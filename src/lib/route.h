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

#ifndef RRR_ROUTE_H
#define RRR_ROUTE_H

struct rrr_route;
struct rrr_parse_pos;

enum rrr_route_fault {
	RRR_ROUTE_FAULT_OK,
	RRR_ROUTE_FAULT_CRITICAL,
	RRR_ROUTE_FAULT_END_MISSING,
	RRR_ROUTE_FAULT_SYNTAX_ERROR,
	RRR_ROUTE_FAULT_INVALID_VALUE,
	RRR_ROUTE_FAULT_VALUE_MISSING,
	RRR_ROUTE_FAULT_INVALID_TYPE,
	RRR_ROUTE_FAULT_STACK_COUNT
};

void rrr_route_destroy (
		struct rrr_route *route
);
int rrr_route_interpret (
		enum rrr_route_fault *fault,
		struct rrr_route **result,
		struct rrr_parse_pos *pos
);

#endif /* RRR_ROUTE_H */
