/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CMODULE_SHARED_H
#define RRR_CMODULE_SHARED_H

struct rrr_cmodule_worker;
struct rrr_message;
struct rrr_message_addr;

// Functions from cmodule_native which are accessed by user cmodules must be
// declared here and not in cmodule_native.h

// Will always free the message also upon errors
int rrr_cmodule_worker_send_message_to_parent (
		struct rrr_cmodule_worker *worker,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr
);

#endif /* RRR_CMODULE_SHARED_H */
