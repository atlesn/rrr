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

#ifndef RRR_SENDERS_H
#define RRR_SENDERS_H

struct instance_metadata; /* From instances.h */

struct instance_sender {
	struct instance_metadata *sender;
	struct instance_sender *next;
};

struct instance_sender_collection {
	struct instance_sender *first_sender;
};

#define RRR_SENDER_LOOP(target,collection) \
	for (struct instance_sender *target = (collection)->first_sender; target != NULL; target = target->next)

void senders_init (struct instance_sender_collection *collection);
int senders_check_empty (struct instance_sender_collection *collection);
int senders_check_exists (struct instance_sender_collection *collection, struct instance_metadata *sender);
int senders_add_sender (struct instance_sender_collection *collection, struct instance_metadata *sender);
void senders_clear (struct instance_sender_collection *collection);
int senders_count (struct instance_sender_collection *collection);
int senders_iterate (
		struct instance_sender_collection *collection,
		int (*callback)(struct instance_metadata *sender, void *arg),
		void *arg
);

#endif /* RRR_SENDERS_H */
