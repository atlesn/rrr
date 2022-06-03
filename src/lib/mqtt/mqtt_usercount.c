/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>

#include "mqtt_usercount.h"
#include "../log.h"

int rrr_mqtt_p_usercount_init (
		struct rrr_mqtt_p_usercount *usercount,
		void (*destroy)(void *arg)
) {
	usercount->destroy = destroy;
	usercount->users = 1;

	return 0;
}

void rrr_mqtt_p_usercount_incref (
		struct rrr_mqtt_p_usercount *usercount
) {
	if (usercount->users == 0) {
		RRR_BUG("Users were 0 in %s\n", __func__);
	}

	usercount->users++;
}

void rrr_mqtt_p_usercount_decref (
		struct rrr_mqtt_p_usercount *usercount
) {
	if (usercount == NULL) {
		return;
	}

	--(usercount->users);

	if (usercount->users < 0) {
		RRR_BUG("Users were < 0 in %s\n", __func__);
	}
	if (usercount->users == 0) {
		usercount->destroy((void *) usercount);
	}
}

int rrr_mqtt_p_usercount_get_refcount (
		struct rrr_mqtt_p_usercount *usercount
) {
	int ret = 0;
	ret = usercount->users;
	return ret;
}
