/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "log.h"
#include "allocator.h"
#include "rrr_strerror.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"

static const char *general_error_message = "Unknown error";

struct rrr_strerror_node {
	RRR_LL_NODE(struct rrr_strerror_node);
	int num;
	char *str;
};

struct rrr_strerror_collection {
	RRR_LL_HEAD(struct rrr_strerror_node);
	int initialized;
};

static struct rrr_strerror_collection errors = {0};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int __rrr_strerror_node_destroy (
		struct rrr_strerror_node *node
) {
	RRR_FREE_IF_NOT_NULL(node->str);
	rrr_free(node);
	return 0;
}

void rrr_strerror_init (void) {
	pthread_mutex_lock(&lock);
	if (errors.initialized == 1) {
		RRR_BUG("Double initialization of rrr_strerror\n");
	}
	memset (&errors, '\0', sizeof(errors));
	errors.initialized = 1;
	pthread_mutex_unlock(&lock);
}

// Should only be called at program exit when other threads have finished. This
// because the find function returns pointers to our saved data.
void rrr_strerror_cleanup (void) {
	pthread_mutex_lock(&lock);
	if (errors.initialized != 1) {
		RRR_BUG("rrr_strerror cleanup called but we were not initialized\n");
	}
	RRR_LL_DESTROY(&errors, struct rrr_strerror_node, __rrr_strerror_node_destroy(node));
	errors.initialized = 0;
	pthread_mutex_unlock(&lock);
}

static const char *__rrr_strerror_find_error_or_register (int find_num) {
	struct rrr_strerror_node *new_node = NULL;
	const char *result = NULL;

	RRR_LL_ITERATE_BEGIN(&errors, struct rrr_strerror_node);
		if (node->num == find_num) {
			result = node->str;
			goto out;
		}
	RRR_LL_ITERATE_END();

	if (RRR_LL_COUNT(&errors) > 512) {
		RRR_BUG("Number of error messages got out control in __rrr_strerror_find_error_or_register when registering %i\n", find_num);
	}

	const char *tmp = strerror(find_num);
	new_node = rrr_allocate(sizeof(*new_node));
	if (new_node == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_strerror_find_error_or_register\n");
		return NULL;
	}

	new_node->num = find_num;
	new_node->str = rrr_strdup(tmp);

	if (new_node->str == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_strerror_find_error_or_register\n");
		goto out;
	}

	RRR_LL_UNSHIFT(&errors, new_node);
	result = new_node->str;
	new_node = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(new_node);
	return result;
}

const char *rrr_strerror (int find_num) {
	const char *str = NULL;

	if (find_num < 0) {
		RRR_MSG_0("Warning: Received negative value %i in rrr_strerror\n", find_num);
	}

	pthread_mutex_lock(&lock);

	if (errors.initialized != 1) {
		RRR_BUG("rrr_strerror not initialized in rrr_strerror\n");
	}
	str = __rrr_strerror_find_error_or_register(find_num);

	if (str == NULL) {
		str = general_error_message;
		RRR_MSG_0("Warning: Could not create error message for error number %i\n", find_num);
	}

//	printf ("Stored error messages: %i\n", RRR_LL_COUNT(&errors));

	pthread_mutex_unlock(&lock);

	return str;
}
