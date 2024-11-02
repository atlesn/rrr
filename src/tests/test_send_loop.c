/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <assert.h>

#include "test.h"
#include "test_send_loop.h"

#include "../lib/allocator.h"
#include "../lib/send_loop.h"
#include "../lib/event/event.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/posix.h"

#define DID_PUSH 1
#define DID_RETURN 2
#define DID_RETRY 4
#define DID_SOFT 8
#define DID_HARD 16
#define DID_ORDER 32

#define DO_RETRY 64
#define DO_SOFT 128
#define DO_HARD 256
#define DO_ORDER 512

#define DID_RELATE 1

#define DO_RELATE 64

#define WAS_ERR 2048

static int __rrr_test_send_loop_push_callback (struct rrr_msg_holder *entry, void *arg) {
	int *result = arg;

	static uint64_t prev_index = 0;
	uint64_t index = rrr_msg_holder_send_index(entry);

	TEST_MSG("+ push entry %" PRIu64 " prev was %" PRIu64 "\n", index, prev_index);

	if ((*result) & DO_ORDER) {
		// This flag is not to be cleared
		if (prev_index > index) {
			TEST_MSG("+ Incorrect index order\n");
			(*result) |= WAS_ERR;
		}
		else {
			TEST_MSG("+ Correct index order\n");
			(*result) |= DID_ORDER;
		}
	}

	prev_index = index;

	if ((*result) & DO_RETRY) {
		(*result) &= ~(DO_RETRY);
		(*result) |= DID_RETRY;
		return RRR_SEND_LOOP_NOT_READY;
	}
	else if ((*result) & DO_SOFT) {
		(*result) &= ~(DO_SOFT);
		(*result) |= DID_SOFT;
		return RRR_SEND_LOOP_SOFT_ERROR;
	}
	else if ((*result) & DO_HARD) {
		(*result) &= ~(DO_HARD);
		(*result) |= DID_HARD;
		return RRR_SEND_LOOP_HARD_ERROR;
	}
	else {
		(*result) |= DID_PUSH;
	}

	return 0;
}

static int __rrr_test_send_loop_return_callback (struct rrr_msg_holder *entry, void *arg) {
	int *result = arg;

	uint64_t index = rrr_msg_holder_send_index(entry);

	TEST_MSG("+ return entry %" PRIu64 "\n", index);

	(*result) |= DID_RETURN;

	return 0;
}

static int __rrr_test_send_loop_related_callback (const struct rrr_msg_holder *entry, const struct rrr_msg_holder *entry_related, void *arg) {
	int *result = arg;

	uint64_t index = rrr_msg_holder_send_index(entry);
	uint64_t index_related = rrr_msg_holder_send_index(entry_related);

	assert(index_related > index);

	if (!((*result) & DO_RELATE)) {
		TEST_MSG("+ not relate %" PRIu64 " and  %" PRIu64 "\n", index, index_related);
		return 1;
	}

	TEST_MSG("+ relate %" PRIu64 " and %" PRIu64 "\n", index, index_related);

	(*result) &= ~(DO_RELATE);
	(*result) |= DID_RELATE;

	return 0;
}

static int __rrr_test_send_loop_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	(void)(arg);
	return 1;
}

int rrr_test_send_loop(void) {
	int ret = 0;

	struct rrr_msg_msg *msg[2];
	struct rrr_msg_msg *msg_ptr[2];
	struct rrr_msg_holder *entry[2];
	struct rrr_event_queue *queue = NULL;
	struct rrr_send_loop *send_loop = NULL;
	int ttl_reached;
	int timeout_reached;
	int result = 0;

	memset(msg, '\0', sizeof(msg));
	memset(entry, '\0', sizeof(entry));

	if ((ret = rrr_event_queue_new (&queue)) != 0) {
		TEST_MSG("Failed to create event queue in %s\n", __func__);
		goto out_final;
	}

	if ((ret = rrr_send_loop_new (
			&send_loop,
			queue,
			"test",
			0,
			0,
			0,
			RRR_SEND_LOOP_ACTION_DROP,
			__rrr_test_send_loop_push_callback,
			__rrr_test_send_loop_return_callback,
			NULL,
			&result
	)) != 0) {
		TEST_MSG("Failed to create send loop in %s\n", __func__);
		goto out_destroy_event_queue;
	}

	for (size_t i = 0; i < sizeof(msg) / sizeof(*msg); i++) {
		if ((ret = rrr_msg_msg_new_empty (
				&msg[i],
				MSG_TYPE_MSG,
				MSG_CLASS_DATA,
				rrr_time_get_64(),
				0,
				0
		)) != 0) {
			RRR_MSG_0("Failed to create message in %s\n", __func__);
			goto out;
		}

		if ((ret = rrr_msg_holder_new (
				&entry[i],
				MSG_TOTAL_SIZE(msg[i]),
				NULL,
				0,
				0,
				msg[i]
		)) != 0) {
			RRR_MSG_0("Failed to create entry in %s\n", __func__);
			goto out;
		}

		msg_ptr[i] = msg[i];
		msg[i] = NULL;
	}

	//////////////////////////////////////////////////////////////////////
	// Event test
	/////////////////////////////
	TEST_MSG("Test event run and remove...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_push(send_loop, entry[0]);
	rrr_msg_holder_unlock(entry[0]);

	if (rrr_event_dispatch_once(queue) != 0) {
		TEST_MSG("- Error from dispatch in %s\n", __func__);
		ret |= 1;
	}

	if (rrr_send_loop_count(send_loop) != 0) {
		TEST_MSG("- Message was not pushed\n");
		ret |= 1;
	}

	if (rrr_send_loop_event_pending(send_loop)) {
		TEST_MSG("- Send loop event still pending\n");
		ret |= 1;
	}

	TEST_MSG("Test event pending after retry...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_push(send_loop, entry[0]);
	rrr_msg_holder_unlock(entry[0]);

	result = DO_RETRY;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_RETRY) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	// Event is not added implicitly when direct call to run is performed
	rrr_send_loop_event_add_or_remove (send_loop);
	if (!rrr_send_loop_event_pending(send_loop)) {
		TEST_MSG("- Send loop event not pending despite retry\n");
		ret |= 1;
	}

	TEST_MSG("Test event removed after clear...\n");
	rrr_send_loop_clear(send_loop);

	if (rrr_send_loop_count(send_loop) != 0) {
		TEST_MSG("- Message was not cleared\n");
		ret |= 1;
	}

	rrr_send_loop_event_add_or_remove (send_loop);
	if (rrr_send_loop_event_pending(send_loop)) {
		TEST_MSG("- Send loop event still pending despite clear\n");
		ret |= 1;
	}

	TEST_MSG("Test event run by periodic start...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_push(send_loop, entry[0]);
	rrr_msg_holder_unlock(entry[0]);

	rrr_send_loop_event_remove(send_loop);
	if (rrr_send_loop_event_pending(send_loop)) {
		TEST_MSG("- Send loop event still pending despite remove\n");
		ret |= 1;
	}

	// The periodic event in send loop should re-add the event. Note that
	// the timer starts when the send loop is created, hence we should run
	// this early in the test.
	if (rrr_event_dispatch (
			queue,
			100 * 1000, // 100 ms. Send loop should not before  250 ms
			__rrr_test_send_loop_periodic,
			NULL
	) != 1) {
		TEST_MSG("- Unexpected return from event dispatch\n");
		ret |= 1;
	}

	if (rrr_send_loop_count(send_loop) != 1) {
		TEST_MSG("- Loop ran too early within 100ms\n");
		ret |= 1;
	}

	// Loop should run once within this dispatch
	if (rrr_event_dispatch (
			queue,
			200 * 1000, // 200 ms. Send loop should run within 250 ms
			__rrr_test_send_loop_periodic,
			NULL
	) != 1) {
		TEST_MSG("- Unexpected return from event dispatch\n");
		ret |= 1;
	}

	if (rrr_send_loop_count(send_loop) != 0) {
		TEST_MSG("- Count not zero after dispatch\n");
		ret |= 1;
	}

	if (rrr_send_loop_event_pending(send_loop)) {
		TEST_MSG("- Event still pending after dispatch\n");
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// TTL test
	/////////////////////////////
	TEST_MSG("Test TTL timeout...\n");

	rrr_send_loop_set_parameters(send_loop, 0, 1 /* 1 us */, 0, RRR_SEND_LOOP_ACTION_RETURN);

	rrr_msg_holder_lock(entry[0]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	rrr_send_loop_entry_prepare(send_loop, entry[0]);

	// Ensure timeout check does not return timeout if message is OK
	rrr_msg_holder_util_timeout_check(&ttl_reached, &timeout_reached, 10 * 1000 /* 10 ms */, 10 * 1000 /* 10 ms */, entry[0]);
	assert(!ttl_reached);
	assert(!timeout_reached);

	// Sleep to make times expire
	rrr_posix_usleep(10 * 1000); /* 10 ms */

	// Set both timers as function should return only TTL timeout even if both timers have expired
	rrr_msg_holder_util_timeout_check(&ttl_reached, &timeout_reached, 1 /* 1 us */, 1 /* 1 us */, entry[0]);
	assert(ttl_reached);
	assert(!timeout_reached);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);

	rrr_msg_holder_unlock(entry[0]);

	// TTL expiration always results in drop
	result = 0;
	if (rrr_send_loop_run(send_loop) != 0 || result != 0) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Timeout test
	/////////////////////////////
	TEST_MSG("Test send timeout...\n");
	rrr_send_loop_set_parameters(send_loop, 0, 0, 1 /* 1 us */, RRR_SEND_LOOP_ACTION_RETURN);

	rrr_msg_holder_lock(entry[0]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	rrr_send_loop_entry_prepare(send_loop, entry[0]);

	// Sleep to make times expire
	rrr_posix_usleep(10 * 1000); /* 10 ms */

	// Function returns only send timeout, not TTL timeout as it is disabled by setting it to 0
	rrr_msg_holder_util_timeout_check(&ttl_reached, &timeout_reached, 0, 1 /* 1 us */, entry[0]);
	assert(!ttl_reached);
	assert(timeout_reached);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);

	rrr_msg_holder_unlock(entry[0]);

	// Send time expiration should result in return
	result = 0;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_RETURN) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Push test
	/////////////////////////////
	TEST_MSG("Test Push...\n");
	rrr_send_loop_set_parameters(send_loop, 0, 10 * 1000, 10 * 1000, RRR_SEND_LOOP_ACTION_RETURN); // 10 ms timeouts

	rrr_msg_holder_lock(entry[0]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	rrr_send_loop_entry_prepare(send_loop, entry[0]);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);

	rrr_msg_holder_unlock(entry[0]);

	result = 0;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_PUSH) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Retry test
	/////////////////////////////
	TEST_MSG("Test retry...\n");
	rrr_msg_holder_lock(entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);
	rrr_msg_holder_unlock(entry[0]);

	result = DO_RETRY;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_RETRY) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	result = 0;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_PUSH) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Soft error test
	/////////////////////////////
	TEST_MSG("Test soft error...\n");
	rrr_msg_holder_lock(entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);
	rrr_msg_holder_unlock(entry[0]);

	result = DO_SOFT;
	if (rrr_send_loop_run(send_loop) != 0 || result != DID_SOFT) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Hard error test
	/////////////////////////////
	TEST_MSG("Test hard error...\n");
	rrr_msg_holder_lock(entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	rrr_send_loop_push(send_loop, entry[0]);
	assert(rrr_msg_holder_usercount(entry[0]) == 2);
	rrr_msg_holder_unlock(entry[0]);

	result = DO_HARD;
	if (rrr_send_loop_run(send_loop) != 1 || result != DID_HARD) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Preserve order
	/////////////////////////////
	TEST_MSG("Test incorrect order...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_msg_holder_lock(entry[1]);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	assert(rrr_msg_holder_usercount(entry[1]) == 1);

	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[1]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	msg_ptr[1]->timestamp = rrr_time_get_64();

	// Push in wrong order
	rrr_send_loop_push(send_loop, entry[1]);
	rrr_send_loop_push(send_loop, entry[0]);

	rrr_msg_holder_unlock(entry[1]);
	rrr_msg_holder_unlock(entry[0]);

	// Failing, not correct order
	result = DO_ORDER;
	rrr_send_loop_set_parameters(send_loop, 0 /* order off */, 10 * 1000, 10 * 1000, RRR_SEND_LOOP_ACTION_RETURN); // 10 ms timeouts
	if (rrr_send_loop_run(send_loop) != 0 || result != (WAS_ERR|DID_PUSH|DID_ORDER|DO_ORDER)) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	TEST_MSG("Test correct order...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_msg_holder_lock(entry[1]);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	assert(rrr_msg_holder_usercount(entry[1]) == 1);

	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[1]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	msg_ptr[1]->timestamp = rrr_time_get_64();

	// Push in wrong order
	rrr_send_loop_push(send_loop, entry[1]);
	rrr_send_loop_push(send_loop, entry[0]);

	rrr_msg_holder_unlock(entry[1]);
	rrr_msg_holder_unlock(entry[0]);

	// Success, correct order
	result = DO_ORDER;
	rrr_send_loop_set_parameters(send_loop, 1 /* order on */, 10 * 1000, 10 * 1000, RRR_SEND_LOOP_ACTION_RETURN); // 10 ms timeouts
	if (rrr_send_loop_run(send_loop) != 0 || result != (DID_ORDER|DID_PUSH|DO_ORDER)) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	//////////////////////////////////////////////////////////////////////
	// Touch related
	/////////////////////////////
	TEST_MSG("Test touch related...\n");
	rrr_msg_holder_lock(entry[0]);
	rrr_msg_holder_lock(entry[1]);

	assert(rrr_msg_holder_usercount(entry[0]) == 1);
	assert(rrr_msg_holder_usercount(entry[1]) == 1);

	rrr_send_loop_entry_prepare(send_loop, entry[0]);
	rrr_send_loop_entry_prepare(send_loop, entry[1]);

	msg_ptr[0]->timestamp = rrr_time_get_64();
	msg_ptr[1]->timestamp = rrr_time_get_64();

	rrr_send_loop_push(send_loop, entry[0]);
	rrr_send_loop_push(send_loop, entry[1]);

	uint64_t old_send_time = rrr_msg_holder_send_time(entry[1]);

	rrr_msg_holder_unlock(entry[1]);
	rrr_msg_holder_unlock(entry[0]);

	rrr_posix_usleep(1000 /* 1 ms */);

	// Not related
	result = 0;
	rrr_send_loop_entry_touch_related(send_loop, entry[0], __rrr_test_send_loop_related_callback, &result);
	if (result != 0) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	rrr_msg_holder_lock(entry[1]);
	if (rrr_msg_holder_send_time(entry[1]) != old_send_time) {
		TEST_MSG("- Send time differed unexpectedly\n");
		ret |= 1;
	}
	rrr_msg_holder_unlock(entry[1]);

	// Related
	result = DO_RELATE;
	rrr_send_loop_entry_touch_related(send_loop, entry[0], __rrr_test_send_loop_related_callback, &result);
	if (result != DID_RELATE) {
		TEST_MSG("- Failed ret %i result %i\n", ret, result);
		ret |= 1;
	}

	rrr_msg_holder_lock(entry[1]);
	if (rrr_msg_holder_send_time(entry[1]) == old_send_time) {
		TEST_MSG("- Send time did not differ\n");
		ret |= 1;
	}
	rrr_msg_holder_unlock(entry[1]);

	out:
		for (size_t i = 0; i < sizeof(msg) / sizeof(*msg); i++) {
			if (entry[i] != NULL)
				rrr_msg_holder_decref(entry[i]);
			RRR_FREE_IF_NOT_NULL(msg[i]);
		}
		rrr_send_loop_destroy(send_loop);
	out_destroy_event_queue:
		rrr_event_queue_destroy(queue);
	out_final:
		return ret;
}
