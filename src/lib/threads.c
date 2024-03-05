/*

Read Route Record

Copyright (C) 2018-2024 Atle Solbakken atle@goliathdns.no

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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "util/rrr_time.h"
#include "util/macro_utils.h"
#include "util/slow_noop.h"
#include "util/gnu.h"
#include "util/posix.h"
#include "allocator.h"
#include "cmdlineparser/cmdline.h"
#include "threads.h"
#include "rrr_strerror.h"
#include "log.h"

// Very harsh option to make watchdogs stop checking alive timers of threads
//#define RRR_THREAD_INCAPACITATE_WATCHDOGS

// Threads which does not shutdown nicely will remain while others shut down
//#define RRR_THREAD_DISABLE_CANCELLING

// Set this higher (like 1000) when debugging
#define RRR_THREAD_FREEZE_LIMIT_FACTOR 1

// Misc. initialization failure simulations
// #define RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_A
// #define RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_B
		
#define RRR_THREAD_WATCHDOG_SLEEPTIME_MS 500

static void __rrr_thread_managed_data_cleanup (
		struct rrr_thread *thread
) {
	RRR_DBG_8 ("Thread %s managed data cleanup\n", thread->name);

	RRR_LL_ITERATE_BEGIN(&thread->managed_data, struct rrr_thread_managed_data);
		node->destroy(node->data);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&thread->managed_data, 0; rrr_free(node));
}

static void __rrr_thread_managed_data_cleanup_if_not_started (
		struct rrr_thread *thread
) {
	if (thread->started) {
		RRR_DBG_8 ("Thread %s not cleaning up managed as it is started. Thread must clean up itself.\n", thread->name);
		return;
	}
	__rrr_thread_managed_data_cleanup(thread);
}

int rrr_thread_managed_data_push (
		struct rrr_thread *thread,
		void *data,
		void (*destroy)(void *data)
) {
	int ret = 0;

	struct rrr_thread_managed_data *managed_data;

	if ((managed_data = rrr_allocate_zero (sizeof(*managed_data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	managed_data->data = data;
	managed_data->destroy = destroy;

	RRR_LL_PUSH(&thread->managed_data, managed_data);

	out:
	return ret;
}

static int __rrr_thread_destroy (
		struct rrr_thread *thread
) {
	__rrr_thread_managed_data_cleanup_if_not_started(thread);
	pthread_cond_destroy(&thread->signal_cond);
	pthread_mutex_destroy(&thread->signal_cond_mutex);
	rrr_free(thread);
	return 0;
}

void rrr_thread_signal_set (
		struct rrr_thread *thread,
		uint32_t signal
) {
	RRR_DBG_8 ("Thread %s set signal %d\n", thread->name, signal);

	rrr_atomic_u32_fetch_or(&thread->state_and_signal, signal);

	int ret_tmp;
	pthread_mutex_lock(&thread->signal_cond_mutex);
	if ((ret_tmp = pthread_cond_broadcast(&thread->signal_cond)) != 0) {
		RRR_MSG_0("Warning: Error %i from pthread_cond_broadcast in %s, error will not be handled\n", ret_tmp, __func__);
	}
	pthread_mutex_unlock(&thread->signal_cond_mutex);
}

void rrr_thread_signal_wait_busy (
		struct rrr_thread *thread,
		uint32_t signal
) {
	while (1) {
		if (rrr_thread_signal_check(thread, signal)) {
			break;
		}
		rrr_posix_usleep (10000); // 10ms
	}
}

static void __rrr_thread_signal_wait_cond_timed (
		struct rrr_thread *thread
) {
	struct timespec wakeup_time;
	rrr_time_gettimeofday_timespec(&wakeup_time, 1 * 1000 * 1000); // 1 second

	pthread_mutex_lock(&thread->signal_cond_mutex);
	int ret_tmp = pthread_cond_timedwait(&thread->signal_cond, &thread->signal_cond_mutex, &wakeup_time);
	pthread_mutex_unlock(&thread->signal_cond_mutex);

	if (ret_tmp != 0) {
		switch (errno) {
			case EAGAIN:
			case ETIMEDOUT:
			case 0:
				break;
			default:
				RRR_MSG_0("Unknown return value %i '%s' in %s, trying to continue\n",
					errno, rrr_strerror(errno), __func__);
				break;
			}
	}
}

static void __rrr_thread_signal_wait_cond (
		struct rrr_thread *thread,
		uint32_t signal,
		int with_watchdog_update
) {
	while (1) {
		if (with_watchdog_update)
			rrr_thread_watchdog_time_update(thread);

		if (rrr_thread_signal_check(thread, signal))
			break;

		__rrr_thread_signal_wait_cond_timed(thread);
	}
}

void rrr_thread_signal_wait_cond_with_watchdog_update (
		struct rrr_thread *thread,
		uint32_t signal
) {
	__rrr_thread_signal_wait_cond (thread, signal, 1);
}

void rrr_thread_signal_wait_cond (
		struct rrr_thread *thread,
		uint32_t signal
) {
	__rrr_thread_signal_wait_cond(thread, signal, 0);
}

void rrr_thread_state_set (
		struct rrr_thread *thread,
		uint32_t new_state
) {
	uint32_t old_state;

	RRR_DBG_8 ("Thread %s setting state %i\n", thread->name, new_state);

	old_state = rrr_atomic_u32_fetch_and(&thread->state_and_signal, RRR_THREAD_SIGNAL_MASK);
	rrr_atomic_u32_fetch_or(&thread->state_and_signal, new_state);

	assert(old_state != new_state);
	assert(!(old_state & RRR_THREAD_STATE_STOPPED));
	assert(!(old_state & RRR_THREAD_STATE_GHOST));
	assert(!(old_state & RRR_THREAD_STATE_READY_TO_DESTROY));

	if (new_state == RRR_THREAD_STATE_STOPPED && (
		!(old_state & RRR_THREAD_STATE_RUNNING_FORKED) &&
		!(old_state & RRR_THREAD_STATE_INITIALIZED) &&
		!(old_state & RRR_THREAD_STATE_STOPPING)
	)) {
		RRR_MSG_0 ("Warning: Setting STOPPED state of thread %p name %s which never completed initialization\n",
				thread, thread->name);
	}
}

static uint32_t __rrr_thread_state_get (
		struct rrr_thread *thread
) {
	return rrr_atomic_u32_load(&thread->state_and_signal) & RRR_THREAD_STATE_MASK;
}

static int __rrr_thread_collection_has_thread (
		struct rrr_thread_collection *collection,
		struct rrr_thread *thread
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node == thread) {
			ret = 1;
			break;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

static int __rrr_thread_new (
		struct rrr_thread **target,
		int is_watchdog
) {
	int ret = 0;

	*target = NULL;

#ifdef RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_A
	ret = 1;
	goto out;
#endif

	struct rrr_thread *thread = rrr_allocate_zero(sizeof(*thread));
	if (thread == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_DBG_8 ("Allocate thread %p\n", thread);

	if (rrr_posix_mutex_init(&thread->signal_cond_mutex, 0) != 0) {
		RRR_MSG_0("Could not create mutex in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	if (rrr_posix_cond_init(&thread->signal_cond, 0) != 0) {
		RRR_MSG_0("Could not create condition in %s\n", __func__);
		ret = 1;
		goto out_destroy_mutex;
	}

	thread->is_watchdog = is_watchdog;

	*target = thread;

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&thread->signal_cond_mutex);
	out_free:
		rrr_free(thread);
	out:
		return ret;
}

int rrr_thread_collection_count (
		struct rrr_thread_collection *collection
) {
	return RRR_LL_COUNT(collection);
}

int rrr_thread_collection_new (
		struct rrr_thread_collection **target
) {
	int ret = 0;

	*target = NULL;

	struct rrr_thread_collection *collection = rrr_allocate(sizeof(*collection));
	if (collection == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_thread_new_collection\n");
		ret = 1;
		goto out;
	}

	memset(collection, '\0', sizeof(*collection));

	*target = collection;

	goto out;
	//out_free:
	//	rrr_free(collection);
	out:
		return ret;
}

static void __rrr_thread_collection_stop_and_join_all_nolock (
		struct rrr_thread_collection *collection
) {
	RRR_DBG_8 ("Stopping all threads\n");

	// No errors allowed in this function

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (!node->started) {
			RRR_DBG_8 ("Thread %s is not started, not stopping\n", node->name);
			RRR_LL_ITERATE_NEXT();
		}

		if (node->is_watchdog) {
			// Setting encourage stop to watchdog makes it skip initial 1 second
			// startup grace should it not already have been started
			RRR_DBG_8 ("Setting encourage stop and start signal thread WD '%s'/%p\n", node->name, node);
		}
		else {
			RRR_DBG_8 ("Setting encourage stop and start signal thread %s/%p\n", node->name, node);
		}

		// Signals are set both in single thread mode and multi thread mode
		rrr_atomic_u32_fetch_or(&node->state_and_signal,
			RRR_THREAD_SIGNAL_ENCOURAGE_STOP |
			RRR_THREAD_SIGNAL_START_INITIALIZE |
			RRR_THREAD_SIGNAL_START_BEFOREFORK |
			RRR_THREAD_SIGNAL_START_AFTERFORK |
			RRR_THREAD_SIGNAL_START_WATCHDOG
		);
	RRR_LL_ITERATE_END();

	// Join with the watchdogs. The other threads might be in hung up state.
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (!node->started) {
			RRR_DBG_8 ("Thread watchdog %s is not started, not stopping\n", node->name);
			RRR_LL_ITERATE_NEXT();
		}

		if (node->is_watchdog) {
			RRR_DBG_8 ("Joining with thread watchdog %s\n", node->name);
			void *ret;
			pthread_join(node->thread, &ret);
			RRR_DBG_8 ("Joined with thread watchdog %s\n", node->name);
		}
	RRR_LL_ITERATE_END();
}

void rrr_thread_collection_destroy (
		int *ghost_count,
		struct rrr_thread_collection *collection
) {
	if (ghost_count != NULL)
		*ghost_count = 0;

	// No errors allowed in this function

	__rrr_thread_collection_stop_and_join_all_nolock(collection);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (rrr_thread_state_check(node, RRR_THREAD_STATE_GHOST)) {
			RRR_MSG_0 ("Thread %s is ghost when freeing all threads. Not freeing memory.\n",
				node->name);

			if (ghost_count != NULL)
				(*ghost_count)++;
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_thread_destroy(node));

	rrr_free(collection);
}

static int __rrr_thread_wait_for_state_initialized (
		struct rrr_thread *thread
) {
	int ret = 0;

	int was_ok = 0;

	// This function is not safe to use while a thread forks

	const unsigned long long max = 120;
	unsigned long long int j;
	for (j = 0; j <= max; j++)  {
		if (rrr_thread_state_check(thread, RRR_THREAD_STATE_RUNNING_FORKED)) {
			RRR_BUG("BUG: Thread %p name %s started prior to receiving signal\n", thread, thread->name);
		}
		else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_INITIALIZED|RRR_THREAD_STATE_STOPPED)) {
			was_ok = 1;
			break;
		}
		rrr_posix_usleep(25000); // 25 ms
	}

	if (was_ok != 1) {
		RRR_MSG_0 ("Thread %s did not transition to INITIALIZED in time, state is now %" PRIu32 "\n",
				thread->name, __rrr_thread_state_get(thread));
		ret = 1;
		assert(0);
		goto out;
	}

	RRR_DBG_8("Thread %p name %s waiting ticks for INITIALIZED: %llu\n", thread, thread->name, j);

	out:
	return ret;
}

static int __rrr_thread_wait_for_state_forked (
		struct rrr_thread *thread
) {
	int ret = 0;

	// THE THREAD WE ARE WAITING FOR MIGHT BE FORKING NOW

	// - Do not perform any non async safe syscalls here as another thread might be forking.
	// - Do not perform any logging except from when we want to crash or there is an error.
	//   If there is an error, it does not matter if the fork deadlocks as we will kill it
	//   off anyway.
	// - Also, do not lock to read the thread state even though the fork should not use
	//   existing thread structures. Don't do validation on the value, only check with ==
	//   if it gets the value we want.

	int was_ok = 0;

	const unsigned long long max = 100; // ~ 5 seconds
	unsigned long long int j;
	for (j = 0; j <= max; j++)  {
		if (rrr_thread_state_check(thread, RRR_THREAD_STATE_RUNNING_FORKED|RRR_THREAD_STATE_STOPPED)) {
			was_ok = 1;
			break;
		}

		if (j > max / 2) {
			rrr_posix_msleep_signal_safe (100); // 100 ms
		}

		rrr_posix_msleep_signal_safe (25); // 25 ms
	}

	if (was_ok != 1) {
		RRR_MSG_0 ("Thread %s did not transition to FORKED in time, state is now %" PRIu32 "\n",
				thread->name, __rrr_thread_state_get(thread));
		ret = 1;
		goto out;
	}

	RRR_DBG_8("Thread %p name %s waiting ticks for FORKED: %llu\n", thread, thread->name, j);

	out:
	return ret;
}

static int  __rrr_thread_collection_start_signal_all_wait_for_state_initialized (
		struct rrr_thread_collection *collection
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog == 1) {
			RRR_LL_ITERATE_NEXT();
		}
		if ((ret = __rrr_thread_wait_for_state_initialized(node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static void __rrr_thread_start_condition_helper_nofork (
		struct rrr_thread *thread,
		int do_nice_wait
) {
	rrr_thread_state_set(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_cond_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	rrr_thread_state_set(thread, RRR_THREAD_STATE_RUNNING_FORKED);
	if (do_nice_wait) {
		// This is unsafe to call if other threads are forking !
		rrr_thread_signal_wait_cond_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);
	}
	else {
		rrr_thread_signal_wait_busy(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);
	}
}

void rrr_thread_start_condition_helper_nofork (
		struct rrr_thread *thread
) {
	__rrr_thread_start_condition_helper_nofork(thread, 0);
}

// Only use when it's guaranteed that no other thread in
// the collection will attempt a fork()
void rrr_thread_start_condition_helper_nofork_nice (
		struct rrr_thread *thread
) {
	__rrr_thread_start_condition_helper_nofork(thread, 1);
}

int rrr_thread_start_condition_helper_fork (
		struct rrr_thread *thread,
		int (*fork_callback)(void *arg),
		void *callback_arg
) {
	rrr_thread_state_set(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_cond_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);

	int ret = fork_callback(callback_arg);

	rrr_thread_state_set(thread, RRR_THREAD_STATE_RUNNING_FORKED);
	rrr_thread_signal_wait_busy(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);

	return ret;
}

void rrr_thread_collection_signal_start_no_procedure_all (
		struct rrr_thread_collection *collection
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog)
			continue;

		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_SINGLE_MODE);
		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_INITIALIZE);
		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_BEFOREFORK);
		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_AFTERFORK);
	RRR_LL_ITERATE_END();
}

int rrr_thread_collection_signal_start_procedure_all (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
) {
	int ret = 0;

	/* Signal threads to proceed to initialization stage. This is needed as some
	 * threads might need data from each other, and we ensure here that the downstream
	 * modules functions are not started untill all threads have been started */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_INITIALIZE);
	RRR_LL_ITERATE_END();

	/* Wait for all threads to initialize */
	if ((ret = __rrr_thread_collection_start_signal_all_wait_for_state_initialized (
			collection
	)) != 0) {
		goto out;
	}

	/* Signal threads to proceed to fork stage.
	 * The threads must then fork one by one as there might be race conditions
	 * if debug messages are printed in the fork helper functions. */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog == 1) {
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_8 ("START_BEFOREFORK signal to thread %p name %s and waiting for it to complete forking\n", node, node->name);

		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_BEFOREFORK);

		// FORKING IN PROGRESS, ONLY ASYNC SAFE LIBRARY FUNCTIONS ALLOWED UNTIL THREAD CHANGES STATE
		// DEBUG MESSAGES ALSO NOT ALLOWED

		if ((ret = __rrr_thread_wait_for_state_forked(node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	RRR_DBG_8 ("All threads are now RUNNNIG_FORKED\n");

	/* Start all threads based on callback condition */
	int must_retry = 0;
	do {
		if (must_retry) {
			rrr_posix_usleep(5000); // 5 ms
		}

		must_retry = 0;

		RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
			if (node->is_watchdog) {
				RRR_LL_ITERATE_NEXT();
			}

			int do_start = 1;
			if (start_check_callback != NULL && start_check_callback(&do_start, node, callback_arg) != 0) {
				RRR_MSG_0("Error from start check callback in %s\n", __func__);
				ret = 1;
				goto out;
			}

			if (do_start == 1) {
				RRR_DBG_8 ("START_AFTERFORK signal to thread %p name %s\n", node, node->name);
				rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_AFTERFORK);
			}
			else {
				must_retry = 1;
			}
		RRR_LL_ITERATE_END();
	} while (must_retry);

	/* Double check that everything was started */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog != 1 && !rrr_thread_signal_check(node, RRR_THREAD_SIGNAL_START_AFTERFORK)) {
			RRR_BUG("Bug: Thread %s did not receive start signal\n", node->name);
		}
	RRR_LL_ITERATE_END();

	/* Start watchdogs. If something fails and we don't get around to do this,
	 * the stop_and_join function will start watchdogs. */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog == 1) {
			RRR_DBG_8("START watchdog %p '%s'\n", node, node->name);
			rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_WATCHDOG);
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

void rrr_thread_start_now_with_watchdog (
		struct rrr_thread *thread
) {
	struct rrr_thread *wd = thread->watchdog;

	RRR_DBG_8("START thread %p '%s'\n", thread, thread->name);
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK|RRR_THREAD_SIGNAL_START_AFTERFORK);

	RRR_DBG_8("START watchdog %p '%s'\n", wd, wd->name);
	rrr_thread_signal_set(wd, RRR_THREAD_SIGNAL_START_WATCHDOG);
}

void rrr_thread_initialize_now_with_watchdog (
		struct rrr_thread *thread
) {
	struct rrr_thread *wd = thread->watchdog;

	RRR_DBG_8("INITIALIZE thread %p '%s'\n", thread, thread->name);
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_START_INITIALIZE);

	RRR_DBG_8("INITIALIZE watchdog %p '%s'\n", wd, wd->name);
	rrr_thread_signal_set(wd, RRR_THREAD_SIGNAL_START_INITIALIZE);
}

static void __rrr_thread_collection_add_thread (
		struct rrr_thread_collection *collection,
		struct rrr_thread *thread
) {
//	VL_DEBUG_MSG_1 ("Adding thread %p to collection %p\n", thread, collection);

	if (__rrr_thread_collection_has_thread(collection, thread)) {
		RRR_BUG("BUG: Attempted to add thread to collection in which it was already part of\n");
	}

	RRR_LL_APPEND(collection, thread);
}

static void __rrr_thread_set_name (
		const struct rrr_thread *thread
) {
	char buf[RRR_THREAD_NAME_MAX_LENGTH * 2 + 8];
	sprintf(buf, "%s", thread->name);
	// Maximum length seems to be 16 characters, at least on Linux
	buf[15] = '\0';
	rrr_set_thread_name(pthread_self(), buf);
}

struct watchdog_data {
	struct rrr_thread *watchdog_thread;
	struct rrr_thread *watched_thread;
};

static void *__rrr_thread_watchdog_entry (
		void *arg
) {
	// Copy the data and free it immediately
	struct watchdog_data data = *((struct watchdog_data *)arg);
	rrr_free(arg);

	uint64_t freeze_limit = 0;

	struct rrr_thread *thread = data.watched_thread;
	struct rrr_thread *self_thread = data.watchdog_thread;

	__rrr_thread_set_name(self_thread);

	freeze_limit = thread->watchdog_timeout_us;

	RRR_DBG_8 ("Watchdog %p for %s/%p started, waiting for start signals\n", self_thread, thread->name, thread);

	rrr_thread_signal_wait_cond(self_thread, RRR_THREAD_SIGNAL_START_INITIALIZE);
	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_INITIALIZED);

	// Use conditional wait to avoid spinning if the main thread
	// not meant to be started immediately
	rrr_thread_signal_wait_cond(self_thread, RRR_THREAD_SIGNAL_START_WATCHDOG);
	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_RUNNING_FORKED);

	RRR_DBG_8 ("Watchdog %p for %s/%p start signals received\n", self_thread, thread->name, thread);

	if (rrr_thread_signal_encourage_stop_check(self_thread)) {
		RRR_DBG_8 ("Watchdog %p for %s/%p, no startup grace as encourage stop signal is set\n",
			self_thread, thread->name, thread);
	}
	else {
		rrr_posix_usleep(1000000);
		RRR_DBG_8 ("Watchdog %p for %s/%p, finished waiting.\n",
			self_thread, thread->name, thread);
	}
	rrr_thread_watchdog_time_update(thread);

#ifdef RRR_THREAD_INCAPACITATE_WATCHDOGS
	while (1) {
		rrr_posix_usleep(5000000);
	}
#endif

	uint64_t prev_loop_time = rrr_time_get_64();
	while (1) {
		uint64_t nowtime = rrr_time_get_64();

		// Main might try to stop the thread
		if (rrr_thread_signal_encourage_stop_check(thread)) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread received encourage stop\n", self_thread, thread->name, thread);
			break;
		}

		if (!rrr_thread_state_check(thread, RRR_THREAD_STATE_RUNNING_FORKED) &&
		    !rrr_thread_state_check(thread, RRR_THREAD_STATE_INITIALIZED)
		) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread state is not RUNNING or INITIALIZED\n", self_thread, thread->name, thread);
			break;
		}
		else if (!rrr_config_global.no_watchdog_timers &&
		         (rrr_atomic_u64_load_relaxed(&thread->watchdog_time) + freeze_limit * RRR_THREAD_FREEZE_LIMIT_FACTOR < nowtime)
		) {
			if (nowtime - prev_loop_time > RRR_THREAD_WATCHDOG_SLEEPTIME_MS * 1000 * 1.1) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread has been frozen but so has the watchdog, maybe we are debugging?\n",
					self_thread, thread->name, thread);
			}
			else {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread froze, attempting encourage stop\n", self_thread, thread->name, thread);
				break;
			}
		}

		prev_loop_time = nowtime;

		if (rrr_thread_state_check(thread, RRR_THREAD_STATE_INITIALIZED)) {
			// Wait for any signal change
			__rrr_thread_signal_wait_cond_timed(thread);
		}
		else {
			rrr_posix_usleep (RRR_THREAD_WATCHDOG_SLEEPTIME_MS * 1000);
		}
	}

	RRR_DBG_8 ("Watchdog %p for %s/%p, executing shutdown routines\n", self_thread, thread->name, thread);

	if (rrr_thread_state_check(thread, RRR_THREAD_STATE_STOPPED)) {
		RRR_DBG_8 ("Watchdog %p for %s/%p, Thread has stopped by itself\n", self_thread, thread->name, thread);
		goto out_nostop;
	}
	else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_NEW)) {
		RRR_MSG_0("Warning: Watchdog %p for %s/%p, thread state is still NEW when WD shutdown routines begin\n", self_thread, thread->name, thread);
	}
	else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_INITIALIZED)) {
		RRR_DBG_8("Note: Watchdog %p for %s/%p thread state is still INITIALIZED when WD shutdown routines begin\n", self_thread, thread->name, thread);
	}
	
	// Ensure this is always set
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP);
	
	RRR_DBG_8 ("Watchdog %p for %s/%p, waiting for thread to set STOPPED pass 1/2, current state is: %" PRIu32 "\n",
		self_thread, thread->name, thread, __rrr_thread_state_get(thread));

	// Wait for thread to set STOPPED
	uint64_t killtime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
	uint64_t patient_stop_time = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_PATIENT_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
#ifndef RRR_THREAD_DISABLE_CANCELLING
	while (!rrr_thread_state_check(thread, RRR_THREAD_STATE_STOPPED)) {
		uint64_t nowtime = rrr_time_get_64();

		// If the shutdown routines of a thread usually take some time, it
		// may set STOPPING after it's loop has ended.
		if (rrr_thread_state_check(thread, RRR_THREAD_STATE_STOPPING) && nowtime < patient_stop_time) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread has set STOPPING state, being more patient\n", self_thread, thread->name, thread);
			rrr_posix_usleep(500000); // 500ms
		}
		else if (nowtime > killtime) {
			RRR_MSG_0 ("Watchdog %p for %s/%p, thread not responding to encourage stop. State is now %" PRIu32 ". Trying to cancel it.\n",
				self_thread, thread->name, thread, __rrr_thread_state_get(thread));
			pthread_cancel(thread->thread);
			break;
		}

		rrr_posix_usleep (10000); // 10 ms
	}
#else
	RRR_DBG_8 ("Watchdog %p for %s/%p, thread watchdog cancelling disabled, soft stop signals only\n", self_thread, thread->name, thread);
#endif

	RRR_DBG_8 ("Watchdog %p for %s/%p to set STOPPED pass 2/2, current state is: %" PRIu32 "\n",
		self_thread, thread->name, thread, __rrr_thread_state_get(thread));

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	uint64_t ghosttime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
	while (!rrr_thread_state_check(thread, RRR_THREAD_STATE_STOPPED)) {
		uint64_t nowtime = rrr_time_get_64();
		if (nowtime > ghosttime) {
			RRR_MSG_0 ("Watchdog %p for %s/%p, thread not responding to cancellation.\n",
				self_thread, thread->name, thread);
			if (rrr_thread_state_check(thread, RRR_THREAD_STATE_NEW)) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in NEW, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_INITIALIZED)) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in INITIALIZED, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_RUNNING_FORKED)) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in RUNNING_FORKED, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_check(thread, RRR_THREAD_STATE_STOPPING)) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in STOPPING, it has started cleanup but this has not completed.\n",
					self_thread, thread->name, thread);
			}
			RRR_MSG_0 ("Watchdog %p for %s/%p, tagging thread as ghost.\n", self_thread, thread->name, thread);
			rrr_thread_state_set(thread, RRR_THREAD_STATE_GHOST);
			break;
		}

		rrr_posix_usleep (10000); // 10 ms
	}

	out_nostop:

	RRR_DBG_8 ("Watchdog %p for %s/%p, thread state upon WD out: %i\n",
		self_thread, thread->name, thread, __rrr_thread_state_get(thread));

	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_STOPPED);

	pthread_exit(0);
}

static void __rrr_thread_cleanup (
		void *arg
) {
	struct rrr_thread *thread = arg;

	if (rrr_thread_state_check(thread, RRR_THREAD_STATE_GHOST)) {
		RRR_MSG_0 ("Thread %s waking up after being ghost\n", thread->name);
	}

	__rrr_thread_managed_data_cleanup(thread);
}

static void __rrr_thread_state_set_stopped (
		void *arg
) {
	struct rrr_thread *thread = arg;
	rrr_thread_state_set(thread, RRR_THREAD_STATE_STOPPED);
}

static int __rrr_thread_wait_for_signal_and_init (
		int *encourage_stop,
		struct rrr_thread *thread
) {
	int ret = 0;

	*encourage_stop = 0;

	rrr_thread_signal_wait_busy(thread, RRR_THREAD_SIGNAL_START_INITIALIZE);

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		RRR_DBG_8("Thread %p/%s received encourage stop before initializing, exiting\n", thread, thread->name);
		*encourage_stop = 1;
		goto out;
	}

	RRR_DBG_8("Thread %p/%s TID %llu received initialize signal, proceeding to init\n",
		thread, thread->name, (long long unsigned int) rrr_gettid());

	if ((ret = thread->init(thread)) != 0) {
		RRR_MSG_0 ("Error from initialization function of thread %p/%s TID %llu\n",
			thread, thread->name, (long long unsigned int) rrr_gettid());
		goto out;
	}

	RRR_DBG_8("Thread %p/%s TID %llu init complete\n",
		thread, thread->name, (long long unsigned int) rrr_gettid());

	out:
	return ret;
}

static void *__rrr_thread_start_routine_intermediate (
		void *arg
) {
	struct rrr_thread *thread = arg;

	int encourage_stop = 0;

	__rrr_thread_set_name(thread);

	// STOPPED must be set at the very end as it allows data structures to be freed

	pthread_cleanup_push(__rrr_thread_state_set_stopped, thread);
	pthread_cleanup_push(__rrr_thread_cleanup, thread);

	if (__rrr_thread_wait_for_signal_and_init(&encourage_stop, thread) != 0 || encourage_stop) {
		goto out_cleanup;
	}

	if (thread->run(thread) != 0) {
		RRR_MSG_0 ("Error from run function of thread %p/%s TID %llu\n",
			thread, thread->name, (long long unsigned int) rrr_gettid());
	}

	RRR_DBG_8("Thread %p/%s TID %llu run complete\n",
		thread, thread->name, (long long unsigned int) rrr_gettid());

	out_cleanup:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

static int __rrr_thread_start (
		struct rrr_thread *thread,
		struct watchdog_data **watchdog_data
) {
	int ret = 0;
	int err = 0;

	err = pthread_create(&thread->thread, NULL, __rrr_thread_start_routine_intermediate, thread);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting thread: %s\n", rrr_strerror(err));
		ret = 1;
		goto out;
	}
	pthread_detach(thread->thread);

	thread->started = 1;

	RRR_DBG_8 ("Started thread %s pthread address %p, it is now detached\n", thread->name, &thread->thread);

	err = pthread_create(&thread->watchdog->thread, NULL, __rrr_thread_watchdog_entry, *watchdog_data);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting watchdog thread: %s\n", rrr_strerror(err));
		ret = 1;
		goto out_stop_thread;
	}

	// Watchdog thread will free the data immediately
	*watchdog_data = NULL;

	thread->watchdog->started = 1;

	RRR_DBG_8 ("Thread %s watchdog started\n", thread->name);

	goto out;
	out_stop_thread:
		RRR_DBG_8 ("Thread %s cancel and join\n", thread->name);
		pthread_cancel(thread->thread);
		pthread_join(thread->thread, NULL);
		thread->started = 0;
	out:
		return ret;
}

void rrr_thread_run (
		struct rrr_thread *thread
) {
	RRR_DBG_8("Thread %s starting run\n", thread->name);

	thread->started = 1;

	__rrr_thread_start_routine_intermediate(thread);
}

static int __rrr_thread_allocate_watchdog_data (
		struct watchdog_data **result
) {
	*result = rrr_allocate(sizeof(**result));
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory for watchdog in %s\n", __func__);
		return 1;
	}

	return 0;
}

static int __rrr_thread_allocate (
		struct rrr_thread **target,
		struct rrr_thread **target_wd,
		int (*init)(struct rrr_thread *),
		int (*run)(struct rrr_thread *),
		volatile int *encourage_stop,
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
) {
	int ret = 0;

	*target = NULL;
	*target_wd = NULL;

	struct rrr_thread *thread = NULL;

	if (strlen(name) > sizeof(thread->name) - 5) {
		RRR_MSG_0 ("Name for thread was too long: '%s'\n", name);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_thread_new(&thread, 0)) != 0) {
		goto out;
	}

	sprintf(thread->name, "%s", name);

	thread->watchdog_timeout_us = watchdog_timeout_us;
	thread->init = init;
	thread->run = run;
	thread->encourage_stop = encourage_stop;
	thread->private_data = private_data;

	rrr_thread_state_set(thread, RRR_THREAD_STATE_NEW);

#ifdef RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_B
	ret = 1;
	goto out_destroy_thread;
#endif

	if (__rrr_thread_new(&thread->watchdog, 1) != 0) {
		RRR_MSG_0("Could not allocate watchdog thread\n");
		ret = 1;
		goto out_destroy_thread;
	}

	// Do sprintf in two stages to avoid compile warning
	if (strlen(name) > 55) {
		RRR_BUG("BUG: Name of thread too long in %s\n", __func__);
	}
	sprintf(thread->watchdog->name, "WD: ");
	sprintf(thread->watchdog->name + strlen(thread->watchdog->name), "%s", name);

	thread->watchdog->encourage_stop = encourage_stop;

	*target = thread;
	*target_wd = thread->watchdog;

	goto out;
//	out_destroy_watchdog:
//		__rrr_thread_destroy(thread->watchdog);
	out_destroy_thread:
		__rrr_thread_destroy(thread);
		thread = NULL;
	out:
		return ret;
}

struct rrr_thread *rrr_thread_collection_thread_create_and_preload (
		struct rrr_thread_collection *collection,
		int (*init)(struct rrr_thread *),
		int (*run)(struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		volatile int *encourage_stop,
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
) {
	int err;
	struct rrr_thread *thread = NULL;
	struct rrr_thread *thread_wd = NULL;

	if (__rrr_thread_allocate (
			&thread,
			&thread_wd,
			init,
			run,
			encourage_stop,
			name,
			watchdog_timeout_us,
			private_data
	) != 0) {
		goto out;
	}

	if ((err = (preload_routine != NULL ? preload_routine(thread) : 0)) != 0) {
		RRR_MSG_0 ("Error while preloading thread\n");
		goto out_destroy_thread;
	}

	__rrr_thread_collection_add_thread(collection, thread);
	__rrr_thread_collection_add_thread(collection, thread->watchdog);

	goto out;
	out_destroy_thread:
		__rrr_thread_destroy(thread);
		__rrr_thread_destroy(thread_wd);
		thread = NULL;
	out:
		return thread;
}

int rrr_thread_collection_start_all (
		struct rrr_thread_collection *collection
) {
	int ret = 0;

	struct watchdog_data *watchdog_data = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog) {
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_8 ("Starting thread %s\n", node->name);

		if (__rrr_thread_allocate_watchdog_data(&watchdog_data) != 0) {
			goto out;
		}

		watchdog_data->watched_thread = node;
		watchdog_data->watchdog_thread = node->watchdog;

		if (__rrr_thread_start(node, &watchdog_data) != 0) {
			RRR_MSG_0 ("Error while starting thread\n");
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(watchdog_data);
	return ret;
}

int rrr_thread_collection_init_all (
		struct rrr_thread_collection *collection,
		void (*fail_cb)(struct rrr_thread *thread)
) {
	int ret = 0;

	int encourage_stop = 0;
	int init_pos = 0;
	int fail_pos = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog) {
			RRR_LL_ITERATE_NEXT();
		}

		if ((ret = __rrr_thread_wait_for_signal_and_init(&encourage_stop, node)) != 0 || encourage_stop) {
			goto out_cleanup;
		}

		if (encourage_stop) {
			goto out_cleanup;
		}

		init_pos++;
	RRR_LL_ITERATE_END();

	goto out;
	out_cleanup:
		RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
			if (fail_pos >= init_pos) {
				RRR_LL_ITERATE_BREAK();
			}

			fail_cb(node);

			fail_pos++;
		RRR_LL_ITERATE_END();
	out:
		return ret;
}

int rrr_thread_collection_check_any_stopped (
		struct rrr_thread_collection *collection
) {
	int ret = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (rrr_thread_state_check(node, RRR_THREAD_STATE_STOPPED|RRR_THREAD_STATE_GHOST)) {
			RRR_DBG_8("Thread instance %s has stopped or is ghost\n", node->name);
			ret = 1;
		}
	RRR_LL_ITERATE_END();
	return ret;
}
