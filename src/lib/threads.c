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
#include "cmdlineparser/cmdline.h"
#include "threads.h"
#include "rrr_strerror.h"
#include "log.h"

// Very harsh option to make watchdogs stop checking alive timers of threads
//#define VL_THREAD_INCAPACITATE_WATCHDOGS

// Threads which does not shutdown nicely will remain while others shut down
//#define VL_THREAD_DISABLE_CANCELLING

// Set this higher (like 1000) when debugging
#define VL_THREAD_FREEZE_LIMIT_FACTOR 1

struct rrr_thread_postponed_cleanup_node {
	RRR_LL_NODE(struct rrr_thread_postponed_cleanup_node);
	struct rrr_thread *thread;
};

struct rrr_ghost_postponed_cleanup_collection {
	RRR_LL_HEAD(struct rrr_thread_postponed_cleanup_node);
};

static int __rrr_thread_destroy (struct rrr_thread *thread) {
	rrr_thread_lock(thread);

	if (thread->state == RRR_THREAD_STATE_FREE) {
		RRR_BUG("Attempted to free thread which was FREE\n");
	}

	thread->state = RRR_THREAD_STATE_FREE;
	rrr_thread_unlock(thread);
	free(thread);

	return 0;
}

// It is safe to have these dynamically allocated, a thread may wake up after
// such memory has been freed and attempt to use it.
static struct rrr_ghost_postponed_cleanup_collection postponed_cleanup_collection = {0};
static pthread_mutex_t postponed_cleanup_lock = PTHREAD_MUTEX_INITIALIZER;

/* If a ghost becomes ghost (tagged by the watchdog as such):
 * - Main will remove reference to the pointer of the threads rrr_thread struct
 * - If waking up, and prior to exiting, the thread will check if it has been tagged
 *   and will push to this list
 * - At a suitable time, main will call cleanup_run routine and free memory and possibly
 *   run poststop
 */

// Called from threads
static void __rrr_thread_postponed_cleanup_push (struct rrr_thread *thread) {
	struct rrr_thread_postponed_cleanup_node *node = malloc(sizeof(*node));
	memset(node, '\0', sizeof(*node));

	node->thread = thread;

	pthread_mutex_lock(&postponed_cleanup_lock);
	RRR_LL_APPEND(&postponed_cleanup_collection, node);
	pthread_mutex_unlock(&postponed_cleanup_lock);
}

// Called from main
void rrr_thread_postponed_cleanup_run(int *count) {
	*count = 0;
	pthread_mutex_lock(&postponed_cleanup_lock);
	RRR_LL_ITERATE_BEGIN(&postponed_cleanup_collection, struct rrr_thread_postponed_cleanup_node);
		if (node->thread->poststop_routine) {
			node->thread->poststop_routine(node->thread);
		}
		RRR_LL_ITERATE_SET_DESTROY();
		(*count)++;
	RRR_LL_ITERATE_END_CHECK_DESTROY(&postponed_cleanup_collection, __rrr_thread_destroy(node->thread); free(node));
	pthread_mutex_unlock(&postponed_cleanup_lock);
}

void rrr_thread_set_signal(struct rrr_thread *thread, int signal) {
	RRR_DBG_4 ("Thread %s set signal %d\n", thread->name, signal);
	rrr_thread_lock(thread);
	thread->signal |= signal;
	rrr_thread_unlock(thread);
}

int rrr_thread_get_state(struct rrr_thread *thread) {
	int state;
	rrr_thread_lock(thread);
	state = thread->state;
	rrr_thread_unlock(thread);;
	return state;
}

int rrr_thread_check_state(struct rrr_thread *thread, int state) {
	return (rrr_thread_get_state(thread) == state);
}

void rrr_thread_set_state (struct rrr_thread *thread, int state) {
	rrr_thread_lock(thread);

	RRR_DBG_4 ("Thread %s setting state %i\n", thread->name, state);

	if (state == RRR_THREAD_STATE_INIT) {
		RRR_BUG("Attempted to set STARTING state of thread outside reserve_thread function\n");
	}
	if (state == RRR_THREAD_STATE_FREE) {
		RRR_BUG("Attempted to set FREE state of thread outside reserve_thread function\n");
	}
	if (state == RRR_THREAD_STATE_RUNNING && thread->state != RRR_THREAD_STATE_INITIALIZED && thread->state != RRR_THREAD_STATE_RUNNING_FORKED) {
		RRR_BUG("Attempted to set RUNNING state of thread while it was not in INITIALIZED or RUNNING_FORKED state\n");
	}
	if (state == RRR_THREAD_STATE_RUNNING_FORKED && thread->state != RRR_THREAD_STATE_RUNNING) {
		RRR_BUG("Attempted to set RUNNING_FORKED state of thread while it was not in RUNNING state but %i\n", thread->state);
	}
/*	if (state == RRR_THREAD_STATE_STOPPING && (thread->state != RRR_THREAD_STATE_RUNNING && thread->state != RRR_THREAD_STATE_RUNNING_FORKED && thread->state != RRR_THREAD_STATE_INIT)) {
		RRR_MSG_0 ("Warning: Attempted to set STOPPING state of thread %p/%s while it was not in ENCOURAGE STOP or RUNNING state\n", thread, thread->name);
		goto nosetting;
	}*/
	if (state == RRR_THREAD_STATE_STOPPED && (
			thread->state != RRR_THREAD_STATE_RUNNING &&
			thread->state != RRR_THREAD_STATE_RUNNING_FORKED &&
			thread->state != RRR_THREAD_STATE_INITIALIZED
//			&& thread->state != RRR_THREAD_STATE_STOPPING
		)
	) {
		RRR_MSG_0 ("Warning: Attempted to set STOPPED state of thread %p while it was not in RUNNING or INITIALIZED	 state\n", thread);
		goto nosetting;
	}

	thread->state = state;

	nosetting:
	rrr_thread_unlock(thread);
}

static int __rrr_thread_is_in_collection (struct rrr_thread_collection *collection, struct rrr_thread *thread) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node == thread) {
			ret = 1;
			break;
		}
	RRR_LL_ITERATE_END();

	pthread_mutex_unlock(&collection->threads_mutex);

	return ret;
}

static int __rrr_thread_allocate_thread (struct rrr_thread **target) {
	int ret = 0;
	*target = NULL;

	struct rrr_thread *thread = malloc(sizeof(*thread));
	if (thread == NULL) {
		RRR_MSG_0("Could not allocate memory for thread thread\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_8 ("Allocate thread %p\n", thread);
	memset(thread, '\0', sizeof(struct rrr_thread));
	pthread_mutex_init(&thread->mutex, NULL);

	*target = thread;

	out:
	return ret;
}

int rrr_thread_new_collection (
		struct rrr_thread_collection **target
) {
	int ret = 0;
	*target = NULL;

	struct rrr_thread_collection *collection = malloc(sizeof(*collection));
	if (collection == NULL) {
		RRR_MSG_0("Could not allocate memory for thread collection\n");
		ret = 1;
		goto out;
	}

	memset(collection, '\0', sizeof(*collection));

	pthread_mutex_init(&collection->threads_mutex, NULL);

	*target = collection;

	out:
	return ret;
}

void rrr_thread_destroy_collection (
		struct rrr_thread_collection *collection
) {
	// Stop threads function should already have locked and not unlocked again
	//if (pthread_mutex_trylock(&collection->threads_mutex) != EBUSY) {
	//	RRR_MSG_0("Collection was not locked in thread_destroy_collection, must call threads_stop_and_join first\n");
	//	exit (EXIT_FAILURE);
	//}

	// OK if already locked, stop_and_join all leaves the collection locked
	// in case caller wishes to do something with lock held in between the calls
	pthread_mutex_trylock(&collection->threads_mutex);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->is_ghost == 1) {
			// TODO : thread_cleanup() does not lock, maybe it should to avoid race
			// condition with is_ghost and ghost_cleanup_pointer

			// Move pointer to thread, we expect it to clean up if it dies
			RRR_MSG_0 ("Thread %s is ghost when freeing all threads. It will add itself to cleanup list if it wakes up.\n",
					node->name);
			rrr_thread_unlock(node);
		}
		else {
			rrr_thread_unlock(node);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_thread_destroy(node));

	pthread_mutex_unlock(&collection->threads_mutex);
	pthread_mutex_destroy(&collection->threads_mutex);

	free(collection);
}

int rrr_thread_start_all_after_initialized (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	/* Wait for all threads to be in INITIALIZED state */

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		int was_initialized = 0;
		if (node->is_watchdog == 1) {
			continue;
		}
		for (int j = 0; j < 100; j++)  {
			int state = rrr_thread_get_state(node);
			RRR_DBG_8 ("Wait for thread %p name %s, state is now %i\n", node, node->name, state);
			if (	state == RRR_THREAD_STATE_FREE ||
					state == RRR_THREAD_STATE_INITIALIZED ||
					state == RRR_THREAD_STATE_STOPPED
//					|| state == RRR_THREAD_STATE_STOPPING
			) {
				was_initialized = 1;
				break;
			}
			else if (state == RRR_THREAD_STATE_RUNNING) {
				RRR_BUG ("Bug: Thread %s did not wait for start signal.\n", node->name);
			}
			rrr_posix_usleep (10000);
		}
		if (was_initialized != 1) {
			RRR_MSG_0 ("Thread %s did not initialize itself in time\n", node->name);
			ret = 1;
			goto out_unlock;
		}
	RRR_LL_ITERATE_END();

	/* Check for valid start priority */
	int fork_priority_threads_count = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->start_priority < 0 || node->start_priority > RRR_THREAD_START_PRIORITY_MAX) {
			RRR_BUG("Thread %s has unknown start priority of %i\n", node->name, node->start_priority);
		}
		if (node->is_watchdog != 1 && node->start_priority == RRR_THREAD_START_PRIORITY_FORK) {
			fork_priority_threads_count++;
		}
	RRR_LL_ITERATE_END();

	/* Signal priority 0 and fork threads to proceed */
	int must_retry = 0;
	do {
		if (must_retry == 1) {
			rrr_posix_usleep(5000); // 5 ms
		}
		must_retry = 0;

		RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
			if (	node->is_watchdog == 1 || (
						node->start_priority != RRR_THREAD_START_PRIORITY_NORMAL &&
						node->start_priority != RRR_THREAD_START_PRIORITY_FORK
					) ||
					rrr_thread_get_state(node) != RRR_THREAD_STATE_INITIALIZED ||
					node->start_signal_sent == 1
			) {
				RRR_LL_ITERATE_NEXT();
			}

			int do_start = 1;
			if (start_check_callback != NULL && start_check_callback(&do_start, node, callback_arg) != 0) {
				RRR_MSG_0("Error from start check callback in rrr_thread_start_all_after_initialized\n");
				ret = 1;
				goto out_unlock;
			}

			if (do_start == 1) {
				RRR_DBG_8 ("Start signal to thread %p name %s with priority NORMAL or FORK\n", node, node->name);
				rrr_thread_set_signal(node, RRR_THREAD_SIGNAL_START);
				node->start_signal_sent = 1;
			}
			else {
				must_retry = 1;
			}

		RRR_LL_ITERATE_END();
	}
	while (must_retry == 1);

	RRR_DBG_8 ("Wait for %i fork threads to set RUNNNIG_FORKED\n", fork_priority_threads_count);

	/* Wait for forking threads to finish off their forking-business. They might
	 * also have failed at this point in which they would set STOPPED or STOPPING */

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog == 1 || node->start_priority != RRR_THREAD_START_PRIORITY_FORK) {
			RRR_LL_ITERATE_NEXT();
		}
		while (1) {
			int state = rrr_thread_get_state(node);
			if (	state == RRR_THREAD_STATE_RUNNING_FORKED ||
					state == RRR_THREAD_STATE_STOPPED
//					|| state == RRR_THREAD_STATE_STOPPING
			) {
				RRR_DBG_8 ("Fork thread %p name %s set RUNNING_FORKED\n", node, node->name);
				fork_priority_threads_count--;
				break;
			}
			// Don't spin on this check
			rrr_posix_usleep(5000);
		}
		if (fork_priority_threads_count == 0) {
			break;
		}
		if (fork_priority_threads_count < 0) {
			RRR_BUG("Bug: fork_priority_threads_count was < 0\n");
		}
	RRR_LL_ITERATE_END();

	/* Finally, start network priority threads */
	must_retry = 0;
	do {
		if (must_retry == 1) {
			rrr_posix_usleep(5000); // 5 ms
		}
		must_retry = 0;

		RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
			if (	node->is_watchdog == 1 ||
					node->start_priority != RRR_THREAD_START_PRIORITY_NETWORK ||
					node->start_signal_sent == 1
			) {
				RRR_LL_ITERATE_NEXT();
			}

			int do_start = 1;
			if (start_check_callback != NULL && start_check_callback(&do_start, node, callback_arg) != 0) {
				RRR_MSG_0("Error from start check callback in rrr_thread_start_all_after_initialized\n");
				ret = 1;
				goto out_unlock;
			}

			if (do_start == 1) {
				RRR_DBG_8 ("Start signal to thread %p name %s with priority NETWORK\n", node, node->name);
				rrr_thread_set_signal(node, RRR_THREAD_SIGNAL_START);
				node->start_signal_sent = 1;
			}
			else {
				must_retry = 1;
			}
		RRR_LL_ITERATE_END();
	} while (must_retry == 1);

	/* Double check that everything was started */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog != 1 && !rrr_thread_check_signal(node, RRR_THREAD_SIGNAL_START)) {
			RRR_BUG("Bug: Thread %s did not receive start signal\n", node->name);
		}
	RRR_LL_ITERATE_END();

	out_unlock:
	pthread_mutex_unlock(&collection->threads_mutex);
	return ret;
}

static void __rrr_thread_collection_add_thread (struct rrr_thread_collection *collection, struct rrr_thread *thread) {
//	VL_DEBUG_MSG_1 ("Adding thread %p to collection %p\n", thread, collection);

	if (__rrr_thread_is_in_collection(collection, thread)) {
		RRR_BUG("BUG: Attempted to add thread to collection in which it was already part of\n");
	}

	pthread_mutex_lock(&collection->threads_mutex);
	RRR_LL_APPEND(collection, thread);
	pthread_mutex_unlock(&collection->threads_mutex);
}

struct watchdog_data {
	struct rrr_thread *watchdog_thread;
	struct rrr_thread *watched_thread;
};

static void *__rrr_thread_watchdog_entry (void *arg) {
	// COPY AND FREE !!!!
	struct watchdog_data data = *((struct watchdog_data *)arg);
	free(arg);

	struct rrr_thread *thread = data.watched_thread;
	struct rrr_thread *self_thread = data.watchdog_thread;

	RRR_DBG_8 ("Watchdog %p started for thread %s/%p, waiting 1 second.\n", self_thread, thread->name, thread);

	// Wait a bit in case main thread does stuff
	rrr_posix_usleep(20000);

	RRR_DBG_8 ("Watchdog %p for thread %s/%p, finished waiting.\n", self_thread, thread->name, thread);


	rrr_thread_update_watchdog_time(thread);

	rrr_thread_set_state(self_thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_set_state(self_thread, RRR_THREAD_STATE_RUNNING);

#ifdef VL_THREAD_INCAPACITATE_WATCHDOGS
	while (1) {
		rrr_posix_usleep(5000000);
	}
#endif

	uint64_t prev_loop_time = rrr_time_get_64();
	while (1) {

		uint64_t nowtime = rrr_time_get_64();
		uint64_t prevtime = rrr_get_watchdog_time(thread);

		// We or others might try to kill the thread
		if (rrr_thread_check_kill_signal(thread) || rrr_thread_check_encourage_stop(thread)) {
			RRR_DBG_8 ("Thread %s/%p received kill signal or encourage stop\n", thread->name, thread);
			break;
		}

		if (	!rrr_thread_check_state(thread, RRR_THREAD_STATE_RUNNING) &&
				!rrr_thread_check_state(thread, RRR_THREAD_STATE_RUNNING_FORKED) &&
				!rrr_thread_check_state(thread, RRR_THREAD_STATE_INIT) &&
				!rrr_thread_check_state(thread, RRR_THREAD_STATE_INITIALIZED)
		) {
			RRR_DBG_8 ("Thread %s/%p state was no longer RUNNING\n", thread->name, thread);
			break;
		}
		else if (!rrr_config_global.no_watchdog_timers &&
				(prevtime + (long long unsigned int) RRR_THREAD_WATCHDOG_FREEZE_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR < nowtime)
		) {
			if (rrr_time_get_64() - prev_loop_time > 100000) { // 100 ms
				RRR_MSG_0 ("Thread %s/%p has been frozen but so has the watchdog, maybe we are debugging?\n", thread->name, thread);
			}
			else {
				RRR_MSG_0 ("Thread %s/%p froze, attempting to kill\n", thread->name, thread);
				rrr_thread_set_signal(thread, RRR_THREAD_SIGNAL_KILL);
				break;
			}
		}

		prev_loop_time = rrr_time_get_64();
		rrr_posix_usleep (50000); // 50 ms
	}

	if (rrr_thread_check_state(thread, RRR_THREAD_STATE_STOPPED)) {
		// Thread has stopped by itself
		goto out_nostop;
	}

	// If thread is about to start, wait a bit. If main thread hasn't completed with the
	// INIT / INITIALIZED / START-sequence, we attempt to do that now.

	// Wait for INIT stage to complete
	if (rrr_thread_check_state(thread, RRR_THREAD_STATE_INIT)) {
		RRR_DBG_8("Thread %s/%p wasn't finished starting, wait for it to initialize\n", thread->name, thread);
		int limit = 10;

		while (--limit >= 0 && !rrr_thread_check_state(thread, RRR_THREAD_STATE_INITIALIZED)) {
			RRR_DBG_8("Thread %s/%p wasn't finished starting, wait for it to initialize (try %i)\n", thread->name, thread, limit);
			rrr_posix_usleep (50000); // 50 ms (x 10)
		}
		if (!rrr_thread_check_state(thread, RRR_THREAD_STATE_INITIALIZED)) {
			RRR_DBG_8("Thread %s/%p won't initialize, maybe we have to force it to quit\n", thread->name, thread);
		}
	}

	// Wait for INIT and INITIALIZED stage to complete (thread should set RUNNING or STOPPED).
	// We do not print a debug message if the thread is in INITIALIZED stage, it is normal
	// in some circumstances that the thread hasn't been started yet when we want to stop it down.
	int state = rrr_thread_get_state(thread);
	if (state == RRR_THREAD_STATE_INITIALIZED || state == RRR_THREAD_STATE_INIT) {
		int limit = 10;

		do {
			state = rrr_thread_get_state(thread);
			rrr_posix_usleep (50000); // 50 ms (x 10)
		} while(--limit >= 0 && (state == RRR_THREAD_STATE_INITIALIZED || state == RRR_THREAD_STATE_INIT));

		if (state == RRR_THREAD_STATE_INITIALIZED || state == RRR_THREAD_STATE_INIT) {
			RRR_MSG_0("Warning: Thread %s/%p slow to leave INIT/INITIALIZED state, maybe we have to force it to exit. State is now %i.\n", thread->name, thread, thread->state);
		}
	}

	rrr_thread_set_signal(thread, RRR_THREAD_SIGNAL_KILL);

	// Wait for thread to set STOPPED
	uint64_t prevtime = rrr_time_get_64();
#ifndef VL_THREAD_DISABLE_CANCELLING
	while (rrr_thread_get_state(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();
		if (prevtime + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR < nowtime) {
			RRR_MSG_0 ("Thread %s/%p not responding to kill. State is now %i. Killing it harder.\n", thread->name, thread, thread->state);
			if (thread->cancel_function != NULL) {
				int res = thread->cancel_function(thread);
				RRR_MSG_0 ("Thread %s/%p result from custom cancel function: %i\n", thread->name, thread, res);
				rrr_posix_usleep(1000000); // 1 s
			}
			else {
				pthread_cancel(thread->thread);
			}
			break;
		}

		rrr_posix_usleep (10000); // 10 ms
	}
#else
	RRR_DBG_8 ("Thread watchdog cancelling disabled, soft stop signals only\n");
#endif

	RRR_DBG_8 ("Wait for thread %s/%p to set STOPPED, current state is: %i\n", thread->name, thread, rrr_thread_get_state(thread));

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	prevtime = rrr_time_get_64();
	while (rrr_thread_get_state(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();
		if (prevtime + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR< nowtime) {
			RRR_MSG_0 ("Thread %s/%p not responding to cancellation, try again .\n", thread->name, thread);


			/* DISABLED : program crashes if thread has exited : pthread_cancel(thread->thread);
			if (thread->cancel_function != NULL) {
				int res = thread->cancel_function(thread);
				RRR_MSG_0 ("Thread %s/%p result from custom cancel function: %i\n", thread->name, thread, res);
				usleep(1000000);
			}
			else {
			}
			*/

			/*if (rrr_thread_get_state(thread) == RRR_THREAD_STATE_STOPPING) {
				RRR_MSG_0 ("Thread %s/%p is stuck in STOPPING, not finished with it's cleanup.\n", thread->name, thread);
			}
			else */
			if (rrr_thread_get_state(thread) == RRR_THREAD_STATE_RUNNING) {
				RRR_MSG_0 ("Thread %s/%p is stuck in RUNNING, has not started it's cleanup yet.\n", thread->name, thread);
			}
			else if (rrr_thread_get_state(thread) == RRR_THREAD_STATE_RUNNING_FORKED) {
				RRR_MSG_0 ("Thread %s/%p is stuck in RUNNING_FORKED, has not started it's cleanup yet.\n", thread->name, thread);
			}
			RRR_MSG_0 ("Thread %s/%p: Tagging as ghost.\n", thread->name, thread);
			rrr_thread_set_ghost(thread);
			break;
		}

		rrr_posix_usleep (10000); // 10 ms
	}

	RRR_DBG_8 ("Thread %s/%p finished.\n", thread->name, thread);

	out_nostop:

	RRR_DBG_8 ("Thread %s/%p state after stopping: %i\n", thread->name, thread, rrr_thread_get_state(thread));

	rrr_thread_set_state(self_thread, RRR_THREAD_STATE_STOPPED);

	pthread_exit(0);
}

static void __rrr_thread_cleanup(void *arg) {
	struct rrr_thread *thread = arg;
	if (rrr_thread_is_ghost(thread)) {
		RRR_MSG_0 ("Thread %s waking up after being ghost, telling parent to clean up now.\n", thread->name);
		__rrr_thread_postponed_cleanup_push(thread);
	}
}

static void *__rrr_thread_start_routine_intermediate(void *arg) {
	struct rrr_thread *thread = arg;

	// STOPPED must be set at the very end, allows
	// data structures to be freed
	pthread_cleanup_push(rrr_thread_set_stopped, thread);
	pthread_cleanup_push(__rrr_thread_cleanup, thread);

	thread->start_routine(thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

void rrr_thread_stop_and_join_all_no_unlock (
		struct rrr_thread_collection *collection
) {
	RRR_DBG_8 ("Stopping all threads\n");

	// No errors allowed in this function

	pthread_mutex_lock(&collection->threads_mutex);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog) {
			continue;
		}
		rrr_thread_lock(node);
		if (	node->state == RRR_THREAD_STATE_RUNNING ||
				node->state == RRR_THREAD_STATE_RUNNING_FORKED ||
				node->state == RRR_THREAD_STATE_INIT ||
				node->state == RRR_THREAD_STATE_INITIALIZED
		) {
			RRR_DBG_8 ("Setting encourage stop and start signal thread %s/%p\n", node->name, node);
			node->signal = RRR_THREAD_SIGNAL_ENCOURAGE_STOP|RRR_THREAD_SIGNAL_START;
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END();

	// Wait for watchdogs to change state of thread
	//usleep (VL_THREAD_WATCHDOG_KILLTIME_LIMIT*1000*2);

	// Join with the watchdogs. The other threads might be in hung up state.
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog) {
			RRR_DBG_8 ("Joining with thread watchdog %s\n", node->name);
			void *ret;
			pthread_join(node->thread, &ret);
			RRR_DBG_8 ("Joined with thread watchdog %s\n", node->name);
		}
	RRR_LL_ITERATE_END();

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog) {
			RRR_LL_ITERATE_NEXT();
		}

		rrr_thread_lock(node);
		if (node->poststop_routine != NULL) {
			if (node->state == RRR_THREAD_STATE_STOPPED) {
				RRR_DBG_8 ("Running post stop routine for %s\n", node->name);
				node->poststop_routine(node);
			}
			else {
				RRR_MSG_0 ("Cannot run post stop for thread %s as it is not in STOPPED state\n", node->name);
				if (!node->is_ghost) {
					RRR_BUG ("Bug: Thread was not STOPPED nor ghost after join attempt\n");
				}
				RRR_MSG_0 ("Running post stop later if thread wakes up\n");
			}
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END();

	// Do not unlock
}

int rrr_thread_start (struct rrr_thread *thread) {
	int err = 0;

	err = pthread_create(&thread->thread, NULL, __rrr_thread_start_routine_intermediate, thread);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting thread: %s\n", rrr_strerror(err));
		goto out_error;
	}

	RRR_DBG_8 ("Started thread %s pthread address %p\n", thread->name, &thread->thread);

	pthread_detach(thread->thread);

	struct watchdog_data *watchdog_data = malloc(sizeof(*watchdog_data));
	watchdog_data->watchdog_thread = thread->watchdog;
	watchdog_data->watched_thread = thread;

	if (strlen(thread->name) > 55) {
		RRR_BUG("Name of thread too long");
	}

	// Do this two-stage to avoid compile warning, we check the length above
	sprintf(thread->watchdog->name, "WD: ");
	sprintf(thread->watchdog->name + strlen(thread->watchdog->name), "%s", thread->name);

	err = pthread_create(&thread->watchdog->thread, NULL, __rrr_thread_watchdog_entry, watchdog_data);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting watchdog thread: %s\n", rrr_strerror(err));
		pthread_cancel(thread->thread);
		goto out_error;
	}

	thread->watchdog->is_watchdog = 1;

	RRR_DBG_8 ("Thread %s Watchdog started\n", thread->name);

	// Thread tries to set a signal first and therefore can't proceed untill we unlock
	rrr_thread_unlock(thread);

	return 0;

	out_error:
	if (thread != NULL) {
		rrr_thread_unlock_if_locked(thread);
	}
	if (thread->watchdog != NULL) {
		rrr_thread_unlock_if_locked(thread->watchdog);
	}

	return 1;
}

// Use of memory fence on private data pointer is optional, and only
// needed is main and thread use the pointer after thread has started.
// If this is done, private pointer must exclusively be accessed through
// lock wrapper function. If the thread or main frees the private pointer, it must
// be set to NULL afterwards (inside callback of wrapper function). All callbacks
// of wrapper function must check if the pointer has been freed/set to NULL.

int rrr_thread_with_lock_do (
		struct rrr_thread *thread,
		int (*callback)(struct rrr_thread *thread, void *arg),
		void *callback_arg
) {
	int ret = 0;
	pthread_mutex_lock(&thread->mutex);
	ret = callback(thread, callback_arg);
	pthread_mutex_unlock(&thread->mutex);
	return ret;
}

struct rrr_thread *rrr_thread_allocate_preload_and_register (
		struct rrr_thread_collection *collection,
		void *(*start_routine) (struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		void (*poststop_routine) (const struct rrr_thread *),
		int (*cancel_function) (struct rrr_thread *),
		int start_priority,
		const char *name,
		void *private_data
) {
	struct rrr_thread *thread = NULL;

	// NOTE : Locking and gotos in this function are messy, take care

	if (__rrr_thread_allocate_thread(&thread) != 0) {
		RRR_MSG_0("Could not allocate thread\n");
		goto out_error;
	}
	__rrr_thread_collection_add_thread(collection, thread);

	if (strlen(name) > sizeof(thread->name) - 5) {
		RRR_MSG_0 ("Name for thread was too long: '%s'\n", name);
		goto out_error;
	}

	thread->watchdog_time = 0;
	thread->signal = 0;
	thread->start_priority = start_priority;

	thread->cancel_function = cancel_function;
	thread->poststop_routine = poststop_routine;
	thread->start_routine = start_routine;
	thread->private_data = private_data;

	sprintf(thread->name, "%s", name);

	if (__rrr_thread_allocate_thread(&thread->watchdog) != 0) {
		RRR_MSG_0("Could not allocate watchdog thread\n");
		goto out_error;
	}
	__rrr_thread_collection_add_thread(collection, thread->watchdog);

	rrr_thread_lock(thread);

	int err = (preload_routine != NULL ? preload_routine(thread) : 0);
	if (err != 0) {
		RRR_MSG_0 ("Error while preloading thread\n");
		goto out_error;
	}

	thread->state = RRR_THREAD_STATE_INIT;

	// Thread tries to set a signal first and therefore can't proceed until we unlock
	rrr_thread_unlock(thread);

	return thread;

	out_error:
	if (thread != NULL) {
		if (thread->watchdog != NULL) {
			rrr_thread_unlock_if_locked(thread->watchdog);
			__rrr_thread_destroy(thread->watchdog);
		}
		rrr_thread_unlock_if_locked(thread);
		__rrr_thread_destroy(thread);
	}

	return NULL;
}

int rrr_thread_check_any_stopped (
		struct rrr_thread_collection *collection
) {
	int ret = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (
				rrr_thread_get_state(node) == RRR_THREAD_STATE_STOPPED ||
//				rrr_thread_get_state(node) == RRR_THREAD_STATE_STOPPING ||
				rrr_thread_is_ghost(node)
		) {
			RRR_DBG_8("Thread instance %s has stopped or is ghost\n", node->name);
			ret = 1;
		}
	RRR_LL_ITERATE_END();
	return ret;
}

void rrr_thread_join_and_destroy_stopped_threads (
		int *count,
		struct rrr_thread_collection *collection
) {
	*count = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	// FIRST LOOP - Ghost handling, remove ghosts from list without freeing memory
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->is_ghost == 1) {
			// Watchdog has tagged thread as ghost. Make sure the watchdog has exited.
			rrr_thread_lock(node->watchdog);
			if (node->watchdog->state == RRR_THREAD_STATE_STOPPED) {
				// The second loop won't be to find the watchdog anymore, tag the
				// watchdog for destruction in the third loop now
				node->watchdog->ready_to_destroy = 1;

				// Does not free memory, which is now handled by ghost framework
				RRR_LL_ITERATE_SET_DESTROY();
			}
			rrr_thread_unlock(node->watchdog);
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(collection);

	// SECOND LOOP - Check for both thread and watchdog STOPPED, tag to destroy
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->watchdog != NULL) {
			rrr_thread_lock(node->watchdog);

			if (node->watchdog->state == RRR_THREAD_STATE_STOPPED && node->state == RRR_THREAD_STATE_STOPPED) {
				node->watchdog->ready_to_destroy = 1;
				node->ready_to_destroy = 1;
			}

			rrr_thread_unlock(node->watchdog);
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END();

	// THIRD LOOP - Destroy tagged threads
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);

		if (node->ready_to_destroy) {
			(*count)++;
			void *thread_ret;
			RRR_DBG_8("Join with %p, is watchdog: %i, pthread_t %lu\n", node, node->is_watchdog, node->thread);
			if (node->is_watchdog) {
				// Non-watchdogs are already detatched, only join watchdogs
				pthread_join(node->thread, &thread_ret);
			}
			RRR_LL_ITERATE_SET_DESTROY();
		}

		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_thread_destroy(node));

	pthread_mutex_unlock(&collection->threads_mutex);
}

int rrr_thread_iterate_non_wd_and_not_signalled_by_state (
		struct rrr_thread_collection *collection,
		int state,
		int (*callback)(struct rrr_thread *locked_thread, void *arg),
		void *callback_data
) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->is_watchdog == 0 && node->signal == 0) {
			if (node->state == state) {
				ret = callback(node, callback_data);
			}
			if (ret != 0) {
				// NOTE : Return value from callback MUST propagate to caller. Return
				//        values are not only errors.
				RRR_LL_ITERATE_LAST();
			}
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END();

	pthread_mutex_unlock(&collection->threads_mutex);
	return ret;
}

void rrr_thread_free_double_pointer(void *arg) {
	struct rrr_thread_double_pointer *data = arg;
	RRR_FREE_IF_NOT_NULL(*(data->ptr));
}
