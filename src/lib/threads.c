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
//#define RRR_THREAD_INCAPACITATE_WATCHDOGS

// Threads which does not shutdown nicely will remain while others shut down
//#define RRR_THREAD_DISABLE_CANCELLING

// Set this higher (like 1000) when debugging
#define RRR_THREAD_FREEZE_LIMIT_FACTOR 1

// On some systems pthread_t is an int and on others it's a pointer
static unsigned long long int __rrr_pthread_t_to_llu (pthread_t t) {
	return (unsigned long long int) t;
}

#define RRR_PTHREAD_T_TO_LLU(t) \
	__rrr_pthread_t_to_llu(t)

struct rrr_thread_postponed_cleanup_node {
	RRR_LL_NODE(struct rrr_thread_postponed_cleanup_node);
	struct rrr_thread *thread;
};

struct rrr_ghost_postponed_cleanup_collection {
	RRR_LL_HEAD(struct rrr_thread_postponed_cleanup_node);
};

static int __rrr_thread_destroy (struct rrr_thread *thread) {
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

void rrr_thread_set_state (struct rrr_thread *thread, int new_state) {
	rrr_thread_lock(thread);

	RRR_DBG_4 ("Thread %s setting state %i\n", thread->name, new_state);

	if (new_state == RRR_THREAD_STATE_STOPPED && (
			thread->state != RRR_THREAD_STATE_RUNNING_FORKED &&
			thread->state != RRR_THREAD_STATE_INITIALIZED
		)
	) {
		RRR_MSG_0 ("Warning: Setting STOPPED state of thread %p name %s which never completed initialization\n",
				thread, thread->name);
	}

	thread->state = new_state;

	rrr_thread_unlock(thread);
}

static void __rrr_thread_update_self (struct rrr_thread *thread) {
	rrr_thread_lock(thread);
	thread->self = pthread_self();
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
		RRR_MSG_0("Could not allocate memory in __rrr_thread_allocate_thread\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_8 ("Allocate thread %p\n", thread);
	memset(thread, '\0', sizeof(struct rrr_thread));

	if (rrr_posix_mutex_init(&thread->mutex, 0) != 0) {
		RRR_MSG_0("Could not create mutex in __rrr_thread_allocate_thread\n");
		ret = 1;
		goto out_free;
	}

	*target = thread;

	goto out;
	out_free:
		free(thread);
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
		RRR_MSG_0("Could not allocate memory in rrr_thread_new_collection\n");
		ret = 1;
		goto out;
	}

	memset(collection, '\0', sizeof(*collection));

	if (rrr_posix_mutex_init(&collection->threads_mutex, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_thread_new_collection\n");
		ret = 1;
		goto out_free;
	}

	*target = collection;

	goto out;
	out_free:
		free(collection);
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

enum rrr_thread_start_state_group {
	RRR_THREAD_START_ALL_WAIT_FOR_STATE_INITIALIZED,
	RRR_THREAD_START_ALL_WAIT_FOR_STATE_FORKING,
	RRR_THREAD_START_ALL_WAIT_FOR_STATE_FORKED
};

static int  __rrr_thread_start_all_wait_for_state (
		struct rrr_thread_collection *collection,
		enum rrr_thread_start_state_group state_group
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		int was_ok = 0;
		if (node->is_watchdog == 1) {
			RRR_LL_ITERATE_NEXT();
		}
		for (int j = 0; j < 100; j++)  {
			int state = rrr_thread_get_state(node);
			RRR_DBG_8 ("Wait for thread %p name %s, state is now %i\n", node, node->name, state);

			if (state_group == RRR_THREAD_START_ALL_WAIT_FOR_STATE_INITIALIZED) {
				if (state == RRR_THREAD_STATE_RUNNING_FORKED) {
					RRR_BUG("BUG: Thread %p name %s started prior to receiveing signal\n", node, node->name);
				}
				if (	state == RRR_THREAD_STATE_NEW ||
						state == RRR_THREAD_STATE_INITIALIZED ||
						state == RRR_THREAD_STATE_STOPPED
				) {
					was_ok = 1;
					break;
				}
			}
			else if (state_group == RRR_THREAD_START_ALL_WAIT_FOR_STATE_FORKED) {
				if (	state == RRR_THREAD_STATE_RUNNING_FORKED ||
						state == RRR_THREAD_STATE_STOPPED
				) {
					was_ok = 1;
					break;
				}
			}
			else {
				RRR_BUG("BUG: Unknown state group %i in __rrr_thread_start_all_wait_for_state\n", state_group);
			}

			rrr_posix_usleep (10000);
		}
		if (was_ok != 1) {
			int state = rrr_thread_get_state(node);
			RRR_MSG_0 ("Thread %s did not transition to required state group %i in time state is now %i\n",
					node->name, state_group, state);
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

void rrr_thread_start_condition_helper_nofork (
		struct rrr_thread *thread
) {
	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);
}

int rrr_thread_start_condition_helper_fork (
		struct rrr_thread *thread,
		int (*fork_callback)(void *arg),
		void *callback_arg
) {
	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);

	int ret = fork_callback(callback_arg);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);

	return ret;
}

int rrr_thread_start_all_after_initialized (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	/* Wait for all threads to initialize */
	if ((ret = __rrr_thread_start_all_wait_for_state (
			collection,
			RRR_THREAD_START_ALL_WAIT_FOR_STATE_INITIALIZED
	)) != 0) {
		goto out_unlock;
	}

	/* Signal threads to proceed to fork stage */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog == 1) {
			RRR_LL_ITERATE_NEXT();
		}
		RRR_DBG_8 ("START_BEFOREFORK signal to thread %p name %s with priority FORK\n", node, node->name);
		rrr_thread_set_signal(node, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	RRR_LL_ITERATE_END();

	RRR_DBG_8 ("Waiting for threads to set RUNNNIG_FORKED\n");

	/* Wait for forking threads to finish off their forking-business */
	if ((ret = __rrr_thread_start_all_wait_for_state (
			collection,
			RRR_THREAD_START_ALL_WAIT_FOR_STATE_FORKED
	)) != 0) {
		goto out_unlock;
	}

	/* Finally, start all threads based on callback condition */
	int must_retry = 0;
	do {
		if (must_retry == 1) {
			rrr_posix_usleep(5000); // 5 ms
		}
		must_retry = 0;

		RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
			if (node->is_watchdog == 1) {
				RRR_LL_ITERATE_NEXT();
			}

			int do_start = 1;
			if (start_check_callback != NULL && start_check_callback(&do_start, node, callback_arg) != 0) {
				RRR_MSG_0("Error from start check callback in rrr_thread_start_all_after_initialized\n");
				ret = 1;
				goto out_unlock;
			}

			if (do_start == 1) {
				RRR_DBG_8 ("START_AFTERFORK signal to thread %p name %s\n", node, node->name);
				rrr_thread_set_signal(node, RRR_THREAD_SIGNAL_START_AFTERFORK);
			}
			else {
				must_retry = 1;
			}
		RRR_LL_ITERATE_END();
	} while (must_retry == 1);

	/* Double check that everything was started */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (node->is_watchdog != 1 && !rrr_thread_check_signal(node, RRR_THREAD_SIGNAL_START_AFTERFORK)) {
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
	// Copy the data and free it immediately
	struct watchdog_data data = *((struct watchdog_data *)arg);
	free(arg);

	uint64_t freeze_limit = 0;

	struct rrr_thread *thread = data.watched_thread;
	struct rrr_thread *self_thread = data.watchdog_thread;

	rrr_thread_lock(thread);
	freeze_limit = thread->watchdog_timeout_us;
	rrr_thread_unlock(thread);

	RRR_DBG_8 ("Watchdog %p started for thread %s/%p, waiting 1 second.\n", self_thread, thread->name, thread);
	rrr_posix_usleep(1000000);
	RRR_DBG_8 ("Watchdog %p for thread %s/%p, finished waiting.\n", self_thread, thread->name, thread);

	rrr_thread_update_watchdog_time(thread);

	rrr_thread_set_state(self_thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_set_state(self_thread, RRR_THREAD_STATE_RUNNING_FORKED);

#ifdef RRR_THREAD_INCAPACITATE_WATCHDOGS
	while (1) {
		rrr_posix_usleep(5000000);
	}
#endif

	uint64_t prev_loop_time = rrr_time_get_64();
	while (1) {
		uint64_t nowtime = rrr_time_get_64();
		uint64_t prevtime = rrr_get_watchdog_time(thread);

//		RRR_DBG_8 ("Watchdog for thread %s/%p tick\n", thread->name, thread);

		// Main might try to stop the thread
		if (rrr_thread_check_encourage_stop(thread)) {
			RRR_DBG_8 ("Thread %s/%p received encourage stop\n", thread->name, thread);
			break;
		}

		if (	!rrr_thread_check_state(thread, RRR_THREAD_STATE_RUNNING_FORKED) &&
				!rrr_thread_check_state(thread, RRR_THREAD_STATE_INITIALIZED)
		) {
			RRR_DBG_8 ("Thread %s/%p state is not RUNNING or INITIALIZED\n", thread->name, thread);
			break;
		}
		else if (!rrr_config_global.no_watchdog_timers &&
				(prevtime + freeze_limit * RRR_THREAD_FREEZE_LIMIT_FACTOR < nowtime)
		) {
			if (rrr_time_get_64() - prev_loop_time > 100000) { // 100 ms
				RRR_MSG_0 ("Thread %s/%p has been frozen but so has the watchdog, maybe we are debugging?\n", thread->name, thread);
			}
			else {
				RRR_MSG_0 ("Thread %s/%p froze, attempting encourage stop\n", thread->name, thread);
				break;
			}
		}

		prev_loop_time = rrr_time_get_64();
		rrr_posix_usleep (50000); // 50 ms
	}

	RRR_DBG_8 ("Watchdog for thread %s/%p: Executing shutdown routines\n", thread->name, thread);

	if (rrr_thread_check_state(thread, RRR_THREAD_STATE_STOPPED)) {
		RRR_DBG_8 ("Watchdog for thread %s/%p: Thread has stopped by itself\n", thread->name, thread);
		goto out_nostop;
	}
	else if (rrr_thread_check_state(thread, RRR_THREAD_STATE_NEW)) {
		RRR_MSG_0("Warning: Thread %s/%p state is still NEW\n", thread->name, thread);
	}
	else if (rrr_thread_check_state(thread, RRR_THREAD_STATE_INITIALIZED)) {
		RRR_MSG_0("Warning: Thread %s/%p state is still INITIALIZED\n", thread->name, thread);
	}
	
	// Ensure this is always set
	rrr_thread_set_signal(thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP);
	
	RRR_DBG_8 ("Wait for thread %s/%p to set STOPPED pass 1/2, current state is: %i\n", thread->name, thread, rrr_thread_get_state(thread));

	// Wait for thread to set STOPPED
	uint64_t killtime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
#ifndef RRR_THREAD_DISABLE_CANCELLING
	while (rrr_thread_get_state(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();
		if (nowtime > killtime) {
			RRR_MSG_0 ("Thread %s/%p not responding to encourage stop. State is now %i. Trying to cancel it.\n", thread->name, thread, thread->state);
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

	RRR_DBG_8 ("Wait for thread %s/%p to set STOPPED pass 2/2, current state is: %i\n", thread->name, thread, rrr_thread_get_state(thread));

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	uint64_t ghosttime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
	while (rrr_thread_get_state(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();
		if (nowtime > ghosttime) {
			RRR_MSG_0 ("Thread %s/%p not responding to cancellation.\n", thread->name, thread);
			if (rrr_thread_get_state(thread) == RRR_THREAD_STATE_NEW) {
				RRR_MSG_0 ("Thread %s/%p is stuck in NEW, has not started it's cleanup yet.\n", thread->name, thread);
			}
			else if (rrr_thread_get_state(thread) == RRR_THREAD_STATE_INITIALIZED) {
				RRR_MSG_0 ("Thread %s/%p is stuck in INITIALIZED, has not started it's cleanup yet.\n", thread->name, thread);
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

	out_nostop:

	RRR_DBG_8 ("Thread %s/%p WD state upon WD out: %i\n", thread->name, thread, rrr_thread_get_state(thread));

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

	__rrr_thread_update_self(thread);

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
		if (node->state != RRR_THREAD_STATE_STOPPED) {
			RRR_DBG_8 ("Setting encourage stop and start signal thread %s/%p\n", node->name, node);
			node->signal = RRR_THREAD_SIGNAL_ENCOURAGE_STOP|RRR_THREAD_SIGNAL_START_AFTERFORK|RRR_THREAD_SIGNAL_START_BEFOREFORK;
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END();

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
// needed if main and thread use the pointer after thread has started.
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
		const char *name,
		uint64_t watchdog_timeout_us,
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
	sprintf(thread->name, "%s", name);

	thread->watchdog_time = 0;
	thread->watchdog_timeout_us = watchdog_timeout_us;
	thread->signal = 0;

	thread->cancel_function = cancel_function;
	thread->poststop_routine = poststop_routine;
	thread->start_routine = start_routine;
	thread->private_data = private_data;
	thread->state = RRR_THREAD_STATE_NEW;

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
		if (	rrr_thread_get_state(node) == RRR_THREAD_STATE_STOPPED ||
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
			RRR_DBG_8("Join with %p, is watchdog: %i, pthread_t %llu\n",
					node, node->is_watchdog, RRR_PTHREAD_T_TO_LLU(node->thread));
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

