/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#define RRR_THREAD_SIGNAL_CHECK(signals,test) \
	((signals & test) == test)

#define RRR_THREAD_STATE_CHECK(state,test) \
	(state == test)

// Misc. initialization failure simulations
// #define RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_A
// #define RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_B
// #define RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_C
// #define RRR_THREAD_SIMULATE_START_FAILURE_A
// #define RRR_THREAD_SIMULATE_START_FAILURE_B
		
#define RRR_THREAD_WATCHDOG_SLEEPTIME_MS 500

// On some systems pthread_t is an int and on others it's a pointer
static unsigned long long int __rrr_pthread_t_to_llu (pthread_t t) {
	return (unsigned long long int) t;
}

#define RRR_PTHREAD_T_TO_LLU(t) \
	__rrr_pthread_t_to_llu(t)

#ifdef RRR_THREAD_DEBUG_MUTEX
#	define RRR_THREAD_MUTEX_INIT_FLAGS RRR_POSIX_MUTEX_IS_ERRORCHECK
#else
#	define RRR_THREAD_MUTEX_INIT_FLAGS 0
#endif

struct rrr_thread_postponed_cleanup_node {
	RRR_LL_NODE(struct rrr_thread_postponed_cleanup_node);
	struct rrr_thread *thread;
};

struct rrr_ghost_postponed_cleanup_collection {
	RRR_LL_HEAD(struct rrr_thread_postponed_cleanup_node);
};

static int __rrr_thread_destroy (
		struct rrr_thread *thread
) {
	pthread_cond_destroy(&thread->signal_cond);
	pthread_mutex_destroy(&thread->mutex);
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
static void __rrr_thread_cleanup_postponed_push (
		struct rrr_thread *thread
) {
	struct rrr_thread_postponed_cleanup_node *node = malloc(sizeof(*node));
	memset(node, '\0', sizeof(*node));

	node->thread = thread;

	pthread_mutex_lock(&postponed_cleanup_lock);
	RRR_LL_APPEND(&postponed_cleanup_collection, node);
	pthread_mutex_unlock(&postponed_cleanup_lock);
}

// Called from main
void rrr_thread_cleanup_postponed_run (
		int *count
) {
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

static void rrr_thread_unlock_if_locked (
		struct rrr_thread *thread
) {
	if (pthread_mutex_trylock(&thread->mutex) != 0) {
	}
	pthread_mutex_unlock(&thread->mutex);
}

void rrr_thread_signal_set (
		struct rrr_thread *thread,
		int signal
) {
	RRR_DBG_8 ("Thread %s set signal %d\n", thread->name, signal);
	rrr_thread_lock(thread);
	thread->signal |= signal;
	int ret_tmp;
	if ((ret_tmp = pthread_cond_broadcast(&thread->signal_cond)) != 0) {
		RRR_MSG_0("Warning: Error %i from pthread_cond_broadcast in rrr_thread_signal_set, error will not be handled\n", ret_tmp);
	}
	rrr_thread_unlock(thread);
}

int rrr_thread_signal_check (
		struct rrr_thread *thread,
		int signal
) {
	int ret;
	rrr_thread_lock(thread);
	ret = RRR_THREAD_SIGNAL_CHECK(thread->signal, signal);
	rrr_thread_unlock(thread);;
	return ret;
}

void rrr_thread_signal_wait_busy (
		struct rrr_thread *thread,
		int signal
) {
	while (1) {
		rrr_thread_lock(thread);
		int signal_test = thread->signal;
		rrr_thread_unlock(thread);
		if ((signal_test & signal) == signal) {
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

	pthread_mutex_lock(&thread->mutex);
	int ret_tmp = pthread_cond_timedwait(&thread->signal_cond, &thread->mutex, &wakeup_time);
	pthread_mutex_unlock(&thread->mutex);

	if (ret_tmp != 0) {
		switch (errno) {
			case EAGAIN:
			case ETIMEDOUT:
			case 0:
				break;
			default:
				RRR_BUG("BUG: Return from pthread_cond_timedwait was %i %s in __rrr_thread_signal_wait_cond_timed\n",
						errno, rrr_strerror(errno));
		}
	}
}

void rrr_thread_signal_wait_cond_with_watchdog_update (
		struct rrr_thread *thread,
		int signal
) {
	while (1) {
		rrr_thread_lock(thread);
		int signal_test = thread->signal;
		thread->watchdog_time = rrr_time_get_64();
		rrr_thread_unlock(thread);

		if ((signal_test & signal) == signal) {
			break;
		}

		__rrr_thread_signal_wait_cond_timed(thread);
	}
}

int rrr_thread_ghost_check (
		struct rrr_thread *thread
) {
	int ret;
	rrr_thread_lock(thread);
	ret = thread->is_ghost;
	rrr_thread_unlock(thread);
	return ret;
}

int rrr_thread_state_get (
		struct rrr_thread *thread
) {
	int state;
	rrr_thread_lock(thread);
	state = thread->state;
	rrr_thread_unlock(thread);
	return state;
}

int rrr_thread_state_check (
		struct rrr_thread *thread,
		int state
) {
	int ret = 0;
	rrr_thread_lock(thread);
	ret = RRR_THREAD_STATE_CHECK(thread->state, state);
	rrr_thread_unlock(thread);
	return ret;
}

void rrr_thread_state_set (
		struct rrr_thread *thread,
		int new_state
) {
	rrr_thread_lock(thread);

	RRR_DBG_8 ("Thread %s setting state %i\n", thread->name, new_state);

	if (new_state == RRR_THREAD_STATE_STOPPED && (
			thread->state != RRR_THREAD_STATE_RUNNING_FORKED &&
			thread->state != RRR_THREAD_STATE_INITIALIZED &&
			thread->state != RRR_THREAD_STATE_STOPPING
		)
	) {
		RRR_MSG_0 ("Warning: Setting STOPPED state of thread %p name %s which never completed initialization\n",
				thread, thread->name);
	}

	thread->state = new_state;

	rrr_thread_unlock(thread);
}

static void __rrr_thread_self_set (
		struct rrr_thread *thread
) {
	rrr_thread_lock(thread);
	thread->self = pthread_self();
	rrr_thread_unlock(thread);
}

static int __rrr_thread_collection_has_thread (
		struct rrr_thread_collection *collection,
		struct rrr_thread *thread
) {
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

	struct rrr_thread *thread = malloc(sizeof(*thread));
	if (thread == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_thread_allocate_thread\n");
		ret = 1;
		goto out;
	}

	memset(thread, '\0', sizeof(struct rrr_thread));

	RRR_DBG_8 ("Allocate thread %p\n", thread);

	if (rrr_posix_mutex_init(&thread->mutex, RRR_THREAD_MUTEX_INIT_FLAGS) != 0) {
		RRR_MSG_0("Could not create mutex in __rrr_thread_allocate_thread\n");
		ret = 1;
		goto out_free;
	}

	if (rrr_posix_cond_init(&thread->signal_cond, 0) != 0) {
		RRR_MSG_0("Could not create condition in __rrr_thread_allocate_thread\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	thread->is_watchdog = is_watchdog;

	*target = thread;

	goto out;
	out_destroy_mutex:
		pthread_mutex_destroy(&thread->mutex);
	out_free:
		free(thread);
	out:
		return ret;
}

int rrr_thread_collection_count (
		struct rrr_thread_collection *collection
) {
	int count = 0;

	pthread_mutex_lock(&collection->threads_mutex);
	count = RRR_LL_COUNT(collection);
	pthread_mutex_unlock(&collection->threads_mutex);

	return count;
}

int rrr_thread_collection_new (
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

static void __rrr_thread_collection_stop_and_join_all_nolock (
		struct rrr_thread_collection *collection
) {
	RRR_DBG_8 ("Stopping all threads\n");

	// No errors allowed in this function

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->thread == 0) {
			RRR_BUG("BUG: Not thread ID set for thread in __rrr_thread_collection_stop_and_join_all_nolock, initialization function must not produce this state\n");
		}
		if (node->is_watchdog) {
			// Setting encourage stop to watchdog makes it skip initial 1 second
			// startup grace should it not already have been started
			RRR_DBG_8 ("Setting encourage stop and start signal thread WD '%s'/%p\n", node->name, node);
		}
		else {
			RRR_DBG_8 ("Setting encourage stop and start signal thread %s/%p\n", node->name, node);
		}
		node->signal |= RRR_THREAD_SIGNAL_ENCOURAGE_STOP|RRR_THREAD_SIGNAL_START_INITIALIZE|RRR_THREAD_SIGNAL_START_AFTERFORK|RRR_THREAD_SIGNAL_START_BEFOREFORK;
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
}

void rrr_thread_collection_destroy (
		struct rrr_thread_collection *collection
) {
	pthread_mutex_lock(&collection->threads_mutex);

	__rrr_thread_collection_stop_and_join_all_nolock(collection);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->is_ghost == 1) {
			// TODO : thread_cleanup() does not lock, maybe it should to avoid race
			// condition with is_ghost and ghost_cleanup_pointer

			RRR_MSG_0 ("Thread %s is ghost when freeing all threads. It will add itself to cleanup list if it wakes up.\n",
					node->name);
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		rrr_thread_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, __rrr_thread_destroy(node));

	pthread_mutex_unlock(&collection->threads_mutex);
	pthread_mutex_destroy(&collection->threads_mutex);

	free(collection);
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
		int state = rrr_thread_state_get(thread);
		if (state == RRR_THREAD_STATE_RUNNING_FORKED) {
			RRR_BUG("BUG: Thread %p name %s started prior to receiving signal\n", thread, thread->name);
		}
		else if ( state == RRR_THREAD_STATE_NEW ||
		          state == RRR_THREAD_STATE_INITIALIZED ||
		          state == RRR_THREAD_STATE_STOPPED
		) {
			was_ok = 1;
			break;
		}
		rrr_posix_usleep(25000); // 25 ms
	}

	if (was_ok != 1) {
		int state = rrr_thread_state_get(thread);
		RRR_MSG_0 ("Thread %s did not transition to INITIALIZED in time, state is now %i\n",
				thread->name, state);
		ret = 1;
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

	// We can only use the sleep() function which only has second resolution. We therefore
	// busy-wait for many rounds before finally sleeping if the thread is slow to change
	// state.

	int was_ok = 0;

	const unsigned long long max = 100000000; // 100 mill
	unsigned long long int j;
	for (j = 0; j <= max; j++)  {
		if ( thread->state == RRR_THREAD_STATE_RUNNING_FORKED ||
		     thread->state == RRR_THREAD_STATE_STOPPED
		) {
			was_ok = 1;
			break;
		}
		if (j > max - 3) {
			sleep(1);
		}
		rrr_slow_noop();
	}

	if (was_ok != 1) {
		RRR_MSG_0 ("Thread %s did not transition to FORKED in time, state is now %i\n",
				thread->name, thread->state);
		ret = 1;
		goto out;
	}

	RRR_DBG_8("Thread %p name %s waiting ticks for FORKED: %llu\n", thread, thread->name, j);

	out:
	return ret;
}

static int  __rrr_thread_collection_start_all_wait_for_state_initialized (
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

int rrr_thread_collection_start_all (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	/* Signal threads to proceed to initialization stage. This is needed as some
	 * threads might need data from each other, and we ensure here that the downstream
	 * modules functions are not started untill all threads have been started */
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_INITIALIZE);
	RRR_LL_ITERATE_END();

	/* Wait for all threads to initialize */
	if ((ret = __rrr_thread_collection_start_all_wait_for_state_initialized (
			collection
	)) != 0) {
		goto out_unlock;
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
			goto out_unlock;
		}
	RRR_LL_ITERATE_END();

	RRR_DBG_8 ("All threads are now RUNNNIG_FORKED\n");

	/* Start all threads based on callback condition */
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
				rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_AFTERFORK);
			}
			else {
				must_retry = 1;
			}
		RRR_LL_ITERATE_END();
	} while (must_retry == 1);

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
			rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_BEFOREFORK);
			rrr_thread_signal_set(node, RRR_THREAD_SIGNAL_START_AFTERFORK);
		}
	RRR_LL_ITERATE_END();

	out_unlock:
		pthread_mutex_unlock(&collection->threads_mutex);
		return ret;
}

void rrr_thread_start_now_with_watchdog (
		struct rrr_thread *thread
) {
	rrr_thread_lock(thread);
	struct rrr_thread *wd = thread->watchdog;
	rrr_thread_unlock(thread);

	RRR_DBG_8("START thread %p '%s'\n", thread, thread->name);
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_START_INITIALIZE);
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	rrr_thread_signal_set(thread, RRR_THREAD_SIGNAL_START_AFTERFORK);

	RRR_DBG_8("START watchdog %p '%s'\n", wd, wd->name);
	rrr_thread_signal_set(wd, RRR_THREAD_SIGNAL_START_INITIALIZE);
	rrr_thread_signal_set(wd, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	rrr_thread_signal_set(wd, RRR_THREAD_SIGNAL_START_AFTERFORK);
}

void rrr_thread_initialize_now_with_watchdog (
		struct rrr_thread *thread
) {
	rrr_thread_lock(thread);
	struct rrr_thread *wd = thread->watchdog;
	rrr_thread_unlock(thread);

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

	pthread_mutex_lock(&collection->threads_mutex);
	RRR_LL_APPEND(collection, thread);
	pthread_mutex_unlock(&collection->threads_mutex);
}

static void __rrr_thread_ghost_set (
		struct rrr_thread *thread
) {
	rrr_thread_lock(thread);
	thread->is_ghost = 1;
	rrr_thread_unlock(thread);
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
	free(arg);

	uint64_t freeze_limit = 0;

	struct rrr_thread *thread = data.watched_thread;
	struct rrr_thread *self_thread = data.watchdog_thread;

	rrr_thread_lock(thread);
	freeze_limit = thread->watchdog_timeout_us;
	rrr_thread_unlock(thread);

	RRR_DBG_8 ("Watchdog %p for %s/%p started, waiting for start signals\n", self_thread, thread->name, thread);

	rrr_thread_signal_wait_busy(self_thread, RRR_THREAD_SIGNAL_START_INITIALIZE);
	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_busy(self_thread, RRR_THREAD_SIGNAL_START_BEFOREFORK);
	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_RUNNING_FORKED);
	rrr_thread_signal_wait_busy(self_thread, RRR_THREAD_SIGNAL_START_AFTERFORK);

	RRR_DBG_8 ("Watchdog %p for %s/%p start signals received\n", self_thread, thread->name, thread);

	if (rrr_thread_signal_check(self_thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) {
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

		// Read all variables at once and check them later
		rrr_thread_lock(thread);
		const int signals = thread->signal;
		const int state = thread->state;
		const uint64_t prevtime = thread->watchdog_time;
		rrr_thread_unlock(thread);

		// Main might try to stop the thread
		if (RRR_THREAD_SIGNAL_CHECK(signals, RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread received encourage stop\n", self_thread, thread->name, thread);
			break;
		}

		if (	!RRR_THREAD_STATE_CHECK(state, RRR_THREAD_STATE_RUNNING_FORKED) &&
				!RRR_THREAD_STATE_CHECK(state, RRR_THREAD_STATE_INITIALIZED)
		) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread state is not RUNNING or INITIALIZED\n", self_thread, thread->name, thread);
			break;
		}
		else if (!rrr_config_global.no_watchdog_timers &&
				(prevtime + freeze_limit * RRR_THREAD_FREEZE_LIMIT_FACTOR < nowtime)
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

		if (RRR_THREAD_STATE_CHECK(state, RRR_THREAD_STATE_INITIALIZED)) {
			// Waits for any signal change
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
	
	RRR_DBG_8 ("Watchdog %p for %s/%p, waiting for thread to set STOPPED pass 1/2, current state is: %i\n", self_thread, thread->name, thread, rrr_thread_state_get(thread));

	// Wait for thread to set STOPPED
	uint64_t killtime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
	uint64_t patient_stop_time = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_PATIENT_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
#ifndef RRR_THREAD_DISABLE_CANCELLING
	while (rrr_thread_state_get(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();

		// If the shutdown routines of a thread usually take some time, it
		// may set STOPPING after it's loop has ended.
		if (rrr_thread_state_get(thread) == RRR_THREAD_STATE_STOPPING && nowtime < patient_stop_time) {
			RRR_DBG_8 ("Watchdog %p for %s/%p, thread has set STOPPING state, being more patient\n", self_thread, thread->name, thread);
			rrr_posix_usleep(500000); // 500ms
		}
		else if (nowtime > killtime) {
			RRR_MSG_0 ("Watchdog %p for %s/%p, thread not responding to encourage stop. State is now %i. Trying to cancel it.\n",
				self_thread, thread->name, thread, thread->state);
			if (thread->cancel_function != NULL) {
				int res = thread->cancel_function(thread);
				RRR_MSG_0 ("Watchdog %p for %s/%p, result from custom cancel function: %i\n", self_thread, thread->name, thread, res);
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
	RRR_DBG_8 ("Watchdog %p for %s/%p, thread watchdog cancelling disabled, soft stop signals only\n", self_thread, thread->name, thread);
#endif

	RRR_DBG_8 ("Watchdog %p for %s/%p to set STOPPED pass 2/2, current state is: %i\n", self_thread, thread->name, thread, rrr_thread_state_get(thread));

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	uint64_t ghosttime = rrr_time_get_64() + RRR_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * RRR_THREAD_FREEZE_LIMIT_FACTOR;
	while (rrr_thread_state_get(thread) != RRR_THREAD_STATE_STOPPED) {
		uint64_t nowtime = rrr_time_get_64();
		if (nowtime > ghosttime) {
			RRR_MSG_0 ("Watchdog %p for %s/%p, thread not responding to cancellation.\n",
				self_thread, thread->name, thread);
			if (rrr_thread_state_get(thread) == RRR_THREAD_STATE_NEW) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in NEW, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_get(thread) == RRR_THREAD_STATE_INITIALIZED) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in INITIALIZED, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_get(thread) == RRR_THREAD_STATE_RUNNING_FORKED) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in RUNNING_FORKED, has not started it's cleanup yet.\n",
					self_thread, thread->name, thread);
			}
			else if (rrr_thread_state_get(thread) == RRR_THREAD_STATE_STOPPING) {
				RRR_MSG_0 ("Watchdog %p for %s/%p, thread is stuck in STOPPING, it has started cleanup but this has not completed.\n",
					self_thread, thread->name, thread);
			}
			RRR_MSG_0 ("Watchdog %p for %s/%p, tagging thread as ghost.\n", self_thread, thread->name, thread);
			__rrr_thread_ghost_set(thread);
			break;
		}

		rrr_posix_usleep (10000); // 10 ms
	}

	out_nostop:

	RRR_DBG_8 ("Watchdog %p for %s/%p, thread state upon WD out: %i\n",
		self_thread, thread->name, thread, rrr_thread_state_get(thread));

	rrr_thread_state_set(self_thread, RRR_THREAD_STATE_STOPPED);

	pthread_exit(0);
}

static void __rrr_thread_cleanup (
		void *arg
) {
	struct rrr_thread *thread = arg;
	if (rrr_thread_ghost_check(thread)) {
		RRR_MSG_0 ("Thread %s waking up after being ghost, telling parent to clean up now.\n", thread->name);
		__rrr_thread_cleanup_postponed_push(thread);
	}
}

static void __rrr_thread_state_set_stopped (
		void *arg
) {
	struct rrr_thread *thread = arg;
	rrr_thread_state_set(thread, RRR_THREAD_STATE_STOPPED);
}

static void *__rrr_thread_start_routine_intermediate (
		void *arg
) {
	struct rrr_thread *thread = arg;

	__rrr_thread_self_set(thread);

	// STOPPED must be set at the very end, a  data structures to be freed
	pthread_cleanup_push(__rrr_thread_state_set_stopped, thread);
	pthread_cleanup_push(__rrr_thread_cleanup, thread);

	rrr_thread_signal_wait_busy(thread, RRR_THREAD_SIGNAL_START_INITIALIZE);
	if (!rrr_thread_signal_check(thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) {
		RRR_DBG_8("Thread %p/%s received initialize signal, proceeding\n", thread, thread->name);
		thread->start_routine(thread);
	}
	else {
		RRR_DBG_8("Thread %p/%s received encourage stop before initializing, exiting\n", thread, thread->name);
	}

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

	thread->watchdog->private_data = watchdog_data;

#ifdef RRR_THREAD_SIMULATE_START_FAILURE_A
	ret = 1;
	goto out;
#endif

	err = pthread_create(&thread->watchdog->thread, NULL, __rrr_thread_watchdog_entry, *watchdog_data);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting watchdog thread: %s\n", rrr_strerror(err));
		ret = 1;
		goto out;
	}

	RRR_DBG_8 ("Thread %s watchdog started\n", thread->name);

	// Watchdog thread will free the data immediately
	*watchdog_data = NULL;

#ifdef RRR_THREAD_SIMULATE_START_FAILURE_B
	ret = 1;
	goto out_stop_watchdog;
#endif

	err = pthread_create(&thread->thread, NULL, __rrr_thread_start_routine_intermediate, thread);
	if (err != 0) {
		RRR_MSG_0 ("Error while starting thread: %s\n", rrr_strerror(err));
		ret = 1;
		goto out_stop_watchdog;
	}
	pthread_detach(thread->thread);

	RRR_DBG_8 ("Started thread %s pthread address %p, it is now detached\n", thread->name, &thread->thread);

	goto out;
	out_stop_watchdog:
		RRR_DBG_8 ("Thread %s cancel and join with watchdog\n", thread->name);
		pthread_cancel(thread->watchdog->thread);
		pthread_join(thread->watchdog->thread, NULL);
	out:
		return ret;
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

static int __rrr_thread_allocate_watchdog_data (
		struct watchdog_data **result
) {
	*result = malloc(sizeof(**result));
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory for watchdog in __rrr_thread_start\n");
		return 1;
	}

	return 0;
}

static int __rrr_thread_allocate_and_start (
		struct rrr_thread **target,
		struct rrr_thread **target_wd,
		void *(*start_routine) (struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		void (*poststop_routine) (const struct rrr_thread *),
		int (*cancel_function) (struct rrr_thread *),
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
) {
	int ret = 0;

	*target = NULL;
	*target_wd = NULL;

	struct rrr_thread *thread = NULL;
	struct watchdog_data *watchdog_data = NULL;

	if (strlen(name) > sizeof(thread->name) - 5) {
		RRR_MSG_0 ("Name for thread was too long: '%s'\n", name);
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_thread_new(&thread, 0)) != 0) {
		goto out;
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

	if ((ret = __rrr_thread_allocate_watchdog_data(&watchdog_data)) != 0) {
		goto out_destroy_thread;
	}

#ifdef RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_B
	ret = 1;
	goto out_destroy_watchdog_data;
#endif

	if (__rrr_thread_new(&thread->watchdog, 1) != 0) {
		RRR_MSG_0("Could not allocate watchdog thread\n");
		ret = 1;
		goto out_destroy_watchdog_data;
	}

	// Do sprintf in two stages to avoid compile warning
	if (strlen(name) > 55) {
		RRR_BUG("BUG: Name of thread too long in __rrr_thread_allocate_and_start\n");
	}
	sprintf(thread->watchdog->name, "WD: ");
	sprintf(thread->watchdog->name + strlen(thread->watchdog->name), "%s", name);

	{
#ifdef RRR_THREAD_SIMULATE_ALLOCATION_FAILURE_C
		ret = 1;
		goto out_destroy_watchdog;
#endif

		int err = (preload_routine != NULL ? preload_routine(thread) : 0);

		if (err != 0) {
			RRR_MSG_0 ("Error while preloading thread\n");
			ret = 1;
			goto out_destroy_watchdog;
		}
	}

	watchdog_data->watched_thread = thread;
	watchdog_data->watchdog_thread = thread->watchdog;

	if ((ret = __rrr_thread_start(thread, &watchdog_data)) != 0) {
		goto out_destroy_watchdog;
	}

	*target = thread;
	*target_wd = thread->watchdog;

	goto out;
	out_destroy_watchdog:
		rrr_thread_unlock_if_locked(thread->watchdog);
		__rrr_thread_destroy(thread->watchdog);
	out_destroy_watchdog_data:
		RRR_FREE_IF_NOT_NULL(watchdog_data);
	out_destroy_thread:
		rrr_thread_unlock_if_locked(thread);
		__rrr_thread_destroy(thread);
		thread = NULL;
	out:
		return ret;
}

struct rrr_thread *rrr_thread_collection_thread_new (
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
	struct rrr_thread *thread_wd = NULL;

	if (__rrr_thread_allocate_and_start (
		&thread,
		&thread_wd,
		start_routine,
		preload_routine,
		poststop_routine,
		cancel_function,
		name,
		watchdog_timeout_us,
		private_data
	) != 0) {
		goto out;
	}

	__rrr_thread_collection_add_thread(collection, thread);
	__rrr_thread_collection_add_thread(collection, thread->watchdog);

	out:
		return thread;
}

int rrr_thread_collection_check_any_stopped (
		struct rrr_thread_collection *collection
) {
	int ret = 0;
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		if (	rrr_thread_state_get(node) == RRR_THREAD_STATE_STOPPED ||
				rrr_thread_ghost_check(node)
		) {
			RRR_DBG_8("Thread instance %s has stopped or is ghost\n", node->name);
			ret = 1;
		}
	RRR_LL_ITERATE_END();
	return ret;
}

void rrr_thread_collection_join_and_destroy_stopped_threads (
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
				// The second loop won't be able to find the watchdog anymore, tag the
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
		if (!node->is_watchdog) {
			if (node->watchdog == NULL) {
				RRR_BUG("BUG: No watchdog set for thread in second loop of rrr_thread_collection_join_and_destroy_stopped_threads, initialization function must not produce this state.\n");
			}

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
			if (node->poststop_routine != NULL) {
				RRR_BUG("BUG: poststop_routine was set for a thread which was attemted to be stopped using rrr_thread_collection_join_and_destroy_stopped_threads, this is not allowed\n");
			}
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

int rrr_thread_collection_iterate_non_wd_and_not_started_by_state (
		struct rrr_thread_collection *collection,
		int state,
		int (*callback)(struct rrr_thread *locked_thread, void *arg),
		void *callback_data
) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_thread);
		rrr_thread_lock(node);
		if (node->is_watchdog == 0 && (node->signal & ~(RRR_THREAD_SIGNAL_START_INITIALIZE)) == 0) {
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

