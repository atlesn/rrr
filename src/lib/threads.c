/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include "cmdlineparser/cmdline.h"
#include "threads.h"
#include "vl_time.h"
#include "../global.h"

//#define VL_THREAD_NO_WATCHDOGS
#define VL_THREAD_FREEZE_LIMIT_FACTOR 1000

struct vl_thread_ghost {
	struct vl_thread_ghost *next;
	struct vl_thread *thread;
};

static struct vl_thread_ghost *ghost_list_first = NULL;
static struct vl_thread_ghost_data *ghost_cleanup_list_first = NULL;
static pthread_mutex_t ghost_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void thread_clear_ghosts(void) {
	pthread_mutex_lock(&ghost_list_mutex);
	struct vl_thread_ghost *next;
	for (struct vl_thread_ghost *cur = ghost_list_first; cur != NULL; cur = next) {
		next = cur->next;
		free(cur);
	}
	pthread_mutex_unlock(&ghost_list_mutex);
}

int thread_has_ghosts(void) {
	pthread_mutex_lock(&ghost_list_mutex);
	for (struct vl_thread_ghost *cur = ghost_list_first; cur != NULL; cur = cur->next) {
		VL_MSG_ERR("Thread is ghost: %s\n", cur->thread->name);
	}
	pthread_mutex_unlock(&ghost_list_mutex);

	return (ghost_list_first != NULL);
}

// Lock should be held already
void thread_remove_ghost(const struct vl_thread *thread) {
	struct vl_thread_ghost *do_free = NULL;

	struct vl_thread_ghost *prev = NULL;
	for (struct vl_thread_ghost *cur = ghost_list_first; cur != NULL; cur = cur->next) {
			if (cur->thread == thread) {
				if (prev) {
					prev->next = cur->next;
				}
				else {
					ghost_list_first = cur->next;
				}
				break;
			}
			prev = cur;
	}

	if (do_free) {
		VL_MSG_ERR("Removed thread %s from ghost queue\n", do_free->thread->name);
		free (do_free);
	}
}

void thread_push_ghost(struct vl_thread *thread) {
	struct vl_thread_ghost *ghost = malloc(sizeof(*ghost));

	pthread_mutex_lock(&ghost_list_mutex);
	ghost->next = ghost_list_first;
	ghost->thread = thread;
	ghost_list_first = ghost;
	pthread_mutex_unlock(&ghost_list_mutex);
}

static inline struct vl_thread_ghost_data *thread_new_ghost_data (struct vl_thread *thread, void *ptr) {
	struct vl_thread_ghost_data *ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory in thread_new_ghost_data\n");
		return NULL;
	}

	memset (ret, '\0', sizeof(*ret));

	thread_lock(thread);
	ret->ghost_cleanup_pointer = ptr;
	ret->poststop_routine = thread->poststop_routine;
	ret->thread = thread;
	thread_unlock(thread);

	return ret;
}

void thread_add_ghost_data (struct vl_thread_ghost_data *data) {
	pthread_mutex_lock(&ghost_list_mutex);
	if (ghost_cleanup_list_first == NULL) {
		ghost_cleanup_list_first = data;
	}
	else {
		data->next = ghost_cleanup_list_first;
		ghost_cleanup_list_first = data;
	}
	pthread_mutex_unlock(&ghost_list_mutex);
}

int thread_run_ghost_cleanup(int *count) {
	int ret = 0;

	*count = 0;

	pthread_mutex_lock(&ghost_list_mutex);
	struct vl_thread_ghost_data *data = ghost_cleanup_list_first;
	while (data != NULL) {
		struct vl_thread_ghost_data *next = data->next;

		(*count)++;

		int do_thread_free = 0;
		int do_private_data_free = 0;

		// If free_as_ghost_data is zero, thread collection cleanup has not run yet. We then
		// only run the poststop routine and the thread struct will be freed later. If
		// collection cleanup is complete, we must free the thread struct as well.
		thread_lock(data->thread);

		VL_DEBUG_MSG_1("Running ghost cleanup for thread %s\n", data->thread->name);

		if (data->thread->free_by_ghost) {
			do_thread_free = 1;
		}
		if (data->thread->free_private_data_by_ghost) {
			do_private_data_free = 1;
		}

		if (data->thread->poststop_routine != NULL) {
			VL_DEBUG_MSG_1("Running post stop routine for thread %s\n", data->thread->name);
			data->thread->poststop_routine(data->thread);
		}
		data->poststop_routine = NULL; // Make sure things aren't done twice

		// TODO : Nobody sets this pointer
		if (data->ghost_cleanup_pointer != NULL) {
			free(data->ghost_cleanup_pointer);
		}

		thread_remove_ghost(data->thread);

		thread_unlock(data->thread);

		if (do_private_data_free) {
			free(data->thread->private_data);
		}
		if (do_thread_free) {
			free(data->thread);
		}
		free(data);

		data = next;
	}
	ghost_cleanup_list_first = NULL;
	pthread_mutex_unlock(&ghost_list_mutex);

	return ret;
}

void __thread_set_state_hard (struct vl_thread *thread, int state) {
	thread_lock(thread);

	VL_DEBUG_MSG_4 ("Thread %s set state hard to %i, state was %i\n", thread->name, state, thread->state);
	thread->state = state;

	thread_unlock(thread);
}

void thread_set_state (struct vl_thread *thread, int state) {
	thread_lock(thread);

	VL_DEBUG_MSG_4 ("Thread %s set state %i\n", thread->name, state);

	if (state == VL_THREAD_STATE_INIT) {
		VL_BUG("Attempted to set STARTING state of thread outside reserve_thread function\n");
	}
	if (state == VL_THREAD_STATE_FREE) {
		VL_BUG("Attempted to set FREE state of thread outside reserve_thread function\n");
	}
	if (state == VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_INITIALIZED && thread->state != VL_THREAD_STATE_RUNNING_FORKED) {
		VL_BUG("Attempted to set RUNNING state of thread while it was not in INITIALIZED or RUNNING_FORKED state\n");
	}
	if (state == VL_THREAD_STATE_RUNNING_FORKED && thread->state != VL_THREAD_STATE_RUNNING) {
		VL_BUG("Attempted to set RUNNING_FORKED state of thread while it was not in RUNNING state but %i\n", thread->state);
	}
	if (state == VL_THREAD_STATE_STOPPING && (thread->state != VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_RUNNING_FORKED && thread->state != VL_THREAD_STATE_INIT)) {
		VL_MSG_ERR ("Warning: Attempted to set STOPPING state of thread %p/%s while it was not in ENCOURAGE STOP or RUNNING state\n", thread, thread->name);
		goto nosetting;
	}
	if (state == VL_THREAD_STATE_STOPPED && (
			thread->state != VL_THREAD_STATE_RUNNING &&
			thread->state != VL_THREAD_STATE_RUNNING_FORKED &&
			thread->state != VL_THREAD_STATE_STOPPING
		)
	) {
		VL_MSG_ERR ("Warning: Attempted to set STOPPED state of thread %p while it was not in ENCOURAGE STOP or STOPPING state\n", thread);
		goto nosetting;
	}

	thread->state = state;

	nosetting:
	thread_unlock(thread);
}

int __thread_is_in_collection (struct vl_thread_collection *collection, struct vl_thread *thread) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	VL_THREADS_LOOP(test,collection) {
		if (test == thread) {
			ret = 1;
			break;
		}
	}

	pthread_mutex_unlock(&collection->threads_mutex);

	return ret;
}

int __thread_allocate_thread (struct vl_thread **target) {
	int ret = 0;
	*target = NULL;

	struct vl_thread *thread = malloc(sizeof(*thread));
	if (thread == NULL) {
		VL_MSG_ERR("Could not allocate memory for thread thread\n");
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_1 ("Allocate thread %p\n", thread);
	memset(thread, '\0', sizeof(struct vl_thread));
	pthread_mutex_init(&thread->mutex, NULL);

	*target = thread;

	out:
	return ret;
}

void __thread_destroy (struct vl_thread *thread) {
	thread_lock(thread);
	if (thread->state != VL_THREAD_STATE_STOPPED) {
		VL_BUG("Attempted to free thread which was not STOPPED\n");
	}
	thread->state = VL_THREAD_STATE_FREE;
	thread_unlock(thread);
	free(thread);
}

int thread_new_collection (struct vl_thread_collection **target) {
	int ret = 0;
	*target = NULL;

	struct vl_thread_collection *collection = malloc(sizeof(*collection));
	if (collection == NULL) {
		VL_MSG_ERR("Could not allocate memory for thread collection\n");
		ret = 1;
		goto out;
	}

	memset(collection, '\0', sizeof(*collection));

	pthread_mutex_init(&collection->threads_mutex, NULL);

	*target = collection;

	out:
	return ret;
}

void thread_destroy_collection (struct vl_thread_collection *collection) {
	// Stop threads function should already have locked and not unlocked again
	if (pthread_mutex_trylock(&collection->threads_mutex) != EBUSY) {
		VL_MSG_ERR("Collection was not locked in thread_destroy_collection, must call threads_stop_and_join first\n");
		exit (EXIT_FAILURE);
	}

	struct vl_thread *next;
	for(struct vl_thread *thread = collection->first; thread != NULL; thread = next) {
		thread_lock(thread);
		next = thread->next;
		if (thread->is_ghost == 1) {
			// TODO : thread_cleanup() does not lock, maybe it should to avoid race
			// condition with is_ghost and ghost_cleanup_pointer

			// Move pointer to thread, we expect it to clean up if it dies
			VL_MSG_ERR ("Thread is ghost when freeing all threads. Move main thread data pointer into thread for later cleanup.\n");
			thread->free_by_ghost = 1;
			thread_push_ghost(thread);
			thread_unlock(thread);
		}
		else {
			thread_unlock(thread);
			// TODO : Add pthread_mutex_destroy(threads[i]->....) and test
			__thread_destroy(thread);
		}
	}

	pthread_mutex_unlock(&collection->threads_mutex);
	pthread_mutex_destroy(&collection->threads_mutex);

	free(collection);
}

int thread_start_all_after_initialized (struct vl_thread_collection *collection) {
	int ret = 0;

	pthread_mutex_lock(&collection->threads_mutex);

	/* Wait for all threads to be in INITIALIZED state */
	VL_THREADS_LOOP(thread,collection) {
		int was_initialized = 0;
		if (thread->is_watchdog == 1) {
			continue;
		}
		for (int j = 0; j < 100; j++)  {
			int state = thread_get_state(thread);
			VL_DEBUG_MSG_1 ("Wait for thread %p name %s, state is now %i\n", thread, thread->name, state);
			if (	state == VL_THREAD_STATE_FREE ||
					state == VL_THREAD_STATE_INITIALIZED ||
					state == VL_THREAD_STATE_STOPPED ||
					state == VL_THREAD_STATE_STOPPING
			) {
				was_initialized = 1;
				break;
			}
			else if (state == VL_THREAD_STATE_RUNNING) {
				VL_MSG_ERR ("Bug: Thread %s did not wait for start signal.\n", thread->name);
				exit (EXIT_FAILURE);
			}
			usleep (10000);
		}
		if (was_initialized != 1) {
			VL_MSG_ERR ("Thread %s did not initialize itself in time\n", thread->name);
			ret = 1;
			goto out_unlock;
		}
	}

	/* Check for valid start priority */
	int fork_priority_threads_count = 0;
	VL_THREADS_LOOP(thread,collection) {
		if (thread->start_priority < 0 || thread->start_priority > VL_THREAD_START_PRIORITY_MAX) {
			VL_BUG("Thread %s has unknown start priority of %i\n", thread->name, thread->start_priority);
		}
		if (thread->is_watchdog != 1 && thread->start_priority == VL_THREAD_START_PRIORITY_FORK) {
			fork_priority_threads_count++;
		}
	}

	/* Signal priority 0 and fork threads to proceed */
	VL_THREADS_LOOP(thread,collection) {
		if (	thread->is_watchdog != 1 && (
					thread->start_priority == VL_THREAD_START_PRIORITY_NORMAL ||
					thread->start_priority == VL_THREAD_START_PRIORITY_FORK
				) &&
				thread_get_state(thread) == VL_THREAD_STATE_INITIALIZED
		) {
				VL_DEBUG_MSG_1 ("Start signal to thread %p name %s with priority NORMAL or FORK\n", thread, thread->name);
				thread_set_signal(thread, VL_THREAD_SIGNAL_START);
		}
	}

	VL_DEBUG_MSG_1 ("Wait for %i fork threads to set RUNNNIG_FORKED\n", fork_priority_threads_count);

	/* Wait for forking threads to finish off their forking-business. They might
	 * also have failed at this point in which they would set STOPPED or STOPPING */
	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog == 1 || thread->start_priority != VL_THREAD_START_PRIORITY_FORK) {
			continue;
		}
		while (1) {
			if (	thread_get_state(thread) == VL_THREAD_STATE_RUNNING_FORKED ||
					thread_get_state(thread) == VL_THREAD_STATE_STOPPED ||
					thread_get_state(thread) == VL_THREAD_STATE_STOPPING
			) {
				VL_DEBUG_MSG_1 ("Fork thread %p name %s set RUNNING_FORKED\n", thread, thread->name);
				fork_priority_threads_count--;
				break;
			}
		}
		if (fork_priority_threads_count == 0) {
			break;
		}
		if (fork_priority_threads_count < 0) {
			VL_BUG("Bug: fork_priority_threads_count was < 0\n");
		}
	}

	/* Finally, start network priority threads */
	VL_THREADS_LOOP(thread,collection) {
		if (	thread->is_watchdog != 1 &&
				thread->start_priority == VL_THREAD_START_PRIORITY_NETWORK
		) {
			thread_set_signal(thread, VL_THREAD_SIGNAL_START);
			VL_DEBUG_MSG_1 ("Start signal to thread %p name %s with priority NETWORK\n", thread, thread->name);
		}
	}

	/* Double check that everything was started */
	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog != 1 && !thread_check_signal(thread, VL_THREAD_SIGNAL_START)) {
			VL_BUG("Bug: Thread %s did not receive start signal\n", thread->name);
		}
	}

	out_unlock:
	pthread_mutex_unlock(&collection->threads_mutex);
	return ret;
}

void __thread_collection_remove_thread (struct vl_thread_collection *collection, struct vl_thread *thread) {
	pthread_mutex_lock(&collection->threads_mutex);

	if (collection->first == thread) {
		collection->first = thread->next;
	}
	else {
		int found = 0;
		VL_THREADS_LOOP(test,collection) {
			thread_lock(test);
			if (test->next == thread) {
				test->next = thread->next;
				found = 1;
			}
			thread_unlock(test);
		}
		if (found != 1) {
			VL_MSG_ERR("BUG: Could not find thread to be freed in linked list\n");
			exit(EXIT_FAILURE);
		}
	}

	pthread_mutex_unlock(&collection->threads_mutex);
}

void __thread_collection_add_thread (struct vl_thread_collection *collection, struct vl_thread *thread) {
//	VL_DEBUG_MSG_1 ("Adding thread %p to collection %p\n", thread, collection);

	if (__thread_is_in_collection(collection, thread)) {
		VL_MSG_ERR("BUG: Attempted to add thread to collection in which it was already part of\n");
		exit(EXIT_FAILURE);
	}

	pthread_mutex_lock(&collection->threads_mutex);

	thread->next = collection->first;
	collection->first = thread;

	pthread_mutex_unlock(&collection->threads_mutex);
}

struct watchdog_data {
	struct vl_thread *watchdog_thread;
	struct vl_thread *watched_thread;
};

void *__thread_watchdog_entry (void *arg) {
	// COPY AND FREE !!!!
	struct watchdog_data data = *((struct watchdog_data *)arg);
	free(arg);

	struct vl_thread *thread = data.watched_thread;
	struct vl_thread *self_thread = data.watchdog_thread;

	VL_DEBUG_MSG_1 ("Watchdog %p started for thread %s/%p, waiting 1 second.\n", self_thread, thread->name, thread);

	// Wait a bit in case main thread does stuff
	usleep(20000);

	VL_DEBUG_MSG_1 ("Watchdog %p for thread %s/%p, finished waiting.\n", self_thread, thread->name, thread);


	update_watchdog_time(thread);

	thread_set_state(self_thread, VL_THREAD_STATE_INITIALIZED);
	thread_set_state(self_thread, VL_THREAD_STATE_RUNNING);

	uint64_t prev_loop_time = time_get_64();
	while (1) {

		uint64_t nowtime = time_get_64();
		uint64_t prevtime = get_watchdog_time(thread);

		// We or others might try to kill the thread
		if (thread_check_kill_signal(thread) || thread_check_encourage_stop(thread)) {
			VL_DEBUG_MSG_1 ("Thread %s/%p received kill signal\n", thread->name, thread);
			break;
		}

		if (	!thread_check_state(thread, VL_THREAD_STATE_RUNNING) &&
				!thread_check_state(thread, VL_THREAD_STATE_RUNNING_FORKED) &&
				!thread_check_state(thread, VL_THREAD_STATE_INIT) &&
				!thread_check_state(thread, VL_THREAD_STATE_INITIALIZED)
		) {
			VL_DEBUG_MSG_1 ("Thread %s/%p state was no longer RUNNING\n", thread->name, thread);
			break;
		}
		else if (!rrr_global_config.no_watchdog_timers &&
				(prevtime + (long long unsigned int) VL_THREAD_WATCHDOG_FREEZE_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR < nowtime)
		) {
			if (time_get_64() - prev_loop_time > 100000) { // 100 ms
				VL_MSG_ERR ("Thread %s/%p has been frozen but so has the watchdog, maybe we are debugging?\n", thread->name, thread);
			}
			else {
				VL_MSG_ERR ("Thread %s/%p froze, attempting to kill\n", thread->name, thread);
				thread_set_signal(thread, VL_THREAD_SIGNAL_KILL);
				break;
			}
		}

		prev_loop_time = time_get_64();
		usleep (50000); // 50 ms
	}

	if (thread_check_state(thread, VL_THREAD_STATE_STOPPED)) {
		// Thread has stopped by itself
		goto out_nostop;
	}

	// If thread is about to start, wait a bit. If main thread hasn't completed with the
	// INIT / INITIALIZED / START-sequence, we attempt to do that now.

	if (thread_check_state(thread, VL_THREAD_STATE_INIT)) {
		VL_DEBUG_MSG_1("Thread %s/%p wasn't finished starting, wait for it to initialize\n", thread->name, thread);
		int limit = 10;
		while (!thread_check_state(thread, VL_THREAD_STATE_INITIALIZED) && limit > 0) {
			VL_DEBUG_MSG_1("Thread %s/%p wasn't finished starting, wait for it to initialize (try %i)\n", thread->name, thread, limit);
			usleep (50000); // 50 ms (x 10)
			limit--;
		}
		if (!thread_check_state(thread, VL_THREAD_STATE_INITIALIZED)) {
			VL_DEBUG_MSG_1("Thread %s/%p won't initialize, maybe we have to force it to quit\n", thread->name, thread);
		}
	}

	int state = thread_get_state(thread);
	if (state < VL_THREAD_STATE_RUNNING && state > VL_THREAD_STATE_STOPPED) {
		VL_MSG_ERR("Warning: Thread %s/%p slow to leave INIT/INITIALIZED state, maybe we have to force it to exit. State is now %i.\n", thread->name, thread, thread->state);
	}

	thread_set_signal(thread, VL_THREAD_SIGNAL_KILL);

	// Wait for thread to set STOPPED or STOPPING, some simply skip STOPPING or we don't execute fast enough to trap it
	uint64_t prevtime = time_get_64();
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR < nowtime) {
			VL_MSG_ERR ("Thread %s/%p not responding to kill. State is now %i. Killing it harder.\n", thread->name, thread, thread->state);
			if (thread->cancel_function != NULL) {
				int res = thread->cancel_function(thread);
				VL_MSG_ERR ("Thread %s/%p result from custom cancel function: %i\n", thread->name, thread, res);
			}
			else {
				pthread_cancel(thread->thread);
			}
			usleep(1000000); // 1 s
			break;
		}

		usleep (10000); // 10 ms
	}

	VL_DEBUG_MSG_1 ("Wait for thread %s/%p to set STOPPED, current state is: %i\n", thread->name, thread, thread_get_state(thread));

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	prevtime = time_get_64();
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 * VL_THREAD_FREEZE_LIMIT_FACTOR< nowtime) {
			VL_MSG_ERR ("Thread %s/%p not responding to cancellation, try again .\n", thread->name, thread);
			if (thread->cancel_function != NULL) {
				int res = thread->cancel_function(thread);
				VL_MSG_ERR ("Thread %s/%p result from custom cancel function: %i\n", thread->name, thread, res);
			}
			else {
				pthread_cancel(thread->thread);
			}
			usleep(1000000);
			if (thread_get_state(thread) == VL_THREAD_STATE_STOPPING) {
				VL_MSG_ERR ("Thread %s/%p is stuck in STOPPING, not finished with it's cleanup.\n", thread->name, thread);
			}
			else if (thread_get_state(thread) == VL_THREAD_STATE_RUNNING) {
				VL_MSG_ERR ("Thread %s/%p is stuck in RUNNING, has not started it's cleanup yet.\n", thread->name, thread);
			}
			else if (thread_get_state(thread) == VL_THREAD_STATE_RUNNING_FORKED) {
				VL_MSG_ERR ("Thread %s/%p is stuck in RUNNING_FORKED, has not started it's cleanup yet.\n", thread->name, thread);
			}
			VL_MSG_ERR ("Thread %s/%p: Tagging as ghost.\n", thread->name, thread);
			thread_set_ghost(thread);
			break;
		}

		usleep (10000); // 10 ms
	}

	VL_DEBUG_MSG_1 ("Thread %s/%p finished.\n", thread->name, thread);

	out_nostop:

	thread_set_state(self_thread, VL_THREAD_STATE_STOPPING);
	thread_set_state(self_thread, VL_THREAD_STATE_STOPPED);

	VL_DEBUG_MSG_1 ("Thread %s/%p state after stopping: %i\n", thread->name, thread, thread_get_state(thread));

	pthread_exit(0);
}

void __thread_cleanup(void *arg) {
	struct vl_thread *thread = arg;

	// Check if we have died slowly and need to clean something up
	// from our parent which has abandoned us

	// TODO : Maybe we should lock the thread to avoid race condition with
	// threads_destroy()
	if (thread_is_ghost(thread)) {
		VL_MSG_ERR ("Thread %s waking up after being ghost, telling parent to clean up now.\n", thread->name);
		struct vl_thread_ghost_data *ghost_data = thread_new_ghost_data(thread, NULL);
		if (ghost_data == NULL) {
			return;
		}
		thread_add_ghost_data(ghost_data);
	}
}

void *__thread_start_routine_intermediate(void *arg) {
	struct vl_thread *thread = arg;

	pthread_cleanup_push(thread_set_stopped, thread);
	pthread_cleanup_push(__thread_cleanup, thread);

	thread->start_routine(thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

void threads_stop_and_join (
		struct vl_thread_collection *collection,
		void (*upstream_ghost_handler)(struct vl_thread *thread)
) {
	VL_DEBUG_MSG_1 ("Stopping all threads\n");

	pthread_mutex_lock(&collection->threads_mutex);

	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog) {
			continue;
		}
		thread_lock(thread);
		if (	thread->state == VL_THREAD_STATE_RUNNING ||
				thread->state == VL_THREAD_STATE_RUNNING_FORKED ||
				thread->state == VL_THREAD_STATE_INIT ||
				thread->state == VL_THREAD_STATE_INITIALIZED
		) {
			VL_DEBUG_MSG_1 ("Setting encourage stop and start signal thread %s/%p\n", thread->name, thread);
			thread->signal = VL_THREAD_SIGNAL_ENCOURAGE_STOP|VL_THREAD_SIGNAL_START;
		}
		thread_unlock(thread);
	}

	// Wait for watchdogs to change state of thread
	//usleep (VL_THREAD_WATCHDOG_KILLTIME_LIMIT*1000*2);

	// Join with the watchdogs. The other threads might be in hung up state.
	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog) {
			VL_DEBUG_MSG_1 ("Joining with thread watchdog %s\n", thread->name);
			void *ret;
			pthread_join(thread->thread, &ret);
			VL_DEBUG_MSG_1 ("Joined with thread watchdog %s\n", thread->name);
		}
	}

	VL_THREADS_LOOP(thread,collection) {
		if (!thread->is_watchdog) {
			thread_lock(thread);
			if (thread->poststop_routine != NULL) {
				if (thread->state == VL_THREAD_STATE_STOPPED) {
					VL_DEBUG_MSG_1 ("Running post stop routine for %s\n", thread->name);
					thread->poststop_routine(thread);
				}
				else {
					VL_MSG_ERR ("Cannot run post stop for thread %s as it is not in STOPPED state\n", thread->name);
					if (!thread->is_ghost) {
						VL_MSG_ERR("Bug: Thread was not STOPPED nor ghost after join attempt\n");
						exit(EXIT_FAILURE);
					}
					VL_MSG_ERR ("Thread will run post stop itself after cleanup\n");
				}
			}
			if (thread->is_ghost) {
				upstream_ghost_handler(thread);
			}
			thread_unlock(thread);
		}
	}
	// Don't unlock, destroy does that
}

int thread_start (struct vl_thread *thread) {
	int err = 0;

	err = pthread_create(&thread->thread, NULL, __thread_start_routine_intermediate, thread);
	if (err != 0) {
		VL_MSG_ERR ("Error while starting thread: %s\n", strerror(err));
		goto out_error;
	}

	VL_DEBUG_MSG_1 ("Started thread %s pthread address %p\n", thread->name, &thread->thread);

	pthread_detach(thread->thread);

#ifndef VL_THREAD_NO_WATCHDOGS
	struct watchdog_data *watchdog_data = malloc(sizeof(*watchdog_data));
	watchdog_data->watchdog_thread = thread->watchdog;
	watchdog_data->watched_thread = thread;

	if (strlen(thread->name) > 55) {
		VL_BUG("Name of thread too long");
	}

	// Do this two-stage to avoid compile warning, we check the length above
	sprintf(thread->watchdog->name, "WD: ");
	sprintf(thread->watchdog->name + strlen(thread->watchdog->name), "%s", thread->name);

	err = pthread_create(&thread->watchdog->thread, NULL, __thread_watchdog_entry, watchdog_data);
	if (err != 0) {
		VL_MSG_ERR ("Error while starting watchdog thread: %s\n", strerror(err));
		pthread_cancel(thread->thread);
		goto out_error;
	}

	thread->watchdog->is_watchdog = 1;

	VL_DEBUG_MSG_1 ("Thread %s Watchdog started\n", thread->name);
#endif

	// Thread tries to set a signal first and therefore can't proceed untill we unlock
	thread_unlock(thread);

	return 0;

	out_error:
	if (thread != NULL) {
		thread_unlock_if_locked(thread);
	}
	if (thread->watchdog != NULL) {
		thread_unlock_if_locked(thread->watchdog);
	}

	return 1;
}

struct vl_thread *thread_preload_and_register (
		struct vl_thread_collection *collection,
		void *(*start_routine) (struct vl_thread *),
		int (*preload_routine) (struct vl_thread *),
		void (*poststop_routine) (const struct vl_thread *),
		int (*cancel_function) (struct vl_thread *),
		int start_priority,
		void *arg, const char *name
) {
	struct vl_thread *thread = NULL;

	if (__thread_allocate_thread(&thread) != 0) {
		VL_MSG_ERR("Could not allocate thread\n");
		goto out_error;
	}
	__thread_collection_add_thread(collection, thread);

	if (strlen(name) > sizeof(thread->name) - 5) {
		VL_MSG_ERR ("Name for thread was too long: '%s'\n", name);
		goto out_error;
	}

	thread->private_data = arg;
	thread->watchdog_time = 0;
	thread->signal = 0;
	thread->start_priority = start_priority;

	thread->cancel_function = cancel_function;
	thread->poststop_routine = poststop_routine;
	thread->start_routine = start_routine;

	sprintf(thread->name, "%s", name);

	if (__thread_allocate_thread(&thread->watchdog) != 0) {
		VL_MSG_ERR("Could not allocate watchdog thread\n");
		goto out_error;
	}
	__thread_collection_add_thread(collection, thread->watchdog);

	thread_lock(thread);

	thread->state = VL_THREAD_STATE_INIT;

	int err = (preload_routine != NULL ? preload_routine(thread) : 0);
	if (err != 0) {
		VL_MSG_ERR ("Error while preloading thread\n");
		goto out_error;
	}

	// Thread tries to set a signal first and therefore can't proceed until we unlock
	thread_unlock(thread);

	return thread;

	out_error:
	if (thread != NULL) {
		if (thread->watchdog != NULL) {
			thread_unlock_if_locked(thread->watchdog);
			__thread_destroy(thread->watchdog);
		}
		thread_unlock_if_locked(thread);
		__thread_destroy(thread);
	}

	return NULL;
}

int thread_check_any_stopped (struct vl_thread_collection *collection) {
	int ret = 0;
	VL_THREADS_LOOP(thread,collection) {
		if (
				thread_get_state(thread) == VL_THREAD_STATE_STOPPED ||
				thread_get_state(thread) == VL_THREAD_STATE_STOPPING ||
				thread_is_ghost(thread)
		) {
			VL_DEBUG_MSG_1("Thread instance %s has stopped or is ghost\n", thread->name);
			ret = 1;
		}
	}
	return ret;
}

void thread_free_double_pointer(void *arg) {
	struct vl_thread_double_pointer *data = arg;
	RRR_FREE_IF_NOT_NULL(*(data->ptr));
}

void thread_free_single_pointer(void *arg) {
	RRR_FREE_IF_NOT_NULL(arg);
}
