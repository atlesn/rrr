/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include "cmdlineparser/cmdline.h"
#include "threads.h"
#include "vl_time.h"
#include "../global.h"

//#define VL_THREAD_NO_WATCHDOGS

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
		VL_MSG_ERR ("Attempted to set STARTING state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_FREE) {
		VL_MSG_ERR ("Attempted to set FREE state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_INITIALIZED) {
		VL_MSG_ERR ("Attempted to set RUNNING state of thread while it was not in INITIALIZED state\n");
		exit (EXIT_FAILURE);
	}
/*	if (state == VL_THREAD_STATE_ENCOURAGE_STOP && thread->state != VL_THREAD_STATE_RUNNING) {
		VL_MSG_ERR ("Warning: Attempted to set ENCOURAGE STOP state of thread while it was not in RUNNING state\n");
		goto nosetting;
	}*/
	if (state == VL_THREAD_STATE_STOPPING && (thread->state != VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_INIT)) {
		VL_MSG_ERR ("Warning: Attempted to set STOPPING state of thread %p while it was not in ENCOURAGE STOP or RUNNING state\n", thread);
		goto nosetting;
	}
	if (state == VL_THREAD_STATE_STOPPED && (thread->state != VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_STOPPING)) {
		VL_MSG_ERR ("Warning: Attempted to set STOPPED state of thread %p while it was not in ENCOURAGE STOP or STOPPING state\n", thread);
		goto nosetting;
	}

	thread->state = state;

	nosetting:
	thread_unlock(thread);;
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

int __thread_new_thread (struct vl_thread **target) {
	int ret = 0;
	*target = NULL;

	struct vl_thread *thread = malloc(sizeof(*thread));
	if (thread == NULL) {
		VL_MSG_ERR("Could not allocate memory for thread thread\n");
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_1 ("Initialize thread %p\n", thread);
	memset(thread, '\0', sizeof(struct vl_thread));
	pthread_mutex_init(&thread->mutex, NULL);

	*target = thread;

	out:
	return ret;
}

void __thread_destroy (struct vl_thread_collection *collection, struct vl_thread *thread) {
	thread_lock(thread);
	if (thread->state != VL_THREAD_STATE_STOPPED) {
		VL_MSG_ERR ("Attempted to free thread which was not STOPPED\n");
		exit (EXIT_FAILURE);
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
			thread->ghost_cleanup_pointer = thread;
			thread_unlock(thread);
		}
		else {
			thread_unlock(thread);
			// TODO : Add pthread_mutex_destroy(threads[i]->....) and test
			__thread_destroy(collection, thread);
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

	/* Signal all threads to proceed */
	VL_THREADS_LOOP(thread,collection) {
		if (thread_get_state(thread) == VL_THREAD_STATE_INITIALIZED && thread->is_watchdog != 1) {
			thread_set_signal(thread, VL_THREAD_SIGNAL_START);
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
	printf ("Adding thread %p to collection %p\n", thread, collection);

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

	// Wait one second in case main thread does stuff
	usleep(1000000);

	VL_DEBUG_MSG_1 ("Watchdog %p for thread %s/%p, finished waiting.\n", self_thread, thread->name, thread);


	update_watchdog_time(thread);

	thread_set_state(self_thread, VL_THREAD_STATE_INITIALIZED);
	thread_set_state(self_thread, VL_THREAD_STATE_RUNNING);

	while (1) {
		uint64_t nowtime = time_get_64();
		uint64_t prevtime = get_watchdog_time(thread);

		// We or others might try to kill the thread
		if (thread_check_kill_signal(thread)) {
			VL_DEBUG_MSG_1 ("Thread %s/%p received kill signal\n", thread->name, thread);
			break;
		}

		if (	!thread_check_state(thread, VL_THREAD_STATE_RUNNING) &&
				!thread_check_state(thread, VL_THREAD_STATE_INIT) &&
				!thread_check_state(thread, VL_THREAD_STATE_INITIALIZED)
		) {
			VL_DEBUG_MSG_1 ("Thread %s/%p state was no longer RUNNING\n", thread->name, thread);
			break;
		}
		else if (prevtime + VL_THREAD_WATCHDOG_FREEZE_LIMIT * 1000 < nowtime) {
			VL_MSG_ERR ("Thread %s/%p froze, attempting to kill\n", thread->name, thread);
			thread_set_signal(thread, VL_THREAD_SIGNAL_KILL);
			break;
		}

		usleep (50000); // 50 ms
	}

	if (	thread_check_state(thread, VL_THREAD_STATE_STOPPED) ||
			thread_check_state(thread, VL_THREAD_STATE_STOPPING)
	) {
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

	if (thread_check_state(thread, VL_THREAD_STATE_INITIALIZED)) {
		VL_DEBUG_MSG_1("Thread %s/%p was in INITIALIZED state, set start signal\n", thread->name, thread);
		thread_set_signal(thread, VL_THREAD_SIGNAL_START);
		usleep (500000); // 500 ms
	}

	int state = thread_get_state(thread);
	if (state < VL_THREAD_STATE_RUNNING && state > VL_THREAD_STATE_STOPPED) {
		VL_MSG_ERR("Warning: Thread %s/%p slow to leave INIT/INITIALIZED state, maybe we have to force it to exit. State is now %i.\n", thread->name, thread, thread->state);
	}

	thread_set_signal(thread, VL_THREAD_SIGNAL_ENCOURAGE_STOP);

//	__thread_set_state_hard(thread, VL_THREAD_STATE_ENCOURAGE_STOP);

	// Wait for thread to set STOPPED or STOPPING, some simply skip STOPPING or we don't execute fast enough to trap it
	uint64_t prevtime = time_get_64();
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED && thread_get_state(thread) != VL_THREAD_STATE_STOPPING) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 < nowtime) {
			VL_MSG_ERR ("Thread %s/%p not responding to kill. State is now %i. Killing it harder.\n", thread->name, thread, thread->state);
			pthread_cancel(thread->thread);
			break;
		}

		usleep (10000); // 10 ms
	}

	VL_DEBUG_MSG_1 ("Detected exit of thread %s/%p.\n", thread->name, thread);


	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 < nowtime) {
			pthread_cancel(thread->thread);
			VL_MSG_ERR ("Thread %s/%p not responding to kill. Killing it harder.\n", thread->name, thread);
			usleep (100000); // 100ms
			void *retval;
			if (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
				VL_MSG_ERR ("Thread %s/%p dies slowly, waiting a bit more.\n", thread->name, thread);
				usleep (2000000); // 2000ms
				if (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
					VL_MSG_ERR ("Thread %s/%p doesn't seem to want to let go. Ignoring it and tagging as ghost.\n", thread->name, thread);
					thread->is_ghost = 1;
					break;
				}
			}
			VL_DEBUG_MSG_1 ("Thread %s/%p finished.\n", thread->name, thread);
			break;
		}
		usleep (10000); // 10 ms
	}

	out_nostop:

//	thread_set_state(self_thread, VL_THREAD_STATE_ENCOURAGE_STOP);
	thread_set_state(self_thread, VL_THREAD_STATE_STOPPING);
	thread_set_state(self_thread, VL_THREAD_STATE_STOPPED);

	VL_DEBUG_MSG_1 ("Thread %s/%p state after stopping: %i\n", thread->name, thread, thread_get_state(thread));

	pthread_exit(0);
}

void __thread_cleanup(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	struct vl_thread *thread = start_data->thread;
	thread_set_state(thread, VL_THREAD_STATE_STOPPED);
	free(start_data);

	// Check if we have died slowly and need to clean something up
	// from our parent which has abandoned us

	// TODO : Maybe we should lock the thread to avoid race condition with
	// threads_destroy()
	if (thread->is_ghost && thread->ghost_cleanup_pointer != NULL) {
		VL_MSG_ERR ("Thread waking up after being ghost, cleaning up for parent.");
		free(thread->ghost_cleanup_pointer);
	}
}

void *__thread_start_routine_intermediate(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	pthread_cleanup_push(__thread_cleanup, start_data);
	start_data->start_routine(start_data);
	pthread_cleanup_pop(1);
	thread_set_state(start_data->thread, VL_THREAD_STATE_STOPPED);
	return NULL;
}

void threads_stop_and_join (struct vl_thread_collection *collection) {
	VL_DEBUG_MSG_1 ("Stopping all threads\n");

	pthread_mutex_lock(&collection->threads_mutex);

	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog) {
			continue;
		}
		thread_lock(thread);
		if (	thread->state == VL_THREAD_STATE_RUNNING ||
				thread->state == VL_THREAD_STATE_INIT ||
				thread->state == VL_THREAD_STATE_INITIALIZED
		) {
			VL_DEBUG_MSG_1 ("Setting kill signal thread %s/%p\n", thread->name, thread);
			thread->signal = VL_THREAD_SIGNAL_KILL;
		}
		thread_unlock(thread);
	}

	// Wait for watchdogs to change state of thread
	//usleep (VL_THREAD_WATCHDOG_KILLTIME_LIMIT*1000*2);

	// Join with the watchdogs. The other threads might be in hung up state.
	VL_THREADS_LOOP(thread,collection) {
		if (thread->is_watchdog) {
			printf ("Joining with thread watchdog %s\n", thread->name);
			void *ret;
			pthread_join(thread->thread, &ret);
		}
	}

	// Don't unlock, destroy does that
}

struct vl_thread *thread_preload_and_register (
		struct vl_thread_collection *collection,
		void *(*start_routine) (struct vl_thread_start_data *), void *arg, const char *name
) {
	struct vl_thread *thread = NULL;
	struct vl_thread *watchdog_thread = NULL;
	struct vl_thread_start_data *start_data = NULL;

	if (__thread_new_thread(&thread) != 0) {
		VL_MSG_ERR("Could not allocate thread\n");
		goto out_error;
	}
	__thread_collection_add_thread(collection, thread);

	if (strlen(name) > sizeof(thread->name) - 5) {
		VL_MSG_ERR ("Name for thread was too long: '%s'\n", name);
		goto out_error;
	}

	thread->watchdog_time = 0;
	thread->signal = 0;
	sprintf(thread->name, "%s", name);

	if (__thread_new_thread(&watchdog_thread) != 0) {
		VL_MSG_ERR("Could not allocate watchdog thread\n");
		goto out_error;
	}
	__thread_collection_add_thread(collection, watchdog_thread);


	thread_lock(thread);

	// The thread frees *start_data with a pthread cleanup function
	start_data = malloc(sizeof(*start_data));
	start_data->private_arg = arg;
	start_data->start_routine = start_routine;
	start_data->thread = thread;

	thread->state = VL_THREAD_STATE_INIT;

	int err;
	err = pthread_create(&thread->thread, NULL, __thread_start_routine_intermediate, start_data);
	if (err != 0) {
		VL_MSG_ERR ("Error while starting thread: %s\n", strerror(err));
		goto out_error;
	}

	printf ("Started thread %s pthread address %p\n", thread->name, &thread->thread);

	pthread_detach(thread->thread);

#ifndef VL_THREAD_NO_WATCHDOGS
	struct watchdog_data *watchdog_data = malloc(sizeof(*watchdog_data));
	watchdog_data->watchdog_thread = watchdog_thread;
	watchdog_data->watched_thread = thread;

	sprintf(watchdog_thread->name, "WD: %s", name);

	err = pthread_create(&watchdog_thread->thread, NULL, __thread_watchdog_entry, watchdog_data);
	if (err != 0) {
		VL_MSG_ERR ("Error while starting watchdog thread: %s\n", strerror(err));
		pthread_cancel(thread->thread);
		goto out_error;
	}

	watchdog_thread->is_watchdog = 1;

	VL_DEBUG_MSG_1 ("Thread %s Watchdog started\n", thread->name);
#endif

	// Thread tries to set a signal first and therefore can't proceed untill we unlock
	thread_unlock(thread);

	return thread;

	out_error:
	if (thread != NULL) {
		thread_unlock_if_locked(thread);
		__thread_destroy(collection, thread);
	}
	if (watchdog_thread != NULL) {
		thread_unlock_if_locked(watchdog_thread);
		__thread_destroy(collection, watchdog_thread);
	}
	if (start_data != NULL) {
		free(start_data);
	}

	return NULL;
}
