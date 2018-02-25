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

#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include "threads.h"


static struct vl_thread *threads[VL_THREADS_MAX];
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;

void threads_init() {
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		threads[i] = malloc(sizeof(struct vl_thread));
		printf ("Thread %d\n", i);
		printf ("Initialize thread %p\n", threads[i]);
		memset(threads[i], '\0', sizeof(struct vl_thread));
		pthread_mutex_init(&threads[i]->mutex, NULL);
	}
}

void free_thread(struct vl_thread *thread) {
	pthread_mutex_lock(&threads_mutex);

	int thread_found = 0;
	for (int i = 0; i < VL_THREADS_MAX && thread_found == 0; i++) {
		thread_lock(threads[i]);
		if (threads[i] == thread) {
			thread_found = 1;
			if (threads[i]->state != VL_THREAD_STATE_STOPPED) {
				fprintf (stderr, "Attempted to free thread which was not STOPPED\n");
				exit (EXIT_FAILURE);
			}
			threads[i]->state = VL_THREAD_STATE_FREE;
		}
		thread_unlock(threads[i]);
	}

	if (thread_found != 1) {
		fprintf (stderr, "Attemped to free thread which was not registered\n");
		exit (EXIT_FAILURE);
	}

	pthread_mutex_unlock(&threads_mutex);
}

static struct vl_thread *reserve_thread() {
	struct vl_thread *ret = NULL;

	pthread_mutex_lock(&threads_mutex);

	int thread_found = 0;
	for (int i = 0; i < VL_THREADS_MAX && thread_found == 0; i++) {
		if (threads[i] == NULL) {
			fprintf (stderr, "Warning: Found NULL entry while reserving thread\n");
			continue;
		}
		thread_lock(threads[i]);
		if (threads[i]->state == VL_THREAD_STATE_FREE) {
			threads[i]->state = VL_THREAD_STATE_STOPPED;
			ret = threads[i];
			thread_found = 1;
		}
		thread_unlock(threads[i]);
	}

	pthread_mutex_unlock(&threads_mutex);

	return ret;
}

void *thread_watchdog(void *arg) {
	struct vl_thread *thread = arg;
	usleep (500000);

	while (1) {
		uint64_t nowtime = time_get_64();
		uint64_t prevtime = get_watchdog_time(thread);

		// We or others might try to kill the thread
		if (thread_check_kill_signal(thread)) {
			fprintf (stderr, "Thread %p received kill signal\n", thread);
			break;
		}
		if (thread_get_state(thread) != VL_THREAD_STATE_RUNNING) {
			fprintf (stderr, "Thread %p state was no longed RUNNING\n", thread);
			break;
		}
		else if (prevtime + VL_THREAD_WATCHDOG_FREEZE_LIMIT * 1000 < nowtime) {
			fprintf (stderr, "Thread %p froze, attempting to kill\n", thread);
			thread_set_signal(thread, VL_THREAD_SIGNAL_KILL);
			break;
		}

		usleep (50000); // 50 ms
	}

	if (thread_get_state(thread) == VL_THREAD_STATE_STOPPED || thread_get_state(thread) == VL_THREAD_STATE_STOPPING) {
		// Thread has stopped by itself
		goto out_nostop;
	}

	thread_set_state(thread, VL_THREAD_STATE_ENCOURAGE_STOP);

	// Wait for thread to set STOPPED or STOPPING, some simply skip STOPPING or we don't execute fast enough to trap it
	uint64_t prevtime = time_get_64();
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED && thread_get_state(thread) != VL_THREAD_STATE_STOPPING) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 < nowtime) {
			pthread_cancel(thread->thread);
			fprintf (stderr, "Thread %p not responding to kill. Killing it harder.\n", thread);
			break;
		}

		usleep (10000); // 10 ms
	}

	// Wait for thread to set STOPPED only (this tells that the thread is finished cleaning up)
	while (thread_get_state(thread) != VL_THREAD_STATE_STOPPED) {
		uint64_t nowtime = time_get_64();
		if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 < nowtime) {
			pthread_cancel(thread->thread);
			fprintf (stderr, "Thread %p not responding to kill. Killing it harder.\n", thread);
			break;
		}
		usleep (10000); // 10 ms
	}

	out_nostop:
	printf ("Thread %p state after stopping: %i\n", thread, thread_get_state(thread));

	pthread_exit(0);
}

void thread_cleanup(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	struct vl_thread *thread = start_data->thread;
	thread_set_state(thread, VL_THREAD_STATE_STOPPED);
	free(start_data);
}

static void *start_routine_intermediate(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	pthread_cleanup_push(thread_cleanup, start_data);
	start_data->start_routine(start_data);
	pthread_cleanup_pop(1);
	thread_set_state(start_data->thread, VL_THREAD_STATE_STOPPED);
	return NULL;
}

/*
void thread_wait_state(struct vl_thread *thread, int state) {
	while (1) {
		pthread_mutex_lock(&thread->mutex);
		if (thread_get_state(thread) == state) {
			break;
		}
		pthread_mutex_unlock(&thread->mutex);
		usleep (10000); // 10ms
	}
}
*/
void threads_stop() {
	printf ("Stopping all threads\n");
	pthread_mutex_lock(&threads_mutex);
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		if (threads[i]->is_watchdog) {
			continue;
		}
		thread_lock(threads[i]);
		if (threads[i]->state == VL_THREAD_STATE_RUNNING) {
			printf ("Setting kill signal thread %p\n", threads[i]);
			threads[i]->signal = VL_THREAD_SIGNAL_KILL;
		}
		thread_unlock(threads[i]);
	}

	// Wait for watchdogs to change state of thread
	//usleep (VL_THREAD_WATCHDOG_KILLTIME_LIMIT*1000*2);

	// Join with the watchdogs. The other threads might be in hung up state.
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		if (threads[i]->is_watchdog) {
			void *ret;
			pthread_join(threads[i]->thread, &ret);
		}
		else {
			pthread_detach(threads[i]->thread);
		}
	}

	// Don't unlock, destroy does that
}

void threads_destroy() {
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		free(threads[i]);
		threads[i] = NULL;
	}
	pthread_mutex_unlock(&threads_mutex);
	pthread_mutex_destroy(&threads_mutex);
}


struct vl_thread *thread_start (void *(*start_routine) (struct vl_thread_start_data *), void *arg) {
	struct vl_thread *thread;
	struct vl_thread *watchdog_thread;

	thread = reserve_thread();
	if (thread == NULL) {
		fprintf (stderr, "Maximum number of threads reached, can't start another one\n");
		return NULL;
	}

	watchdog_thread = reserve_thread();
	if (watchdog_thread == NULL) {
		fprintf (stderr, "Maximum number of threads reached while reserving watchdog thread, can't start another one\n");
		free_thread(thread);
		return NULL;
	}

	thread->watchdog_time = 0;
	thread->signal = 0;

	thread_lock(thread);

	// The thread frees *start_data with a pthread cleanup function
	struct vl_thread_start_data *start_data  = malloc(sizeof(*start_data));
	start_data->private_arg = arg;
	start_data->start_routine = start_routine;
	start_data->thread = thread;

	thread->state = VL_THREAD_STATE_STARTING;

	int err;
	err = pthread_create(&thread->thread, NULL, start_routine_intermediate, start_data);
	if (err != 0) {
		fprintf (stderr, "Error while starting thread: %s\n", strerror(err));
		err = 1;
		free(start_data);
		goto nowatchdog;
	}

	err = pthread_create(&watchdog_thread->thread, NULL, thread_watchdog, thread);
	if (err != 0) {
		fprintf (stderr, "Error while starting watchdog thread: %s\n", strerror(err));
		err = 1;
		pthread_cancel(thread->thread);
	}

	watchdog_thread->is_watchdog = 1;

	printf ("Thread %p Watchdog %p\n", thread, watchdog_thread);

	nowatchdog:

	// Thread tries to set a signal first and therefore can't proceed untill we unlock
	thread_unlock(thread);

	return (err == 0 ? thread : NULL);
}
