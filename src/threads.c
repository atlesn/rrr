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
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include "threads.h"

// Milliseconds
#define VL_THREAD_WATCHDOG_FREEZE_LIMIT 5000
#define VL_THREAD_WATCHDOG_KILLTIME_LIMIT 5000

static struct vl_thread *threads[VL_THREADS_MAX];
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;

void threads_init() {
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		threads[i] = malloc(sizeof(struct vl_thread));
		memset(threads[i], '\0', sizeof(struct vl_thread));
		pthread_mutex_init(&threads[i]->mutex, NULL);
	}
}

int thread_get_state(struct vl_thread *thread) {
	int state;
	pthread_mutex_lock(&thread->mutex);
	state = thread->signal;
	pthread_mutex_unlock(&thread->mutex);
	return state;
}

int thread_get_signal(struct vl_thread *thread) {
	int signal;
	pthread_mutex_lock(&thread->mutex);
	signal = thread->signal;
	pthread_mutex_unlock(&thread->mutex);
	return signal;
}

void free_thread(struct vl_thread *thread) {
	pthread_mutex_lock(&threads_mutex);

	int thread_found = 0;
	for (int i = 0; i < VL_THREADS_MAX && thread_found == 0; i++) {
		pthread_mutex_lock(&threads[i]->mutex);
		if (threads[i] == thread) {
			thread_found = 1;
			if (threads[i]->state != VL_THREAD_STATE_STOPPED) {
				fprintf (stderr, "Attempted to free thread which was not STOPPED\n");
				exit (EXIT_FAILURE);
			}
			threads[i]->state = VL_THREAD_STATE_FREE;
		}
		pthread_mutex_unlock(&threads[i]->mutex);
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
		pthread_mutex_lock(&threads[i]->mutex);
		if (threads[i]->state == VL_THREAD_STATE_FREE) {
			threads[i]->state = VL_THREAD_STATE_STOPPED;
			ret = threads[i];
			thread_found = 1;
		}
		pthread_mutex_unlock(&threads[i]->mutex);
	}

	pthread_mutex_unlock(&threads_mutex);

	return ret;
}

struct watchdog_data {
	struct vl_thread *thread;
	void *arg;
};

void *thread_watchdog(void *arg) {
	struct watchdog_data wd = *((struct watchdog_data *) arg); // Remember to copy!!!!

	int prev_watchdog_counter = -1;

	uint64_t prevtime = time_get_64();
	while (1) {
		uint64_t nowtime = get_watchdog_time(wd.thread);

		// We or others might try to kill the thread
		if (thread_check_kill_signal(wd.thread)) {
			prevtime = time_get_64();
			while (thread_get_signal(wd.thread) != VL_THREAD_STATE_STOPPING) {
				nowtime = time_get_64();

				if (prevtime + VL_THREAD_WATCHDOG_KILLTIME_LIMIT * 1000 < nowtime) {
					fprintf (stderr, "Thread not responding to kill. Killing it harder.\n");
					pthread_cancel(wd.thread->thread);
					break;
				}

				usleep (10000); // 10 ms
			}
		}
		else if (prevtime + VL_THREAD_WATCHDOG_FREEZE_LIMIT * 1000 < nowtime) {
			fprintf (stderr, "Thread froze, attempting to kill\n");
			thread_set_signal(wd.thread, VL_THREAD_SIGNAL_KILL);

		}

		prevtime = nowtime;
		usleep (50000); // 50 ms
	}
}

struct vl_thread_start_data {
	void *(*start_routine) (void*);
	void *arg;
};

void thread_cleanup(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	free(start_data);
}

static void *start_routine_intermediate(void *arg) {
	struct vl_thread_start_data *start_data = arg;
	pthread_cleanup_push(thread_cleanup, start_data);
	start_data->start_routine(start_data->arg);
	pthread_cleanup_pop(1);
	return NULL;
}

void thread_set_state(struct vl_thread *thread, int state) {
	pthread_mutex_lock(&thread->mutex);

	if (state == VL_THREAD_STATE_STARTING) {
		fprintf (stderr, "Attempted to set STARTING state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_FREE) {
		fprintf (stderr, "Attempted to set FREE state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_STARTING) {
		fprintf (stderr, "Attempted to set RUNNING state of thread while it was not in STARTING state\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_STOPPING && thread->state != VL_THREAD_STATE_RUNNING) {
		fprintf (stderr, "Warning: Attempted to set STOPPING state of thread while it was not in RUNNING state\n");
		goto nosetting;
	}
	if (state == VL_THREAD_STATE_STOPPED && thread->state != VL_THREAD_STATE_STOPPING) {
		fprintf (stderr, "Attempted to set STOPPIED state of thread while it was not in STOPPING state\n");
		exit (EXIT_FAILURE);
	}

	thread->state = state;

	nosetting:
	pthread_mutex_unlock(&thread->mutex);
}

void thread_set_signal(struct vl_thread *thread, int signal) {
	pthread_mutex_lock(&thread->mutex);
	thread->signal = signal;
	pthread_mutex_unlock(&thread->mutex);
}

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

void threads_free() {
	pthread_mutex_lock(&threads_mutex);
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		pthread_mutex_lock(&threads[i]->mutex);
		if (threads[i]->state == VL_THREAD_STATE_RUNNING) {
			threads[i]->signal = VL_THREAD_SIGNAL_KILL;
		}
		pthread_mutex_unlock(&threads[i]->mutex);
	}
	for (int i = 0; i < VL_THREADS_MAX; i++) {
		pthread_mutex_lock(&threads[i]->mutex);
		while (threads[i]->state == VL_THREAD_STATE_RUNNING) {
			usleep(1000);
		}
		pthread_mutex_unlock(&threads[i]->mutex);
		pthread_mutex_destroy(&threads[i]->mutex);
		free(threads[i]);
		threads[i] = NULL;
	}
	pthread_mutex_unlock(&threads_mutex);
}

int thread_start (void *(*start_routine) (void*), void *data) {
	struct vl_thread *thread;
	struct vl_thread *watchdog_thread;

	thread = reserve_thread();
	if (thread == NULL) {
		fprintf (stderr, "Maximum number of threads reached, can't start another one\n");
		return 1;
	}

	watchdog_thread = reserve_thread();
	if (watchdog_thread == NULL) {
		fprintf (stderr, "Maximum number of threads reached while reserving watchdog thread, can't start another one\n");
		free_thread(thread);
		return 1;
	}

	thread->watchdog_time = 0;
	thread->signal = 0;
	pthread_mutex_init(&thread->mutex, NULL);
	pthread_mutex_lock(&thread->mutex);

	// The thread frees *start_data with a pthread cleanup function
	struct vl_thread_start_data *start_data  = malloc(sizeof(*start_data));
	start_data->arg = data;
	start_data->start_routine = start_routine;

	int err;
	err = pthread_create(&thread->thread, NULL, start_routine_intermediate, start_data);
	if (err != 0) {
		fprintf (stderr, "Error while starting thread: %s\n", strerror(err));
		err = 1;
		free(start_data);
		goto nowatchdog;
	}

	struct watchdog_data wd = {
			thread, data
	};

	err = pthread_create(&thread->thread, NULL, thread_watchdog, &wd);
	if (err != 0) {
		fprintf (stderr, "Error while starting thread: %s\n", strerror(err));
		err = 1;
		pthread_cancel(thread->thread);
	}

	nowatchdog:

	// Thread tries to set a signal first and therefore can't proceed untill we unlock
	pthread_mutex_unlock(&thread->mutex);

	return err;
}
