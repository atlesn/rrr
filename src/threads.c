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

#include "threads.h"

static struct vl_thread threads[VL_THREADS_MAX];
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;

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

static struct vl_thread *reserve_thread() {
	struct vl_thread *ret = NULL;

	pthread_mutex_lock(&threads_mutex);

	for (int i = 0; i < VL_THREADS_MAX; i++) {
		pthread_mutex_lock(&(threads[i].mutex));
		if (threads[i].state == VL_THREAD_STATE_FREE) {
			threads[i].state = VL_THREAD_STATE_STARTING;
			ret = &threads[i];
			break;
		}
		pthread_mutex_unlock(&threads[i].mutex);
	}

	pthread_mutex_unlock(&threads_mutex);

	return ret;
}



int thread_wait_signal(struct vl_thread *thread) {
	int signal = 0;
	while (thread_get_signal(thread) != 0) {
		usleep (250000);
	}
	return signal;
}

void thread_watchdog(void *arg) {
	struct vl_thread *thread = (struct vl_thread *) arg;

	int prev_watchdog_counter = -1;

	while (thread_get_signal(thread) != VL_THREAD_SIGNAL_KILL) {

	}
}

int thread_start (void *(*start_routine) (void*), void *arg) {
	struct vl_thread *thread;

	thread = reserve_thread();
	if (thread == NULL) {
		fprintf (stderr, "Maximum number of threads reached, can't start another one\n");
		return 1;
	}

	thread->watchdog_counter = 0;
	thread->signal = 0;
	pthread_mutex_init (&thread->mutex, NULL);
	pthread_mutex_lock(&thread->mutex);

	int err = pthread_create(&thread->thread, NULL, start_routine, arg);

	if (err != 0) {
		fprintf (stderr, "Error while starting thread: %s\n", strerror(err));
		err = 1;
	}

	pthread_mutex_unlock(&thread->mutex);

	return err;
}
