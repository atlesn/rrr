/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <event2/event.h>
#include <event2/thread.h>

#include "log.h"
#include "event.h"
#include "threads.h"
#include "rrr_strerror.h"
#include "rrr_config.h"
#include "rrr_path_max.h"
#include "string_builder.h"
#include "socket/rrr_socket.h"
#include "util/gnu.h"
#include "util/posix.h"
#include "util/rrr_time.h"

#define QUEUE_MAX 0x100
#define INC(pos) \
	(pos) = (pos + 1) % (QUEUE_MAX)
#define QUEUE_RPOS_INC() \
	INC(queue->queue_rpos)
#define QUEUE_WPOS_INC() \
	INC(queue->queue_wpos)

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int rrr_event_libevent_initialized = 0;

struct rrr_event {
	uint8_t function;
	uint8_t flags;
	uint16_t amount;
};

struct rrr_event_queue {
	unsigned int queue_rpos;
	unsigned int queue_wpos;
	pthread_mutex_t lock;
	struct event_base *event_base;
	struct rrr_event queue[QUEUE_MAX];
	int (*functions[0x100])(RRR_EVENT_FUNCTION_ARGS);
	int signal_fd_listen;
	int signal_fd_write;
	int signal_fd_read;
};

void rrr_event_queue_destroy (
		struct rrr_event_queue *queue
) {
	if (queue->signal_fd_read != 0) {
		rrr_socket_close(queue->signal_fd_read);
	}
	if (queue->signal_fd_write != 0) {
		rrr_socket_close(queue->signal_fd_write);
	}
	if (queue->signal_fd_listen != 0) {
		rrr_socket_close(queue->signal_fd_listen);
	}
	pthread_mutex_destroy(&queue->lock);
	event_base_free(queue->event_base);
	munmap(queue, sizeof(*queue));
}

static int __rrr_event_queue_new_connect_callback (
		const char *filename,
		void *arg
) {
	struct rrr_event_queue *queue = arg;
	return rrr_socket_unix_connect (
			&queue->signal_fd_write,
			"event",
			filename,
			1
	);
}

int rrr_event_queue_new (
		struct rrr_event_queue **target
) {
	int ret = 0;

	// TODO : use_pthreads might not be needed as the libevent
	//        structures are only accessed by one thread.
	pthread_mutex_lock(&init_lock);
	if (rrr_event_libevent_initialized++ == 0) {
		ret = evthread_use_pthreads();
	}
	pthread_mutex_unlock(&init_lock);

	if (ret != 0) {
		RRR_MSG_0("evthread_use_pthreads() failed in rrr_event_queue_new\n");
		ret = 1;
		goto out;
	}

	*target = NULL;

	struct rrr_event_queue *queue = NULL;

	if ((queue = rrr_posix_mmap(sizeof(*queue))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in rrr_event_queue_new\n");
		ret = 1;
		goto out;
	}

	if ((rrr_posix_mutex_init(&queue->lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Could not initialize mutex B in rrr_event_queue_init\n");
		ret = 1;
		goto out_munmap;
	}

	if ((queue->event_base = event_base_new()) == NULL) {
		RRR_MSG_0("Could not create event base in rrr_event_queue_init\n");
		ret = 1;
		goto out_destroy_lock;
	}

	char buf[PATH_MAX];
	snprintf(buf, PATH_MAX, "%s%s", rrr_config_global.run_directory, "/event.sock-XXXXXX");

	if ((ret = rrr_socket_unix_create_bind_and_listen (
			&queue->signal_fd_listen,
			"event",
			buf,
			1,
			1,
			1,
			0
	)) != 0) {
		RRR_MSG_0("Failed to create listen socket for event queue, path was '%s'\n", buf);
		ret = 1;
		goto out_destroy_event_base;
	}

	if ((ret = rrr_socket_with_filename_do (
			queue->signal_fd_listen,
			__rrr_event_queue_new_connect_callback,
			queue
	)) != 0) {
		RRR_MSG_0("Failed to connect to listening socket in rrr_event_queue_init\n");
		ret = 1;
		goto out_close_listen_fd;
	}

	struct sockaddr_storage addr_dummy;
	socklen_t addr_len_dummy = sizeof(addr_dummy);

	if ((queue->signal_fd_read = rrr_socket_accept (
			queue->signal_fd_listen,
			(struct sockaddr *) &addr_dummy,
			&addr_len_dummy,
			"event"
	)) <= 0) {
		RRR_MSG_0("Failed to accept on listening socket in rrr_event_queue_init\n");
		ret = 1;
		goto out_close_connect_fd;
	}

	RRR_DBG_9_PRINTF("EQ INIT FD %i thread ID %llu\n",
		queue->signal_fd_listen, (long long unsigned) rrr_gettid());

	*target = queue;

	goto out;
	out_close_connect_fd:
		rrr_socket_close(queue->signal_fd_write);
	out_close_listen_fd:
		rrr_socket_close(queue->signal_fd_listen);
	out_destroy_event_base:
		event_base_free(queue->event_base);
	out_destroy_lock:
		pthread_mutex_destroy(&queue->lock);
	out_munmap:
		munmap(queue, sizeof(*queue));
	out:
		return ret;
}

struct event_base *rrr_event_queue_base_get (
		struct rrr_event_queue *queue
) {
	return queue->event_base;
}

void rrr_event_queue_fds_get (
		int *fd_listen,
		int *fd_read,
		int *fd_write,
		struct rrr_event_queue *queue
) {
	*fd_listen = queue->signal_fd_listen;
	*fd_read = queue->signal_fd_read;
	*fd_write = queue->signal_fd_write;
}

void rrr_event_function_set (
		struct rrr_event_queue *handle,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
) {
	handle->functions[code] = function;
}
				
static void __rrr_event_write_signal (
		struct rrr_event_queue *queue
) {
	int max = 100;
	while (--max) {
		if (write(queue->signal_fd_write, "", 1) == 1) {
			return;
		}
		sched_yield();
	}
	if (errno != EWOULDBLOCK) {
		RRR_MSG_0_PRINTF("Warning: write() to signal fd %i failed in __rrr_event_write_signal: %s\n",
			queue->signal_fd_write, rrr_strerror(errno));
	}
}

static void __rrr_event_destroy_void_dbl_ptr (
		void *arg
) {
	struct event **event = arg;
	if (*event != NULL) {
		event_free(*event);
	}
}

struct rrr_event_callback_data {
	struct rrr_event_queue *queue;
	int (*callback_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS);
	void *callback_arg;
	int callback_periodic_ret;
};

static void __rrr_event_dispatch (
		evutil_socket_t fd,
		short event_flags,
		void *arg
) {
	struct rrr_event_callback_data *callback_data = arg;
	struct rrr_event_queue *queue = callback_data->queue;

	(void)(fd);
	(void)(event_flags);

	int ret_tmp = 0;

	char dummy_buf[128];
	// Read only 1 byte
	read(fd, dummy_buf, 1);

	uint8_t function = 0;
	uint8_t flags = 0;
	uint16_t amount = 0;

	{
		pthread_mutex_lock(&queue->lock);

		struct rrr_event event  = queue->queue[queue->queue_rpos];

		if (event.amount > 0) {
			memset (&queue->queue[queue->queue_rpos], '\0', sizeof(queue->queue[0]));
			QUEUE_RPOS_INC();
			function = event.function;
			flags = event.flags;
			amount = event.amount;
		}

		pthread_mutex_unlock(&queue->lock);
	}

	if (amount == 0) {
		// Read more bytes
		read(fd, dummy_buf, sizeof(dummy_buf));
		goto out;
	}

	if (callback_data->queue->functions[function] == NULL) {
		RRR_BUG("BUG: Function %u was not registered in __rrr_event_dispatch\n", function);
	}

	RRR_DBG_9_PRINTF("EQ DISP FD %i function %u flags %u amount %u\n",
		queue->signal_fd_listen, function, flags, amount);

	while (amount > 0) {
		uint16_t amount_new = amount;
		if ((ret_tmp = callback_data->queue->functions[function](&amount_new, flags, callback_data->callback_arg)) != 0) {
			goto out;
		}
		if (amount_new > amount) {
			RRR_BUG("BUG: Amount increased after event function, possible underflow in __rrr_event_dispatch\n");
		}
		amount = amount_new;
		RRR_DBG_9_PRINTF("EQ DISP FD %i => amount %u (remaining)\n",
			queue->signal_fd_listen, amount);
	}


	out:
	if (ret_tmp != 0) {
		event_base_loopbreak(callback_data->queue->event_base);
	}
}

static void __rrr_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_event_callback_data *callback_data = arg;

	(void)(fd);
	(void)(flags);

	if ( callback_data->callback_periodic != NULL &&
	    (callback_data->callback_periodic_ret = callback_data->callback_periodic(callback_data->callback_arg)) != 0
	) {
		event_base_loopbreak(callback_data->queue->event_base);
	}
}

int rrr_event_dispatch (
		struct rrr_event_queue *queue,
		unsigned int periodic_interval_us,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_event_callback_data callback_data = {
		queue,
		function_periodic,
		callback_arg,
		0
	};

	struct event *signal_event = NULL;
	struct event *periodic_event = NULL;

	pthread_cleanup_push(__rrr_event_destroy_void_dbl_ptr, &signal_event);
	pthread_cleanup_push(__rrr_event_destroy_void_dbl_ptr, &periodic_event);

	if ((signal_event = event_new (
			queue->event_base,
			queue->signal_fd_read,
			EV_READ|EV_PERSIST,
			__rrr_event_dispatch,
			&callback_data
	)) == NULL) {
		RRR_MSG_0("Failed to create listening event in rrr_event_dispatch\n");
		ret = 1;
		goto out;
	}

	struct timeval tv_interval = {0};

	tv_interval.tv_usec = periodic_interval_us % 1000000;
	tv_interval.tv_sec = (periodic_interval_us - tv_interval.tv_usec) / 1000000;

	if ((periodic_event = event_new (
			queue->event_base,
			0,
			EV_TIMEOUT|EV_PERSIST,
			__rrr_event_periodic,
			&callback_data
	)) == NULL) {
		RRR_MSG_0("Failed to create listening event in rrr_event_dispatch\n");
		ret = 1;
		goto out;
	}

	if (event_add(periodic_event, &tv_interval) || event_add(signal_event, NULL)) {
		RRR_MSG_0("Failed to add events in rrr_event_dispatch\n");
		event_del(periodic_event);
		event_del(signal_event);
		ret = 1;
		goto out;
	}

	if ((ret = event_base_dispatch(queue->event_base)) != 0) {
		RRR_MSG_0("Error from event_base_dispatch in rrr_event_dispatch: %i\n", ret);
		ret = 1;
		goto out;
	}

	if (callback_data.callback_periodic_ret != 0) {
		ret = callback_data.callback_periodic_ret & ~(RRR_EVENT_EXIT);
	}
	else if (event_base_got_break(queue->event_base)) {
		ret = 1;
		goto out;
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static void __rrr_event_pass_add_maximum_amount (
		uint16_t *amount,
		struct rrr_event *event
) {
	const uint16_t available = 0xffff - event->amount;
	if (*amount > available) {
		event->amount += available;
		*amount -= available;
	} else {
		event->amount += *amount;
		*amount = 0;
	}
}

static void __rrr_event_queue_dump_unlocked (
		const struct rrr_event_queue *queue
) {
	struct rrr_string_builder string_builder = {0};

	rrr_string_builder_append_format(&string_builder, "EQ DUMP FD %i rpos %u wpos %u:", queue->signal_fd_listen, queue->queue_rpos, queue->queue_wpos);

	for (unsigned long int i = 0; i < QUEUE_MAX; i++) {
		struct rrr_event event = queue->queue[i];
		if (event.amount || event.function || event.flags) {
			rrr_string_builder_append_format(&string_builder, " %lu: %02x-%02x-%02x",
				i, event.function, event.flags, event.amount);
		}
	}

	rrr_string_builder_append(&string_builder, "\n");

	RRR_DBG_9_PRINTF("%s", rrr_string_builder_buf(&string_builder));

	rrr_string_builder_clear(&string_builder);
}

void rrr_event_pass (
		struct rrr_event_queue *queue,
		uint8_t function,
		uint8_t flags,
		uint16_t amount
) {
	pthread_mutex_lock(&queue->lock);

	RRR_DBG_9_PRINTF("EQ PASS FD %i rpos %u wpos %u function %u flags %u amount %u\n",
		queue->signal_fd_listen, queue->queue_rpos, queue->queue_wpos, function, flags, amount);

	for (;;) {
		// Sneak peak at previous write, maybe it's the same function
		uint8_t wpos = queue->queue_wpos;

		const uint8_t wpos_prev = wpos - 1;	
		struct rrr_event *event = &queue->queue[wpos_prev];
		if (event->function == function && event->flags == flags && event->amount > 0 && event->amount < 0xffff) {
			__rrr_event_pass_add_maximum_amount(&amount, event);
		}

		if (amount == 0) {
			goto out;
		}

		// If wpos is full, go backwards in the ring to find already
		// stored events with the same function and flags
		do {
			event = &queue->queue[wpos];

			if (event->amount == 0) {
				// Write to free location
				event->function = function;
				event->flags = flags;
				event->amount = amount;
				QUEUE_WPOS_INC();
				amount = 0;
			}
			else if (wpos == queue->queue_rpos) {
				// Don't add to oldest entry
			}
			else if (event->function == function && event->flags == flags && event->amount < 0xffff) {
				__rrr_event_pass_add_maximum_amount(&amount, event);
			}

			if (amount == 0) {
				goto out;
			}
		} while(--wpos != queue->queue_wpos);

		// Event queue was full :-(
		pthread_mutex_unlock(&queue->lock);
		rrr_posix_usleep(5000); // 5 ms
		pthread_mutex_lock(&queue->lock);
	}

	out:
	if (1||RRR_DEBUGLEVEL_9) {
		__rrr_event_queue_dump_unlocked (queue);
	}
	pthread_mutex_unlock(&queue->lock);
	__rrr_event_write_signal (queue);
}
