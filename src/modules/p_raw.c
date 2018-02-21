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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "../modules.h"
#include "../measurement.h"
#include "p_raw.h"

struct raw_private_data {
	struct module_data *sender;
	struct module_data *receiver;

	pthread_mutex_t sender_lock;
	pthread_mutex_t receiver_lock;
};

int init_private_data(struct raw_private_data *private_data) {
	private_data->sender = NULL;
	private_data->receiver = NULL;

	int err;
	err = pthread_mutex_init(&private_data->sender_lock, NULL);
	if (err != 0) {
		fprintf (stderr, "Could not initialize raw sender lock: %s\n", strerror(err));
		return 1;
	}

	if ((err = pthread_mutex_init(&private_data->receiver_lock, NULL)) != 0) {
		fprintf (stderr, "Could not initialize raw receiver lock: %s\n", strerror(err));
		if ((err = pthread_mutex_destroy(&private_data->sender_lock)) != 0) {
			fprintf (stderr, "Also problems when cleaning up: %s", strerror(err));
		}
		return 1;
	}

	return 0;
}

int destroy_private_data(struct raw_private_data *private_data) {
	int err;

	for (int i = 0; i < 10 && (err = pthread_mutex_trylock(&private_data->receiver_lock)) != 0; i++) {
		usleep (50000);
	}
	if (err != 0) {
		fprintf (stderr, "Warning: Failed to lock receiver in processor on de-init: %s\n", strerror(err));
	}

	for (int i = 0; i < 10 && (err = pthread_mutex_trylock(&private_data->sender_lock)) != 0; i++) {
		usleep (50000);
	}
	if (err != 0) {
		fprintf (stderr, "Warning: Failed to lock sender in processor on de-init: %s\n", strerror(err));
	}

	if (private_data->receiver != NULL) {
		give_module(private_data->receiver);
		private_data->receiver = NULL;
	}

	if (private_data->sender != NULL) {
		give_module(private_data->sender);
		private_data->sender = NULL;
	}

	pthread_mutex_unlock(&private_data->receiver_lock);
	pthread_mutex_unlock(&private_data->sender_lock);

	if ((err = pthread_mutex_destroy(&private_data->receiver_lock)) != 0) {
		fprintf (stderr, "Warning: Error while destroying processor receiver lock: %s\n", strerror(err));
	}
	if ((err = pthread_mutex_destroy(&private_data->sender_lock)) != 0) {
		fprintf (stderr, "Warning: Error while destroying processor sender lock: %s\n", strerror(err));
	}

	return 0;
}

static int module_init(struct module_data *data) {
	printf ("Initialize raw module\n");

	if (data->state != VL_MODULE_STATE_NEW) {
		fprintf (stderr, "Warning: p_raw module init called when module state was not new\n");
	}


	struct raw_private_data *private_data = malloc(sizeof(*private_data));
	if (private_data == NULL) {
		fprintf (stderr, "Could not allocate memory for raw module private data\n");
		return 1;
	}
	if (init_private_data(private_data) != 0) {
		fprintf (stderr, "Error while initializing private data in p_raw\n");
		free (private_data);
		return 1;
	}
	data->private = (void*) private_data;
	return 0;
}

static int module_destroy(struct module_data *data) {
	printf ("Destroy raw module\n");

	if (data->state != VL_MODULE_STATE_INVALID) {
		fprintf (stderr, "Warning: p_raw module destroy called when module state was not invalid\n");
	}

	int err = destroy_private_data((struct raw_private_data *) data->private);

	free(data->private);

	return err;
}

static int set_sender(struct module_data *data, struct module_data *sender) {
	struct raw_private_data *private_data = (struct raw_private_data *) data->private;

	pthread_mutex_lock(&private_data->sender_lock);

	if (data->state != VL_MODULE_STATE_UP) {
		pthread_mutex_unlock(&private_data->sender_lock);
		return 1;
	}

	if (private_data->sender != NULL) {
		give_module (private_data->sender);
	}
	take_module (sender);

	private_data->sender = sender;

	pthread_mutex_unlock(&private_data->sender_lock);

	return 0;
}

static int set_receiver(struct module_data *data, struct module_data *receiver) {
	struct raw_private_data *private_data = (struct raw_private_data *) data->private;

	pthread_mutex_lock(&private_data->receiver_lock);

	if (data->state != VL_MODULE_STATE_UP) {
		pthread_mutex_unlock(&private_data->receiver_lock);
		return 1;
	}

	if (private_data->receiver != NULL) {
		give_module (private_data->receiver);
	}
	take_module (receiver);

	private_data->receiver = receiver;

	pthread_mutex_unlock(&private_data->receiver_lock);

	return 0;
}

static int module_do_work(struct module_data *data) {
	return 0;
}

static struct module_operations module_operations = {
		module_init,
		module_destroy,
		module_do_work,
		NULL,
		NULL,
		set_sender,
		set_receiver,
};

static struct module_data module_data = {
		"raw",
		VL_MODULE_TYPE_PROCESSOR,
		VL_MODULE_STATE_NEW,
		NULL,
		&module_operations,
		NULL
};

struct module_data *module_get_data() {
		return &module_data;
};

__attribute__((constructor)) void load(void) {
	module_data.operations = &module_operations;

}

