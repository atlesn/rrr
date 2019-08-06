/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "buffer.h"
#include "vl_time.h"
#include "../global.h"
#include "mqtt_common.h"
#include "mqtt_connection.h"
#include "mqtt_packet.h"

int rrr_mqtt_connection_send_disconnect_and_close (struct rrr_mqtt_connection *connection) {
	pthread_mutex_lock(&connection->lock);
	if (connection->state == RRR_MQTT_CONNECTION_STATE_CLOSED) {
		VL_BUG("State of connection was already CLOSED in __rrr_mqtt_connection_destroy\n");
	}
	if (connection->fd == 0) {
		VL_BUG("FD was zero in __rrr_mqtt_connection_destroy\n");
	}

	// TODO : Send close packet

	close(connection->fd);
	connection->fd = 0;
	connection->state = RRR_MQTT_CONNECTION_STATE_CLOSED;

	pthread_mutex_unlock(&connection->lock);

	return 0;
}

static void __rrr_mqtt_connection_destroy (struct rrr_mqtt_connection *connection) {
	if (connection == NULL) {
		VL_BUG("NULL pointer in __rrr_mqtt_connection_destroy\n");
	}

	pthread_mutex_lock(&connection->lock);
	if (connection->state != RRR_MQTT_CONNECTION_STATE_CLOSED) {
		if (connection->fd == 0) {
			VL_BUG("Connection was not closed but FD was zero in __rrr_mqtt_connection_destroy\n");
		}
		pthread_mutex_unlock(&connection->lock);
		if (rrr_mqtt_connection_send_disconnect_and_close(connection) != 0) {
			VL_MSG_ERR("Warning: Error while sending disconnect packet while destroying connection\n");
		}
	}
	else {
		pthread_mutex_unlock(&connection->lock);
	}

	fifo_buffer_invalidate(&connection->receive_queue.buffer);
	fifo_buffer_invalidate(&connection->send_queue.buffer);
	fifo_buffer_invalidate(&connection->wait_for_ack_queue.buffer);

	pthread_mutex_destroy (&connection->lock);

	free(connection);
}

static int __rrr_mqtt_connection_new (struct rrr_mqtt_connection **connection, int fd, int type) {
	int ret = 0;

	*connection = NULL;
	struct rrr_mqtt_connection *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_connection_new\n");
		ret = 1;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = pthread_mutex_init (&res->lock, 0)) != 0) {
		VL_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_new\n");
		goto out;
	}

	ret |= fifo_buffer_init(&res->receive_queue.buffer);
	ret |= fifo_buffer_init(&res->send_queue.buffer);
	ret |= fifo_buffer_init(&res->wait_for_ack_queue.buffer);

	if (ret != 0) {
		VL_MSG_ERR("Could not initialize buffers in __rrr_mqtt_connection_new\n");
		goto out;
	}

	res->fd = fd;
	res->type = type;
	res->connect_time = res->last_seen_time = time_get_64();

	out:
	if (ret == 0) {
		*connection = res;
	}
	else if (res != NULL) {
		__rrr_mqtt_connection_destroy(res);
	}

	return ret;
}

void rrr_mqtt_connection_collection_destroy (struct rrr_mqtt_connection_collection *connections) {
	if (connections == NULL) {
		return;
	}

	struct rrr_mqtt_connection *cur = connections->first;
	while (cur) {
		struct rrr_mqtt_connection *next = cur->next;
		__rrr_mqtt_connection_destroy (cur);
		cur = next;
	}

	connections->first = NULL;
	connections->invalid = 1;

	pthread_mutex_destroy (&connections->lock);
}

int rrr_mqtt_connection_collection_init (struct rrr_mqtt_connection_collection *connections) {
	int ret = 0;

	memset (connections, '\0', sizeof(*connections));

	connections->invalid = 1;

	if ((ret = pthread_mutex_init (&connections->lock, 0)) != 0) {
		VL_MSG_ERR("Could not initialize mutex in __rrr_mqtt_connection_collection_new\n");
		goto out;
	}

	out:
	if (ret != 0) {
		rrr_mqtt_connection_collection_destroy(connections);
	}
	else {
		connections->invalid = 0;
	}

	return ret;
}

int rrr_mqtt_connection_collection_new_connection (
		struct rrr_mqtt_connection **connection,
		struct rrr_mqtt_connection_collection *connections,
		int fd,
		int type
) {
	int ret = 0;
	struct rrr_mqtt_connection *res = NULL;

	*connection = NULL;

	if (connections->invalid == 1) {
		VL_BUG("rrr_mqtt_connection_collection_new_connection called with invalid set to 1\n");
	}

	if (fd < 1) {
		VL_BUG("FD was < 1 in rrr_mqtt_connection_collection_new_connection\n");
	}

	if ((ret = __rrr_mqtt_connection_new(&res, fd, type)) != 0) {
		VL_MSG_ERR("Could not create new connection in rrr_mqtt_connection_collection_new_connection\n");
		goto out_nolock;
	}

	pthread_mutex_lock(&connections->lock);
	res->next = connections->first;
	connections->first = res;
	pthread_mutex_unlock(&connections->lock);

	*connection = res;

	out_nolock:
	return ret;
}
