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

#include "../global.h"
#include "mqtt_packet.h"
#include "mqtt_common.h"
#include "mqtt_broker.h"

static void __rrr_mqtt_broker_destroy_listen_fds_elements (struct rrr_mqtt_listen_fd_collection *fds) {
	pthread_mutex_lock(&fds->lock);
	struct rrr_mqtt_listen_fd *cur = fds->first;
	while (cur) {
		struct rrr_mqtt_listen_fd *next = cur->next;

		printf ("mqtt broker close listen fd %i\n", cur->ip.fd);

		ip_network_cleanup(&cur->ip);
		free(cur);

		cur = next;
	}

	fds->first = NULL;
	pthread_mutex_unlock(&fds->lock);
}

static void __rrr_mqtt_broker_destroy_listen_fds (struct rrr_mqtt_listen_fd_collection *fds) {
	__rrr_mqtt_broker_destroy_listen_fds_elements(fds);
	pthread_mutex_destroy(&fds->lock);
}

static int __rrr_mqtt_broker_init_listen_fds (struct rrr_mqtt_listen_fd_collection *fds) {
	fds->first = NULL;
	return pthread_mutex_init(&fds->lock, 0);
}

static struct rrr_mqtt_listen_fd *__rrr_mqtt_broker_listen_fd_allocate_unlocked (
		struct rrr_mqtt_listen_fd_collection *fds
) {
	struct rrr_mqtt_listen_fd *ret = malloc (sizeof(*ret));
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_mqtt_broker_listen_fd_allocate_unlocked\n");
		goto out;
	}

	memset (ret, '\0', sizeof(*ret));
	ret->next = fds->first;
	fds->first = ret;

	out:
	return ret;
}

static void __rrr_mqtt_broker_listen_fd_destroy_unlocked (
		struct rrr_mqtt_listen_fd_collection *fds,
		struct rrr_mqtt_listen_fd *fd
) {
	int did_remove = 0;

	if (fds->first == fd) {
		fds->first = fd->next;
		did_remove = 1;
	}
	else {
		struct rrr_mqtt_listen_fd *cur = fds->first;
		while (cur) {
			if (cur->next == fd) {
				cur->next = cur->next->next;
				did_remove = 1;
				break;
			}
		}
	}

	if (did_remove == 0) {
		VL_BUG("FD not found in __rrr_mqtt_broker_listen_fd_destroy_unlocked\n");
	}

	ip_network_cleanup(&fd->ip);
	free(fd);
}

static int __rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_mqtt_listen_fd_collection *fds,
		int port,
		int max_connections
) {
	int ret = 0;

	pthread_mutex_lock(&fds->lock);

	struct rrr_mqtt_listen_fd *fd = __rrr_mqtt_broker_listen_fd_allocate_unlocked(fds);
	if (fd == NULL) {
		ret = 1;
		goto out_unlock;
	}

	fd->ip.port = port;

	if ((ret = ip_network_start_tcp_ipv4_and_ipv6(&fd->ip, max_connections)) != 0) {
		VL_MSG_ERR("Could not start network in __rrr_mqtt_broker_listen_ipv4_and_ipv6\n");
		goto out_destroy_fd;
	}

	goto out_unlock;

	out_destroy_fd:
	__rrr_mqtt_broker_listen_fd_destroy_unlocked(fds, fd);

	out_unlock:
	pthread_mutex_unlock(&fds->lock);

	return ret;
}

static int __rrr_mqtt_broker_listen_fd_accept_connections (
		struct rrr_mqtt_listen_fd *fd,
		const char *creator,
		int (*callback)(const struct ip_accept_data *accept_data, void *arg),
		void *callback_arg
) {
	struct ip_accept_data *accept_data = NULL;

	int ret = 0;

	do {
		if ((ret = ip_accept(&accept_data, &fd->ip, creator)) != 0) {
			VL_MSG_ERR("Error from ip_accept in __rrr_mqtt_broker_listen_fd_accept_connections\n");
			break;
		}

		if (accept_data != NULL) {
			ret = callback(accept_data, callback_arg);
			if (ret != 0) {
				VL_MSG_ERR("Error from callback function in __rrr_mqtt_broker_listen_fd_accept_connections\n");
				break;
			}
		}

		RRR_FREE_IF_NOT_NULL(accept_data);
	} while (accept_data != NULL);

	RRR_FREE_IF_NOT_NULL(accept_data);

	return ret;
}

static int __rrr_mqtt_broker_listen_fds_accept_connections (
		struct rrr_mqtt_listen_fd_collection *fds,
		const char *creator,
		int (*callback)(const struct ip_accept_data *accept_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock(&fds->lock);

	struct rrr_mqtt_listen_fd *cur = fds->first;
	while (cur) {
		/* Save the error flag but loop the rest of the FDs even if one FD fails */
		int ret_tmp = __rrr_mqtt_broker_listen_fd_accept_connections(cur, creator, callback, callback_arg);
		if (ret_tmp != 0) {
			VL_MSG_ERR("Error while accepting connections in __rrr_mqtt_broker_listen_fds_accept_connections\n");
			ret = 1;
		}
		cur = cur->next;
	}

	pthread_mutex_unlock(&fds->lock);

	return ret;
}

int rrr_mqtt_broker_listen_ipv4_and_ipv6 (
		struct rrr_mqtt_broker_data *broker,
		int port,
		int max_connections
) {
	return __rrr_mqtt_broker_listen_ipv4_and_ipv6(&broker->listen_fds, port, max_connections);
}

void rrr_mqtt_broker_stop_listening (struct rrr_mqtt_broker_data *broker) {
	__rrr_mqtt_broker_destroy_listen_fds_elements (&broker->listen_fds);
}

static int rrr_mqtt_p_handler_connect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_publish (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_puback (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrec (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrel (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubcomp (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_subscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_unsubscribe (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pingreq (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_disconnect (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_auth (RRR_MQTT_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;

}

static const struct rrr_mqtt_type_handler_properties handler_properties[] = {
	{NULL},
	{rrr_mqtt_p_handler_connect},
	{NULL},
	{rrr_mqtt_p_handler_publish},
	{rrr_mqtt_p_handler_puback},
	{rrr_mqtt_p_handler_pubrec},
	{rrr_mqtt_p_handler_pubrel},
	{rrr_mqtt_p_handler_pubcomp},
	{rrr_mqtt_p_handler_subscribe},
	{NULL},
	{rrr_mqtt_p_handler_unsubscribe},
	{NULL},
	{rrr_mqtt_p_handler_pingreq},
	{NULL},
	{rrr_mqtt_p_handler_disconnect},
	{rrr_mqtt_p_handler_auth}
};

void rrr_mqtt_broker_destroy (struct rrr_mqtt_broker_data *broker) {
	/* Caller should make sure that no more connections are accepted at this point */
	__rrr_mqtt_broker_destroy_listen_fds(&broker->listen_fds);
	rrr_mqtt_common_data_destroy(&broker->mqtt_data);
	free(broker);
}

int rrr_mqtt_broker_new (struct rrr_mqtt_broker_data **broker, const char *client_name) {
	int ret = 0;

	struct rrr_mqtt_broker_data *res = NULL;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_broker_new\n");
		ret = 1;
		goto out;
	}

	memset (res, '\0', sizeof(*res));

	if ((ret = rrr_mqtt_common_data_init (&res->mqtt_data, client_name, handler_properties)) != 0) {
		VL_MSG_ERR("Could not initialize mqtt data in rrr_mqtt_broker_new\n");
		goto out_free;
	}

	if ((ret = __rrr_mqtt_broker_init_listen_fds(&res->listen_fds)) != 0) {
		VL_MSG_ERR("Could not initialize listen FD collection in rrr_mqtt_broker_new\n");
		goto out_destroy_data;
	}

	goto out_success;

	out_destroy_data:
		rrr_mqtt_common_data_destroy(&res->mqtt_data);
	out_free:
		RRR_FREE_IF_NOT_NULL(res);
	out_success:
		*broker = res;
	out:
		return ret;
}

struct accept_connections_callback_data {
	struct rrr_mqtt_broker_data *data;
	int connection_count;
};

static int __rrr_mqtt_broker_accept_connections_callback (
		const struct ip_accept_data *accept_data,
		void *callback_arg
) {
	struct accept_connections_callback_data *callback_data = callback_arg;
	struct rrr_mqtt_broker_data *data = callback_data->data;

	int ret = 0;

	if ((ret = rrr_mqtt_common_data_register_connection(&data->mqtt_data, accept_data)) != 0) {
		VL_MSG_ERR("Could not register new connection in __rrr_mqtt_broker_accept_connections_callback\n");
	}
	else {
		callback_data->connection_count++;
	}

	return ret;
}

int rrr_mqtt_broker_accept_connections (struct rrr_mqtt_broker_data *data) {
	int ret = 0;

	struct accept_connections_callback_data callback_data = {
			data, 0
	};

	ret = __rrr_mqtt_broker_listen_fds_accept_connections (
			&data->listen_fds,
			data->mqtt_data.client_name,
			__rrr_mqtt_broker_accept_connections_callback,
			&callback_data
	);

	if (ret != 0) {
		VL_MSG_ERR("Error while acceptign connections in rrr_mqtt_broker_accept_connections\n");
	}

	if (callback_data.connection_count > 0) {
		printf ("rrr_mqtt_broker_accept_connections: accepted %i connections\n",
				callback_data.connection_count);
	}

	return ret;
}

int rrr_mqtt_broker_receive_data (struct rrr_mqtt_broker_data *data) {
	int ret = 0;

	return rrr_mqtt_common_read_and_parse (&data->mqtt_data);

	return ret;
}

int rrr_mqtt_broker_synchronized_tick (struct rrr_mqtt_broker_data *data) {
	int ret = 0;

	if ((ret = rrr_mqtt_broker_accept_connections(data)) != 0) {
		goto out;
	}

	if ((ret = rrr_mqtt_broker_receive_data(data)) != 0) {
		goto out;
	}

	out:
	return ret;
}
