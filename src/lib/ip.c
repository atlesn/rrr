/*

Read Route Record

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

#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <src/lib/ip.h>
#include <fcntl.h>

#ifdef VL_WITH_OPENSSL
#include "module_crypt.h"
#endif

#include "ip.h"
#include "../global.h"
#include "messages.h"
#include "vl_time.h"

int ip_stats_init (struct ip_stats *stats, unsigned int period, const char *type, const char *name) {
	stats->period = period;
	stats->name = name;
	stats->type = type;
	return (pthread_mutex_init(&stats->lock, NULL) != 0);
}

int ip_stats_init_twoway (struct ip_stats_twoway *stats, unsigned int period, const char *name) {
	memset(stats, '\0', sizeof(*stats));
	int ret = 0;
	ret |= ip_stats_init(&stats->send, period, "send", name);
	ret |= ip_stats_init(&stats->receive, period, "receive", name);
	return ret;
}

int ip_stats_update(struct ip_stats *stats, unsigned long int packets, unsigned long int bytes) {
	int ret = VL_IP_STATS_UPDATE_OK;

	if (pthread_mutex_lock(&stats->lock) != 0) {
		return VL_IP_STATS_UPDATE_ERR;
	}

	stats->packets += packets;
	stats->bytes += bytes;

	if (stats->time_from == 0) {
		stats->time_from = time_get_64();
	}
	else if (stats->time_from + stats->period * 1000000 < time_get_64()) {
		ret = VL_IP_STATS_UPDATE_READY;
	}

	pthread_mutex_unlock(&stats->lock);
	return ret;
}

int ip_stats_print_reset(struct ip_stats *stats, int do_reset) {
	int ret = VL_IP_STATS_UPDATE_OK;

	if (pthread_mutex_lock(&stats->lock) != 0) {
		return VL_IP_STATS_UPDATE_ERR;
	}

	VL_DEBUG_MSG_2("IP stats for %s %s: %lu packets/s %lu bytes/s, period is %u\n",
			stats->name, stats->type, stats->packets/stats->period, stats->bytes/stats->period, stats->period);

	if (do_reset) {
		stats->time_from = 0;
		stats->packets = 0;
		stats->bytes = 0;
	}

	pthread_mutex_unlock(&stats->lock);
	return ret;
}

/* Receive raw packets */
int ip_receive_packets (
	int fd,
	int (*callback)(struct ip_buffer_entry *entry, void *arg),
	void *arg,
	struct ip_stats *stats
) {
	struct sockaddr src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	struct pollfd fds;
	fds.fd = fd;
	fds.events = POLLIN;

	char buffer[VL_IP_RECEIVE_MAX_SIZE];

	while (1) {
		int res;

		VL_DEBUG_MSG_5 ("ip polling data\n");
		res = poll(&fds, 1, 10);
		if (res == -1) {
			VL_MSG_ERR ("Error from poll when reading data from network: %s\n", strerror(errno));
			return 1;
		}
		else if (!(fds.revents & POLLIN)) {
			VL_DEBUG_MSG_5 ("ip no data available\n");
			break;
		}

		memset(buffer, '\0', VL_IP_RECEIVE_MAX_SIZE);

		VL_DEBUG_MSG_3 ("ip receiving data\n");
		ssize_t count = recvfrom(fd, buffer, VL_IP_RECEIVE_MAX_SIZE, 0, &src_addr, &src_addr_len);

		if (count == -1) {
			VL_MSG_ERR ("Error from recvfrom when reading d <sys/socket.h>ata from network: %s\n", strerror(errno));
			return 1;
		}

		struct ip_buffer_entry *entry = malloc(sizeof(*entry));
		memset(entry, '\0', sizeof(*entry));

		entry->addr = src_addr;
		entry->addr_len = src_addr_len;
		entry->data_length = count;

		VL_ASSERT(sizeof(entry->data.data)==sizeof(buffer),sizes_of_buffers_equal)
		memcpy (entry->data.data, buffer, count);

		if (VL_DEBUGLEVEL_6) {
			for (int i = 0; i < MSG_DATA_MAX_LENGTH; i++) {
				VL_DEBUG_MSG ("%02x-", entry->data.data[i]);
				if ((i + 1) % 32 == 0) {
					VL_DEBUG_MSG ("\n");
				}
			}
			VL_DEBUG_MSG ("\n");
		}

		res = callback(entry, arg);
		if (res == VL_IP_RECEIVE_STOP) {
			break;
		}
		else if (res == VL_IP_RECEIVE_ERR) {
			return 1;
		}

		if (stats != NULL) {
			res = ip_stats_update(stats, 1, VL_IP_RECEIVE_MAX_SIZE);
			if (res == VL_IP_STATS_UPDATE_ERR) {
				VL_MSG_ERR("ip: Error returned from stats update function\n");
				return 1;
			}
			if (res == VL_IP_STATS_UPDATE_READY) {
				if (ip_stats_print_reset(stats, 1) != VL_IP_STATS_UPDATE_OK) {
					VL_MSG_ERR("ip: Error returned from stats print function\n");
					return 1;
				}
			}
		}
	}

	return 0;
}

struct ip_receive_messages_data {
	int (*callback)(struct ip_buffer_entry *entry, void *arg);
	void *arg;
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data;
#endif
};

int ip_receive_messages_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ip_receive_messages_data *data = arg;

#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data = data->crypt_data;
#endif
	const ssize_t count = entry->data_length;

	if (count < 10) {
		VL_MSG_ERR ("Received short message/packet from network\n");
		return 0;
	}

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL) {
		unsigned int input_length = count;

		VL_DEBUG_MSG_3("ip decrypting message of length %u \n", input_length);
		if (module_decrypt_message(
				crypt_data,
				(char*) entry->data.data,
				&input_length,
				sizeof(entry->data.data)
		) != 0) {
			VL_MSG_ERR("Error returned from module decrypt function\n");
			free (entry);
			return 1;
		}

		entry->data_length = input_length;
	}
#endif

/*	if (parse_message(start, input_length, &entry->data.message) != 0) {
		VL_MSG_ERR ("Received invalid message\n");
		free (entry);
		return 0;
	}*/

	if (message_checksum_check(&entry->data.message) != 0) {
		VL_MSG_ERR ("Message checksum was invalid\n");
		free (entry);
		return 0;
	}

	if (message_convert_endianess(&entry->data.message) != 0) {
		VL_MSG_ERR ("Could not convert message endianess\n");
		free (entry);
		return 0;
	}

	return data->callback(entry, data->arg);
}

/* Receive packets and parse vl_message struct or fail */
int ip_receive_messages (
	int fd,
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data,
#endif
	int (*callback)(struct ip_buffer_entry *entry, void *arg),
	void *arg,
	struct ip_stats *stats
) {
	struct ip_receive_messages_data data;

	data.callback = callback;
	data.arg = arg;
#ifdef VL_WITH_OPENSSL
	data.crypt_data = crypt_data;
#endif

	return ip_receive_packets (
			fd,
			ip_receive_messages_callback,
			&data,
			stats
	);
}

int ip_send_message (
	const struct vl_message *input_message,
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data,
#endif
	struct ip_send_packet_info *info,
	struct ip_stats *stats
) {
	char buf[VL_IP_RECEIVE_MAX_SIZE];
	struct vl_message *final_message = (struct vl_message *) buf;

	VL_ASSERT(sizeof(buf) >= sizeof(*input_message),ip_send_buf_can_hold_vl_message);

	memcpy(final_message, input_message, sizeof(*final_message));

	message_prepare_for_network(final_message);

	VL_DEBUG_MSG_3 ("ip sends packet timestamp from %" PRIu64 " data '%s'\n", input_message->timestamp_from, buf + 1);

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL && module_encrypt_message (
			crypt_data,
			buf + 1, strlen(buf + 1), // Remember that buf starts with zero
			sizeof(buf)
	) != 0) {
		return 1;
	}
#endif

	VL_DEBUG_MSG_3("ip: Final message to send ready\n");

	if (sendto(info->fd, buf, sizeof(*final_message), 0, info->res->ai_addr,info->res->ai_addrlen) == -1) {
		VL_MSG_ERR("ip: Error while sending packet to server: %s\n", strerror(errno));
		return 1;
	}

	if (stats != NULL) {
		int res = ip_stats_update(stats, 1, sizeof(*final_message));
		if (res == VL_IP_STATS_UPDATE_ERR) {
			VL_MSG_ERR("ip: Error returned from stats update function\n");
			return 1;
		}
		if (res == VL_IP_STATS_UPDATE_READY) {
			if (ip_stats_print_reset(stats, 1) != VL_IP_STATS_UPDATE_OK) {
				VL_MSG_ERR("ip: Error returned from stats print function\n");
				return 1;
			}
		}
	}

	return 0;
}

void ip_network_cleanup (void *arg) {
	struct ip_data *data = arg;
	if (data->fd != 0) {
		close(data->fd);
		data->fd = 0;
	}
}

int ip_network_start (struct ip_data *data) {
	int fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd == -1) {
		VL_MSG_ERR ("Could not create socket: %s", strerror(errno));
		goto out_error;
	}

	if (data->port < 1 || data->port > 65535) {
		VL_MSG_ERR ("BUG: ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_in si;
	memset(&si, '\0', sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = htons(data->port);
	si.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind (fd, (struct sockaddr *) &si, sizeof(si)) == -1) {
		VL_MSG_ERR ("Could not bind to port %d: %s", data->port, strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;

	return 0;

	out_close_socket:
	close(fd);

	out_error:
	return 1;
}
