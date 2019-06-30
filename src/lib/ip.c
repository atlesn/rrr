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

#ifdef VL_WITH_OPENSSL
#include "module_crypt.h"
#endif

#include "ip.h"
#include "../global.h"
#include "messages.h"
#include "vl_time.h"

void ip_stats_init (struct ip_stats *stats, unsigned int period, const char *type, const char *name) {
	stats->period = period;
	stats->name = name;
	stats->type = type;
	pthread_mutex_init(&stats->lock, NULL);
}

void ip_stats_init_twoway (struct ip_stats_twoway *stats, unsigned int period, const char *name) {
	memset(stats, '\0', sizeof(*stats));
	ip_stats_init(&stats->send, period, "send", name);
	ip_stats_init(&stats->receive, period, "receive", name);
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
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data,
#endif
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

		if (VL_DEBUGLEVEL_3) {
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
			res = ip_stats_update(stats, 1, MSG_STRING_MAX_LENGTH);
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

	unsigned char *start = entry->data.data;
	if (*start != '\0') {
		VL_MSG_ERR ("Datagram received from network did not start with zero\n");
		return 0;
	}

	start++;
	unsigned int input_length = count - 1;

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL) {
		unsigned char *end = memchr(start, '\0', MSG_STRING_MAX_LENGTH - 1);
		if (*end != '\0') {
			VL_MSG_ERR("Could not find terminating zero byte in encrypted message\n");
			free (entry);
			return 1;
		}

		input_length = end - start;

		VL_DEBUG_MSG_3("ip decrypting message %s\n", start);
		if (module_decrypt_message(crypt_data, start, &input_length, MSG_STRING_MAX_LENGTH - 1) != 0) {
			VL_MSG_ERR("Error returned from module decrypt function\n");
			free (entry);
			return 1;
		}
	}
#endif

	if (parse_message(start, input_length, &entry->data.message) != 0) {
		VL_MSG_ERR ("Received invalid message\n");
		free (entry);
		return 0;
	}

	if (message_checksum_check(&entry->data.message) != 0) {
		VL_MSG_ERR ("Message checksum was invalid for '%s'\n", start);
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
#ifdef VL_WITH_OPENSSL
			crypt_data,
#endif
			ip_receive_messages_callback,
			&data,
			stats
	);
}

int ip_send_message (
	struct vl_message* message,
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data,
#endif
	struct ip_send_packet_info *info,
	struct ip_stats *stats
) {
	char buf[MSG_STRING_MAX_LENGTH];
	memset(buf, '\0', MSG_STRING_MAX_LENGTH);
	buf[0] = '\0'; // Network messages must start and end with zero
	if (message_prepare_for_network(message, buf, MSG_STRING_MAX_LENGTH) != 0) {
		//return FIFO_SEARCH_KEEP;
	}

	VL_DEBUG_MSG_3 ("ip sends packet timestamp from %" PRIu64 " data '%s'\n", message->timestamp_from, buf + 1);

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL && module_encrypt_message (
			crypt_data,
			buf + 1, strlen(buf + 1), // Remember that buf starts with zero
			sizeof(buf)
	) != 0) {
		return 1;
	}
#endif

	if (buf[0] != 0) {
		VL_MSG_ERR("ip: Start of send buffer was not zero\n");
		exit(EXIT_FAILURE);
	}

	VL_DEBUG_MSG_3("ip: Final message to send: %s\n", buf + 1);

	if (sendto(info->fd, buf, MSG_STRING_MAX_LENGTH, 0, info->res->ai_addr,info->res->ai_addrlen) == -1) {
		VL_MSG_ERR("ip: Error while sending packet to server\n");
		return 1;
	}

	if (stats != NULL) {
		int res = ip_stats_update(stats, 1, MSG_STRING_MAX_LENGTH);
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
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1) {
		VL_MSG_ERR ("Could not create socket: %s", strerror(errno));
		goto out_error;
	}

	if (data->port < 1 || data->port > 65535) {
		VL_MSG_ERR ("BUG: ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_error;
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
