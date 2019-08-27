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
#include <netinet/tcp.h>
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
#include "rrr_socket.h"
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

		int max_retries = 100;

		retry_poll:
		res = poll(&fds, 1, 10);
		if (res == -1) {
			if (--max_retries == 100) {
				VL_MSG_ERR("Max retries for poll reached in ip_receive_packets for socket %i pid %i\n",
						fd, getpid());
				res = 1;
				return 1;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(10);
				goto retry_poll;
			}
			else if (errno == EINTR) {
				goto retry_poll;
			}
			VL_MSG_ERR ("Error from poll in ip_receive_packets: %s\n", strerror(errno));
			return 1;
		}
		else if (!(fds.revents & POLLIN)) {
			VL_DEBUG_MSG_5 ("ip no data available\n");
			break;
		}

		memset(buffer, '\0', VL_IP_RECEIVE_MAX_SIZE);

		VL_DEBUG_MSG_3 ("ip receiving data\n");

		max_retries = 100;
		ssize_t count;

		retry_recv:
		count = recvfrom(fd, buffer, VL_IP_RECEIVE_MAX_SIZE, 0, &src_addr, &src_addr_len);

		if (count == -1) {
			if (--max_retries == 100) {
				VL_MSG_ERR("Max retries for recvfrom reached in ip_receive_packets for socket %i pid %i\n",
						fd, getpid());
				res = 1;
				return 1;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(10);
				goto retry_recv;
			}
			else if (errno == EINTR) {
				goto retry_recv;
			}
			VL_MSG_ERR ("Error from recvfrom in ip_receive_packets: %s\n", strerror(errno));
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

	if (message_convert_endianess(&entry->data.message) != 0) {
		VL_MSG_ERR ("Could not convert message endianess\n");
		free (entry);
		return 0;
	}

	if (rrr_socket_msg_checksum_check((struct rrr_socket_msg *) &entry->data.message, sizeof(entry->data.message)) != 0) {
		VL_MSG_ERR ("IP: Message checksum was invalid\n");
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

	ssize_t bytes;
	int max_retries = 100;

	retry:
	if ((bytes = sendto(info->fd, buf, sizeof(*final_message), 0, info->res->ai_addr,info->res->ai_addrlen)) == -1) {
		if (--max_retries == 100) {
			VL_MSG_ERR("Max retries for sendto reached in ip_send_message for socket %i pid %i\n",
					info->fd, getpid());
			return 1;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			usleep(10);
			goto retry;
		}
		else if (errno == EINTR) {
			goto retry;
		}
		VL_MSG_ERR ("Error from sendto in ip_send_message: %s\n", strerror(errno));
		return 1;
	}

	if (bytes != sizeof(*final_message)) {
		VL_MSG_ERR("All bytes were not sent in sendto in ip_send_message\n");
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
		rrr_socket_close(data->fd);
		data->fd = 0;
	}
}

int ip_network_start_udp_ipv4 (struct ip_data *data) {
	int fd = rrr_socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_UDP, "ip_network_start");
	if (fd == -1) {
		VL_MSG_ERR ("Could not create socket: %s\n", strerror(errno));
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
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int ip_network_connect_tcp_ipv4_or_ipv6 (struct ip_accept_data **accept_data, unsigned int port, const char *host) {
	int fd = 0;

	*accept_data = NULL;

	if (port < 1 || port > 65535) {
		VL_BUG ("ip_network_start: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

    struct addrinfo hints;
    struct addrinfo *result;

    memset (&hints, '\0', sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int s = getaddrinfo(host, port_str, &hints, &result);
    if (s != 0) {
    	VL_MSG_ERR("Failed to get address of '%s': %s\n", host, gai_strerror(s));
    	goto out_error;
    }

    struct addrinfo *rp;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
    	fd = rrr_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, "ip_network_start");
    	if (fd == -1) {
    		continue;
    	}
    	if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
    		break;
    	}
    	rrr_socket_close(fd);
    }

    freeaddrinfo(result);

    if (fd < 0 || rp == NULL) {
		VL_MSG_ERR ("Could not create socket for host '%s'\n", host);
		goto out_error;
    }

    struct ip_accept_data *accept_result = malloc(sizeof(*result));
    if (accept_result == NULL) {
    	VL_MSG_ERR("Could not allocate memory in ip_network_connect_tcp_ipv4_or_ipv6\n");
    	goto out_close_socket;
    }

    memset(accept_result, '\0', sizeof(*accept_result));

    accept_result->ip_data.fd = fd;
    accept_result->ip_data.port = port;
    accept_result->len = sizeof(accept_result->addr);
    if (getsockname(fd, &accept_result->addr, &accept_result->len) != 0) {
    	VL_MSG_ERR("getsockname failed: %s\n", strerror(errno));
    	goto out_free_accept;
    }

    *accept_data = accept_result;

	return 0;

	out_free_accept:
		free(accept_result);
	out_close_socket:
		rrr_socket_close(fd);
	out_error:
		return 1;
}

int ip_network_start_tcp_ipv4_and_ipv6 (struct ip_data *data, int max_connections) {
	int fd = rrr_socket(AF_INET6, SOCK_CLOEXEC|SOCK_NONBLOCK|SOCK_STREAM, 0, "ip_network_start");
	if (fd == -1) {
		VL_MSG_ERR ("Could not create socket: %s\n", strerror(errno));
		goto out_error;
	}

	if (data->port < 1 || data->port > 65535) {
		VL_MSG_ERR ("BUG: ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_in6 si;
	memset(&si, '\0', sizeof(si));
	si.sin6_family = AF_INET6;
	si.sin6_port = htons(data->port);
	si.sin6_addr = in6addr_any;

	if (bind (fd, (struct sockaddr *) &si, sizeof(si)) == -1) {
		VL_MSG_ERR ("Could not bind to port %d: %s\n", data->port, strerror(errno));
		goto out_close_socket;
	}

	int enable = 1;
	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		VL_MSG_ERR ("Could not set SO_REUSEADDR for socket bound to port %d: %s\n", data->port, strerror(errno));
		goto out_close_socket;
	}

	if (listen (fd, max_connections) < 0) {
		VL_MSG_ERR ("Could not listen to port %d: %s\n", data->port, strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;

	return 0;

	out_close_socket:
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int ip_close (struct ip_data *data) {
	if (data->fd == 0) {
		VL_BUG("Received zero-value FD in ip_close\n");
	}
	int ret = rrr_socket_close(data->fd);

	data->fd = 0;

	return ret;
}

int ip_accept (struct ip_accept_data **accept_data, struct ip_data *listen_data, const char *creator, int tcp_nodelay) {
	int ret = 0;

	struct sockaddr sockaddr_tmp = {0};
	socklen_t socklen_tmp = sizeof(sockaddr_tmp);
	struct ip_accept_data *res = NULL;

	*accept_data = NULL;

	ret = rrr_socket_accept(listen_data->fd, &sockaddr_tmp, &socklen_tmp, creator);
	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
			goto out;
		}
		else {
			VL_MSG_ERR("Error in ip_accept: %s\n", strerror(errno));
			ret = 1;
			goto out;
		}
	}

	int fd = ret;
	ret = 0;

	int enable = 1;
	if (tcp_nodelay == 1) {
		if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &enable, sizeof(enable)) != 0) {
			VL_MSG_ERR("Could not set TCP_NODELAY for socket in ip_accept: %s\n", strerror(errno));
			ret = 1;
			goto out_close_socket;
		}
	}

	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		VL_MSG_ERR ("Could not set SO_REUSEADDR for accepted connection: %s\n", strerror(errno));
		goto out_close_socket;
	}

	res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate memory in ip_accept\n");
		ret = 1;
		goto out;
	}
	memset (res, '\0', sizeof(*res));

	if (sockaddr_tmp.sa_family != AF_INET && sockaddr_tmp.sa_family != AF_INET6) {
		VL_BUG("Non AF_INET/AF_INET6 from accept() in ip_accept\n");
	}

	res->ip_data.fd = fd;
	res->addr = sockaddr_tmp;
	res->len = socklen_tmp;

	{
		struct sockaddr_in client_tmp;
		socklen_t len_tmp = sizeof(client_tmp);
		getpeername(res->ip_data.fd, (struct sockaddr *) &client_tmp, &len_tmp);
	    res->ip_data.port = ntohs (client_tmp.sin_port);
	}

	*accept_data = res;
	res = NULL;

	goto out;

	out_close_socket:
		rrr_socket_close(fd);

	out:
		RRR_FREE_IF_NOT_NULL(res);
		return ret;
}
