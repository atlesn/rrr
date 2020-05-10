/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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
#include <read.h>

#include "ip.h"
#include "ip_buffer_entry.h"
#include "ip_accept_data.h"
#include "../global.h"
#include "messages.h"
#include "array.h"
#include "rrr_socket.h"
#include "vl_time.h"
#include "crc32.h"
#include "rrr_socket_common.h"
#include "rrr_socket_msg.h"
#include "rrr_socket_read.h"
#include "rrr_strerror.h"
#include "read_constants.h"
#include "rrr_socket_constants.h"

int rrr_ip_stats_init (struct ip_stats *stats, unsigned int period, const char *type, const char *name) {
	stats->period = period;
	stats->name = name;
	stats->type = type;
	return (pthread_mutex_init(&stats->lock, NULL) != 0);
}

int rrr_ip_stats_init_twoway (struct ip_stats_twoway *stats, unsigned int period, const char *name) {
	memset(stats, '\0', sizeof(*stats));
	int ret = 0;
	ret |= rrr_ip_stats_init(&stats->send, period, "send", name);
	ret |= rrr_ip_stats_init(&stats->receive, period, "receive", name);
	return ret;
}

int rrr_ip_stats_update(struct ip_stats *stats, unsigned long int packets, unsigned long int bytes) {
	int ret = RRR_IP_STATS_UPDATE_OK;

	if (pthread_mutex_lock(&stats->lock) != 0) {
		return RRR_IP_STATS_UPDATE_ERR;
	}

	stats->packets += packets;
	stats->bytes += bytes;

	if (stats->time_from == 0) {
		stats->time_from = rrr_time_get_64();
	}
	else if (stats->time_from + stats->period * 1000000 < rrr_time_get_64()) {
		ret = RRR_IP_STATS_UPDATE_READY;
	}

	pthread_mutex_unlock(&stats->lock);
	return ret;
}

int rrr_stats_print_reset(struct ip_stats *stats, int do_reset) {
	int ret = RRR_IP_STATS_UPDATE_OK;

	if (pthread_mutex_lock(&stats->lock) != 0) {
		return RRR_IP_STATS_UPDATE_ERR;
	}

	RRR_DBG_2("IP stats for %s %s: %lu packets/s %lu bytes/s, period is %u\n",
			stats->name, stats->type, stats->packets/stats->period, stats->bytes/stats->period, stats->period);

	if (do_reset) {
		stats->time_from = 0;
		stats->packets = 0;
		stats->bytes = 0;
	}

	pthread_mutex_unlock(&stats->lock);
	return ret;
}

struct ip_receive_callback_data {
	struct rrr_ip_buffer_entry *target_entry;
	int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg);
	void *callback_arg;
	struct ip_stats *stats;
};

static int __ip_receive_callback (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct ip_receive_callback_data *callback_data = arg;

	int ret = 0;

	if (read_session->read_complete == 0) {
		RRR_BUG("Read complete was 0 in __ip_receive_packets_callback\n");
	}

	int protocol = 0;

	switch (read_session->socket_options) {
		case SOCK_DGRAM:
			protocol = RRR_IP_UDP;
			break;
		case SOCK_STREAM:
			protocol = RRR_IP_TCP;
			break;
		default:
			RRR_MSG_ERR("Unknown SO_TYPE %i in __ip_receive_callback\n", read_session->socket_options);
			ret = 1;
			goto out;
	}

	if (callback_data->target_entry->message != NULL) {
		RRR_BUG("message pointer of entry was not empty in __ip_receive_callback\n");
	}

	rrr_ip_buffer_entry_set_unlocked (
			callback_data->target_entry,
			read_session->rx_buf_ptr,
			read_session->target_size,
			&read_session->src_addr,
			read_session->src_addr_len,
			protocol
	);

	read_session->rx_buf_ptr = NULL;

	ret = callback_data->callback(callback_data->target_entry, callback_data->callback_arg);

	if (ret == 0) {
		// OK
	}
	else if (ret == RRR_IP_RECEIVE_STOP) {
		ret = 0;
		goto out;
	}
	else if (ret == RRR_IP_RECEIVE_ERR) {
		return 1;
	}
	else {
		RRR_BUG("Unknown return value %i from callback in __ip_receive_callback\n", ret);
	}

	if (callback_data->stats != NULL) {
		ret = rrr_ip_stats_update(callback_data->stats, 1, RRR_IP_RECEIVE_MAX_STEP_SIZE);
		if (ret == RRR_IP_STATS_UPDATE_ERR) {
			RRR_MSG_ERR("ip: Error returned from stats update function\n");
			return 1;
		}
		if (ret == RRR_IP_STATS_UPDATE_READY) {
			if (rrr_stats_print_reset(callback_data->stats, 1) != RRR_IP_STATS_UPDATE_OK) {
				RRR_MSG_ERR("ip: Error returned from stats print function\n");
				return 1;
			}
		}
	}

	out:
	return ret;
}

int rrr_ip_receive_array (
		struct rrr_ip_buffer_entry *target_entry,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		const struct rrr_array *definition,
		int do_sync_byte_by_byte,
		int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {
	struct ip_receive_callback_data callback_data = {
		target_entry,
		callback,
		arg,
		stats
	};

	return rrr_socket_common_receive_array (
			read_session_collection,
			fd,
			read_flags,
			RRR_SOCKET_READ_METHOD_RECVFROM,
			definition,
			do_sync_byte_by_byte,
			__ip_receive_callback,
			&callback_data
	);
}

/* XXX : Disabled, not currently used
int rrr_ip_receive_socket_msg (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int no_sleeping,
		int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {

	struct ip_receive_callback_data callback_data = {
		callback, arg, stats
	};

	return rrr_socket_common_receive_socket_msg (
			read_session_collection,
			fd,
			(no_sleeping != 0 ? RRR_READ_F_NO_SLEEPING : 0),
			RRR_SOCKET_READ_METHOD_RECVFROM,
			__ip_receive_callback,
			&callback_data
	);

}

*/

/* Not currently used
 * TODO : Convert to use read_common message endian flip and verification
 *
struct ip_receive_messages_callback_data {
	int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg);
	void *arg;
};

static int __rrr_ip_receive_rrr_message_callback (
		struct rrr_ip_buffer_entry *entry,
		void *arg
) {
	int ret = 0;
	struct ip_receive_messages_callback_data *data = arg;
	struct rrr_message *message = entry->message;
	const ssize_t count = entry->data_length;
	if (count < 10) {
		RRR_MSG_ERR("Received short message/packet from network\n");
		goto out_free;
	}
	// Header CRC32 is checked when reading the data from remote and getting size
	if (rrr_socket_msg_head_to_host_and_verify(
			(struct rrr_socket_msg*) entry->message, entry->data_length) != 0) {
		RRR_MSG_ERR("Message was invalid in __ip_receive_messages_callback \n");
		goto out_free;
	}
	if (rrr_socket_msg_check_data_checksum_and_length(
			(struct rrr_socket_msg*) entry->message, entry->data_length) != 0) {
		RRR_MSG_ERR("IP: Message checksum was invalid\n");
		goto out_free;
	}
	if (rrr_message_to_host_and_verify(entry->message, entry->data_length) != 0) {
		RRR_MSG_ERR(
				"Message verification failed in __ip_receive_messages_callback (size: %u<>%u)\n",
				MSG_TOTAL_SIZE(message), message->msg_size);
		ret = 1;
		goto out_free;
	}
	return data->callback(entry, data->arg);
	out_free: rrr_ip_buffer_entry_destroy(entry);
	return ret;
}
int rrr_ip_receive_rrr_message (
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int no_sleeping,
		int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {
	struct ip_receive_messages_callback_data data;

	data.callback = callback;
	data.arg = arg;

	return rrr_ip_receive_socket_msg (
		read_session_collection,
		fd,
		no_sleeping,
		__rrr_ip_receive_rrr_message_callback,
		&data,
		stats
	);
}
*/

int rrr_ip_send (
	int *err,
	int fd,
	const struct sockaddr *sockaddr,
	socklen_t addrlen,
	void *data,
	ssize_t data_size
) {
	int ret = 0;
	ssize_t bytes = 0;

	*err = 0;

	int max_retries = 100;

	retry:
	if ((bytes = sendto(fd, data, data_size, 0, sockaddr, addrlen)) == -1) {
		*err = errno;
		if (errno == ECONNREFUSED || errno == ECONNRESET) {
			RRR_MSG_ERR ("Connection refused in rrr_ip_send\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		else if (errno == EPIPE) {
			RRR_MSG_ERR ("Pipe full in ip_send_raw or connection closed by remote\n");
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		else if (--max_retries == 0) {
			RRR_MSG_ERR("Max retries for sendto reached in rrr_ip_send for socket %i pid %i\n",
					fd, getpid());
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			usleep(10);
			goto retry;
		}
		else if (errno == EINTR) {
			goto retry;
		}
		// Sometimes caller tests for many addresses when looking destination up by hostname
		RRR_DBG_1 ("Note: Error from sendto in rrr_ip_send, address family was %u: %s\n", sockaddr->sa_family, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (bytes != data_size) {
		RRR_MSG_ERR("All bytes were not sent in sendto in rrr_ip_send\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_ip_send_message (
	const struct rrr_message *input_message,
	struct rrr_ip_send_packet_info *info,
	struct ip_stats *stats
) {
	int ret = 0;

	ssize_t final_size = MSG_TOTAL_SIZE(input_message);
	ssize_t buf_size = MSG_TOTAL_SIZE(input_message);

	struct rrr_message *final_message = malloc(buf_size);
	if (final_message == NULL) {
		RRR_MSG_ERR("Could not allocate memory in ip_send_message\n");
		ret = 1;
		goto out;
	}

	memcpy(final_message, input_message, final_size);

	final_message->msg_size = final_size;

	rrr_message_prepare_for_network(final_message);

	RRR_DBG_3 ("ip sends packet timestamp from %" PRIu64 "\n", input_message->timestamp);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) final_message,
			RRR_SOCKET_MSG_TYPE_MESSAGE,
			final_size,
			0
	);

	rrr_socket_msg_checksum_and_to_network_endian (
			(struct rrr_socket_msg *) final_message
	);

	int err;
	if ((ret = rrr_ip_send(&err, info->fd, info->res->ai_addr, info->res->ai_addrlen, final_message, final_size)) != 0) {
		RRR_MSG_ERR("Data could not be sent in ip_send_message\n");
		goto out;
	}

	if (stats != NULL) {
		int res = rrr_ip_stats_update(stats, 1, final_size);
		if (res == RRR_IP_STATS_UPDATE_ERR) {
			RRR_MSG_ERR("ip: Error returned from stats update function\n");
			ret = 1;
			goto out;
		}
		if (res == RRR_IP_STATS_UPDATE_READY) {
			if (rrr_stats_print_reset(stats, 1) != RRR_IP_STATS_UPDATE_OK) {
				RRR_MSG_ERR("ip: Error returned from stats print function\n");
				ret = 1;
				goto out;
			}
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(final_message);
	return ret;
}

void rrr_ip_network_cleanup (void *arg) {
	struct rrr_ip_data *data = arg;
	if (data->fd != 0) {
		rrr_socket_close(data->fd);
		data->fd = 0;
	}
}

int rrr_ip_network_start_udp_ipv4_nobind (struct rrr_ip_data *data) {
	int fd = rrr_socket (
			AF_INET,
			SOCK_DGRAM|SOCK_NONBLOCK,
			IPPROTO_UDP,
			"ip_network_start_udp_ipv4_nobind",
			NULL
	);
	if (fd == -1) {
		RRR_MSG_ERR ("Could not create socket: %s\n", rrr_strerror(errno));
		return 1;
	}

	data->fd = fd;

	return 0;
}

int rrr_ip_network_start_udp_ipv4 (struct rrr_ip_data *data) {
	int fd = rrr_socket (
			AF_INET,
			SOCK_DGRAM|SOCK_NONBLOCK,
			IPPROTO_UDP,
			"ip_network_start_udp_ipv4",
			NULL
	);
	if (fd == -1) {
		RRR_MSG_ERR ("Could not create socket: %s\n", rrr_strerror(errno));
		goto out_error;
	}

	if (data->port < 1 || data->port > 65535) {
		RRR_MSG_ERR ("BUG: ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_in si;
	memset(&si, '\0', sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = htons(data->port);
	si.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind (fd, (struct sockaddr *) &si, sizeof(si)) == -1) {
		RRR_MSG_ERR ("Could not bind to port %d: %s", data->port, rrr_strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;

	return 0;

	out_close_socket:
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
		struct rrr_ip_data *ip_data,
		unsigned int port,
		const char *host,
		void *data,
		ssize_t size
) {
	int ret = 0;

	if (port < 1 || port > 65535) {
		RRR_BUG ("rrr_ip_network_udp_sendto: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

	struct addrinfo hints;
	struct addrinfo *result;

	memset (&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	int s = getaddrinfo(host, port_str, &hints, &result);
	if (s != 0) {
		RRR_MSG_ERR("Failed to get address of '%s': %s\n", host, gai_strerror(s));
		ret = 1;
		goto out;
	}

	struct addrinfo *rp;
	int did_send = 0;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int err;
		if (rrr_ip_send(&err, ip_data->fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen, data, size) == 0) {
			did_send = 1;
			break;
		}
	}

	freeaddrinfo(result);

	if (did_send == 0) {
		RRR_MSG_ERR("Could not send UDP data to host %s port %u\n", host, port);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw (
		struct rrr_ip_accept_data **accept_data,
		struct sockaddr *addr,
		socklen_t addr_len
) {
	int fd = 0;

	*accept_data = NULL;

	fd = rrr_socket (
			AF_INET,
			SOCK_STREAM|SOCK_NONBLOCK,
			0,
			"ip_network_connect_tcp_ipv4_or_ipv6_raw",
			NULL
	);
	if (fd == -1) {
		RRR_MSG_ERR("Error while creating socket: %s\n", rrr_strerror(errno));
		goto out_error;
	}

    struct rrr_ip_accept_data *accept_result = malloc(sizeof(*accept_result));
    if (accept_result == NULL) {
    	RRR_MSG_ERR("Could not allocate memory in ip_network_connect_tcp_ipv4_or_ipv6\n");
    	goto out_close_socket;
    }

    memset(accept_result, '\0', sizeof(*accept_result));

	if (rrr_socket_connect_nonblock(fd, (struct sockaddr *) addr, addr_len) != 0) {
		RRR_MSG_ERR("Could not connect in in ip_network_connect_tcp_ipv4_or_ipv6\n");
		goto out_free_accept;
	}

    accept_result->ip_data.fd = fd;
    accept_result->len = addr_len;
    memcpy (&accept_result->addr, addr, addr_len);

    struct sockaddr_in *sockaddr_in = (struct sockaddr_in *) &addr;
    accept_result->ip_data.port = ntohs(sockaddr_in->sin_port);

/*    if (getsockname(fd, &accept_result->addr, &accept_result->len) != 0) {
    	RRR_MSG_ERR("getsockname failed: %s\n", rrr_strerror(errno));
		goto out_free_accept;
    }*/

    *accept_data = accept_result;

	return 0;

	out_free_accept:
		free(accept_result);
	out_close_socket:
		rrr_socket_close(fd);
	out_error:
		return 1;
}

int rrr_ip_network_connect_tcp_ipv4_or_ipv6 (struct rrr_ip_accept_data **accept_data, unsigned int port, const char *host) {
	int fd = 0;

	*accept_data = NULL;

	if (port < 1 || port > 65535) {
		RRR_BUG ("rrr_ip_network_connect_tcp_ipv4_or_ipv6: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

    struct addrinfo hints;
    struct addrinfo *addrinfo_result;

    memset (&hints, '\0', sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int s = getaddrinfo(host, port_str, &hints, &addrinfo_result);
    if (s != 0) {
    	RRR_MSG_ERR("Failed to get address of '%s': %s\n", host, gai_strerror(s));
    	goto out_error;
    }

    struct addrinfo *rp;
    for (rp = addrinfo_result; rp != NULL; rp = rp->ai_next) {
    	fd = rrr_socket (
    			rp->ai_family,
				rp->ai_socktype|SOCK_NONBLOCK,
				rp->ai_protocol,
				"ip_network_connect_tcp_ipv4_or_ipv6",
				NULL
		);
    	if (fd == -1) {
    		RRR_MSG_ERR("Error while creating socket: %s\n", rrr_strerror(errno));
    		continue;
    	}

    	if (rrr_socket_connect_nonblock(fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == 0) {
    		break;
    	}

    	rrr_socket_close(fd);
    }

    freeaddrinfo(addrinfo_result);

    if (fd < 0 || rp == NULL) {
		RRR_MSG_ERR ("Could not create socket for host '%s'\n", host);
		goto out_error;
    }

    struct rrr_ip_accept_data *accept_result = malloc(sizeof(*accept_result));
    if (accept_result == NULL) {
    	RRR_MSG_ERR("Could not allocate memory in ip_network_connect_tcp_ipv4_or_ipv6\n");
    	goto out_close_socket;
    }

    memset(accept_result, '\0', sizeof(*accept_result));

    accept_result->ip_data.fd = fd;
    accept_result->ip_data.port = port;
    accept_result->len = sizeof(accept_result->addr);
    if (getsockname(fd, (struct sockaddr *) &accept_result->addr, &accept_result->len) != 0) {
    	RRR_MSG_ERR("getsockname failed: %s\n", rrr_strerror(errno));
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

int rrr_ip_network_start_tcp_ipv4_and_ipv6 (struct rrr_ip_data *data, int max_connections) {
	int fd = rrr_socket (
			AF_INET6,
			SOCK_NONBLOCK|SOCK_STREAM,
			0,
			"ip_network_start",
			NULL
	);
	if (fd == -1) {
		RRR_MSG_ERR ("Could not create socket: %s\n", rrr_strerror(errno));
		goto out_error;
	}

	if (data->port < 1 || data->port > 65535) {
		RRR_MSG_ERR ("BUG: ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_in6 si;
	memset(&si, '\0', sizeof(si));
	si.sin6_family = AF_INET6;
	si.sin6_port = htons(data->port);
	si.sin6_addr = in6addr_any;

	if (rrr_socket_bind_and_listen(fd, (struct sockaddr *) &si, sizeof(si), SO_REUSEADDR, max_connections) != 0) {
		RRR_MSG_ERR ("Could not listen on port %d: %s\n", data->port, rrr_strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;

	return 0;

	out_close_socket:
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int rrr_ip_close (struct rrr_ip_data *data) {
	if (data->fd == 0) {
		RRR_BUG("Received zero-value FD in ip_close\n");
	}
	int ret = rrr_socket_close(data->fd);

	data->fd = 0;

	return ret;
}

int rrr_ip_accept (struct rrr_ip_accept_data **accept_data, struct rrr_ip_data *listen_data, const char *creator, int tcp_nodelay) {
	int ret = 0;

	struct rrr_sockaddr sockaddr_tmp = {0};
	socklen_t socklen_tmp = sizeof(sockaddr_tmp);
	struct rrr_ip_accept_data *res = NULL;

	*accept_data = NULL;

	ret = rrr_socket_accept(listen_data->fd, &sockaddr_tmp, &socklen_tmp, creator);
	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
			goto out;
		}
		else {
			RRR_MSG_ERR("Error in ip_accept: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}

	int fd = ret;
	ret = 0;

	int enable = 1;
	if (tcp_nodelay == 1) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) != 0) {
			RRR_MSG_ERR("Could not set TCP_NODELAY for socket in ip_accept: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_close_socket;
		}
	}

	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		RRR_MSG_ERR ("Could not set SO_REUSEADDR for accepted connection: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		RRR_MSG_ERR("Error while getting flags with fcntl for socket: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		RRR_MSG_ERR("Error while setting O_NONBLOCK on socket: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}

	res = malloc(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_ERR("Could not allocate memory in ip_accept\n");
		ret = 1;
		goto out;
	}
	memset (res, '\0', sizeof(*res));

	if (	((struct sockaddr *) &sockaddr_tmp)->sa_family != AF_INET &&
			((struct sockaddr *) &sockaddr_tmp)->sa_family != AF_INET6
	) {
		RRR_BUG("Non AF_INET/AF_INET6 from accept() in ip_accept\n");
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
