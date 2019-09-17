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
#include "array.h"
#include "rrr_socket.h"
#include "vl_time.h"
#include "crc32.h"
#include "rrr_socket_common.h"
#include "rrr_socket_msg.h"
#include "rrr_socket_read.h"

void ip_buffer_entry_destroy (
		struct ip_buffer_entry *entry
) {
	RRR_FREE_IF_NOT_NULL(entry->message);
	free(entry);
}

void ip_buffer_entry_destroy_void (
		void *entry
) {
	ip_buffer_entry_destroy(entry);
}

void ip_buffer_entry_set_message (
		struct ip_buffer_entry *entry,
		void *message,
		ssize_t data_length
) {
	entry->message = message;
	entry->data_length = data_length;
}

int ip_buffer_entry_new (
		struct ip_buffer_entry **result,
		ssize_t data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *message
) {
	int ret = 0;

	*result = NULL;

	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory in ip_buffer_entry_new\n");
		ret = 1;
		goto out;
	}

	if (addr == NULL) {
		memset(&entry->addr, '\0', sizeof(entry->addr));
	}
	else {
		entry->addr = *addr;
	}

	if (addr_len > sizeof(entry->addr)) {
		VL_BUG("addr_len too long in ip_buffer_entry_new\n");
	}
	entry->addr_len = addr_len;

	entry->send_time = 0;
	entry->message = message;
	entry->data_length = data_length;

	*result = entry;

	out:
	return ret;
}

int ip_buffer_entry_new_with_empty_message (
		struct ip_buffer_entry **result,
		ssize_t message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	struct ip_buffer_entry *entry = NULL;
	struct vl_message *message = NULL;

	ssize_t message_size = sizeof(*message) - 1 + message_data_length;

	message = malloc(message_size);
	if (message == NULL) {
		VL_MSG_ERR("Could not allocate message in ip_buffer_entry_new_with_message\n");
		goto out;
	}

	memset(message, '\0', message_size);

	if (ip_buffer_entry_new (
			&entry,
			message_size,
			addr,
			addr_len,
			message
	) != 0) {
		VL_MSG_ERR("Could not allocate ip buffer entry in ip_buffer_entry_new_with_message\n");
		ret = 1;
		goto out;
	}

	message = NULL;

	*result = entry;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

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

struct receive_packets_callback_data {
	int (*callback)(struct ip_buffer_entry *entry, void *arg);
	void *callback_arg;
	struct ip_stats *stats;
};

static int __ip_receive_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct receive_packets_callback_data *callback_data = arg;

	int ret = 0;

	if (read_session->read_complete == 0) {
		VL_BUG("Read complete was 0 in __ip_receive_packets_callback\n");
	}

	struct ip_buffer_entry *entry = NULL;

	if (ip_buffer_entry_new (
			&entry,
			read_session->target_size,
			&read_session->src_addr,
			read_session->src_addr_len,
			read_session->rx_buf_ptr
	) != 0) {
		VL_MSG_ERR("Could not allocate ip buffer entry in __ip_receive_packets_callback\b");
		ret = 1;
		goto out;
	}

	read_session->rx_buf_ptr = NULL;

	ret = callback_data->callback(entry, callback_data->callback_arg);
	if (ret == VL_IP_RECEIVE_STOP) {
		goto out;
	}
	else if (ret == VL_IP_RECEIVE_ERR) {
		return 1;
	}

	if (callback_data->stats != NULL) {
		ret = ip_stats_update(callback_data->stats, 1, VL_IP_RECEIVE_MAX_STEP_SIZE);
		if (ret == VL_IP_STATS_UPDATE_ERR) {
			VL_MSG_ERR("ip: Error returned from stats update function\n");
			return 1;
		}
		if (ret == VL_IP_STATS_UPDATE_READY) {
			if (ip_stats_print_reset(callback_data->stats, 1) != VL_IP_STATS_UPDATE_OK) {
				VL_MSG_ERR("ip: Error returned from stats print function\n");
				return 1;
			}
		}
	}

	out:
	return ret;
}

int ip_receive_array (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		const struct rrr_array *definition,
		int (*callback)(struct ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {
	struct rrr_socket_common_get_session_target_length_from_array_data callback_data_array = {
			definition
	};

	struct receive_packets_callback_data callback_data_ip = {
			callback, arg, stats
	};

	int ret = rrr_socket_read_message (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			rrr_socket_common_get_session_target_length_from_array,
			&callback_data_array,
			__ip_receive_callback,
			&callback_data_ip
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			return 0;
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Warning: Soft error while reading data in ip_receive_raw\n");
			return 0;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			VL_MSG_ERR("Hard error while reading data in ip_receive_raw\n");
			return 1;
		}
	}

	return 0;
}

int ip_receive_socket_msg (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
		int (*callback)(struct ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {
	int ret = 0;

	struct receive_packets_callback_data callback_data = {
			callback,
			arg,
			stats
	};

	ret = rrr_socket_read_message (
			read_session_collection,
			fd,
			sizeof(struct rrr_socket_msg),
			4096,
			rrr_socket_common_get_session_target_length_from_message_and_checksum,
			NULL,
			__ip_receive_callback,
			&callback_data
	);

	if (ret != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_READ_INCOMPLETE) {
			return 0;
		}
		else if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Warning: Soft error while reading data in ip_receive_packets\n");
			return 0;
		}
		else if (ret == RRR_SOCKET_HARD_ERROR) {
			VL_MSG_ERR("Hard error while reading data in ip_receive_packets\n");
			return 1;
		}
	}

	return 0;
}

struct ip_receive_messages_callback_data {
	int (*callback)(struct ip_buffer_entry *entry, void *arg);
	void *arg;
#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data;
#endif
};

static int __ip_receive_vl_message_callback(struct ip_buffer_entry *entry, void *arg) {
	int ret = 0;

	struct ip_receive_messages_callback_data *data = arg;
	struct vl_message *message = entry->message;

#ifdef VL_WITH_OPENSSL
	struct module_crypt_data *crypt_data = data->crypt_data;
#endif
	const ssize_t count = entry->data_length;

	if (count < 10) {
		VL_MSG_ERR ("Received short message/packet from network\n");
		goto out_free;
	}

	// Header CRC32 is checked when reading the data from remote and getting size
	if (rrr_socket_msg_head_to_host_and_verify((struct rrr_socket_msg *) entry->message, entry->data_length) != 0) {
		VL_MSG_ERR("Message was invalid in __ip_receive_messages_callback \n");
		goto out_free;
	}

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL) {
		ssize_t new_size = sizeof(struct vl_message) - 1 + entry->data_length + 1024;
		struct vl_message *new_message = realloc(entry->message, new_size);
		if (new_message == NULL) {
			VL_MSG_ERR("Could not realloc message before decryption in __ip_receive_messages_callback\n");
			goto out_free;
		}
		entry->message = new_message;

		char *crypt_start = ((char*) message) + sizeof(struct rrr_socket_msg);
		unsigned int crypt_length_orig = message->network_size - sizeof(struct rrr_socket_msg);
		unsigned int crypt_length = crypt_length_orig;

		VL_DEBUG_MSG_3("ip decrypting message of length %u \n", crypt_length);
		if (module_decrypt_message(
				crypt_data,
				crypt_start,
				&crypt_length,
				new_size
		) != 0) {
			VL_MSG_ERR("Error returned from module decrypt function\n");
			ret = 1;
			goto out_free;
		}

		message->network_size = crypt_length;
		ip_buffer_entry_set_message(entry, message, crypt_length);
	}
#endif

	if (rrr_socket_msg_check_data_checksum_and_length((struct rrr_socket_msg *) entry->message, entry->data_length) != 0) {
		VL_MSG_ERR ("IP: Message checksum was invalid\n");
		goto out_free;
	}

	if (message_to_host_and_verify(entry->message, entry->data_length) != 0) {
		VL_MSG_ERR("Message verification failed in __ip_receive_messages_callback (size: %u<>%u)\n",
				MSG_TOTAL_SIZE(message), message->msg_size);
		ret = 1;
		goto out_free;
	}

	return data->callback(entry, data->arg);

	out_free:
	ip_buffer_entry_destroy(entry);
	return ret;
}

/* Receive packets and parse vl_message struct or fail */
int ip_receive_vl_message (
		struct rrr_socket_read_session_collection *read_session_collection,
		int fd,
#ifdef VL_WITH_OPENSSL
		struct module_crypt_data *crypt_data,
#endif
		int (*callback)(struct ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
) {
	struct ip_receive_messages_callback_data data;

	data.callback = callback;
	data.arg = arg;
#ifdef VL_WITH_OPENSSL
	data.crypt_data = crypt_data;
#endif

	return ip_receive_socket_msg (
		read_session_collection,
		fd,
		__ip_receive_vl_message_callback,
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
	int ret = 0;

	ssize_t final_size = MSG_TOTAL_SIZE(input_message);
	ssize_t buf_size = MSG_TOTAL_SIZE(input_message);

#ifdef VL_WITH_OPENSSL
	buf_size += 1024;
#endif

	struct vl_message *final_message = malloc(buf_size);
	if (final_message == NULL) {
		VL_MSG_ERR("Could not allocate memory in ip_send_message\n");
		ret = 1;
		goto out;
	}

	memcpy(final_message, input_message, final_size);

	final_message->network_size = final_size;
	final_message->msg_size = final_size;

	message_prepare_for_network(final_message);

	VL_DEBUG_MSG_3 ("ip sends packet timestamp from %" PRIu64 "\n", input_message->timestamp_from);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) final_message,
			RRR_SOCKET_MSG_TYPE_VL_MESSAGE,
			final_size,
			0
	);

#ifdef VL_WITH_OPENSSL
	if (crypt_data->crypt != NULL) {
		char *buf_start = ((char *) final_message) + sizeof(struct rrr_socket_msg);
		unsigned int crypt_final_size = final_size - sizeof(struct rrr_socket_msg);
		if (module_encrypt_message (
				crypt_data,
				buf_start,
				&crypt_final_size,
				buf_size
		) != 0) {
			ret = 1;
			goto out;
		}
		final_message->network_size = crypt_final_size + sizeof(struct rrr_socket_msg);
		final_size = crypt_final_size;
	}
#endif

	rrr_socket_msg_checksum_and_to_network_endian (
			(struct rrr_socket_msg *) final_message
	);

	ssize_t bytes;
	int max_retries = 100;

	retry:
	if ((bytes = sendto(info->fd, final_message, final_size, 0, info->res->ai_addr,info->res->ai_addrlen)) == -1) {
		if (--max_retries == 100) {
			VL_MSG_ERR("Max retries for sendto reached in ip_send_message for socket %i pid %i\n",
					info->fd, getpid());
			ret = 1;
			goto out;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			usleep(10);
			goto retry;
		}
		else if (errno == EINTR) {
			goto retry;
		}
		VL_MSG_ERR ("Error from sendto in ip_send_message: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	if (bytes != final_size) {
		VL_MSG_ERR("All bytes were not sent in sendto in ip_send_message\n");
		ret = 1;
		goto out;
	}

	if (stats != NULL) {
		int res = ip_stats_update(stats, 1, final_size);
		if (res == VL_IP_STATS_UPDATE_ERR) {
			VL_MSG_ERR("ip: Error returned from stats update function\n");
			ret = 1;
			goto out;
		}
		if (res == VL_IP_STATS_UPDATE_READY) {
			if (ip_stats_print_reset(stats, 1) != VL_IP_STATS_UPDATE_OK) {
				VL_MSG_ERR("ip: Error returned from stats print function\n");
				ret = 1;
				goto out;
			}
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(final_message);
	return ret;
}

void ip_network_cleanup (void *arg) {
	struct ip_data *data = arg;
	if (data->fd != 0) {
		rrr_socket_close(data->fd);
		data->fd = 0;
	}
}

int ip_network_start_udp_ipv4 (struct ip_data *data) {
	int fd = rrr_socket (
			AF_INET,
			SOCK_DGRAM|SOCK_NONBLOCK,
			IPPROTO_UDP,
			"ip_network_start",
			NULL
	);
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
    	fd = rrr_socket (
    			rp->ai_family,
				rp->ai_socktype|SOCK_NONBLOCK,
				rp->ai_protocol,
				"ip_network_connect_tcp_ipv4_or_ipv6",
				NULL
		);
    	if (fd == -1) {
    		VL_MSG_ERR("Error while creating socket: %s\n", strerror(errno));
    		continue;
    	}

    	if (rrr_socket_connect_nonblock(fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == 0) {
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
	int fd = rrr_socket (
			AF_INET6,
			SOCK_NONBLOCK|SOCK_STREAM,
			0,
			"ip_network_start",
			NULL
	);
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

	if (rrr_socket_bind_and_listen(fd, (struct sockaddr *) &si, sizeof(si), SO_REUSEADDR, max_connections) != 0) {
		VL_MSG_ERR ("Could not listen on port %d: %s\n", data->port, strerror(errno));
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
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) != 0) {
			VL_MSG_ERR("Could not set TCP_NODELAY for socket in ip_accept: %s\n", strerror(errno));
			ret = 1;
			goto out_close_socket;
		}
	}

	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		VL_MSG_ERR ("Could not set SO_REUSEADDR for accepted connection: %s\n", strerror(errno));
		goto out_close_socket;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		VL_MSG_ERR("Error while getting flags with fcntl for socket: %s\n", strerror(errno));
		goto out_close_socket;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		VL_MSG_ERR("Error while setting O_NONBLOCK on socket: %s\n", strerror(errno));
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
