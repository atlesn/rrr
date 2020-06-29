/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdlib.h>

#include "cmodule_common.h"

#include "cmodule_native.h"
#include "buffer.h"
#include "modules.h"
#include "ip_buffer_entry.h"
#include "message_addr.h"
#include "messages.h"
#include "instances.h"
#include "instance_config.h"
#include "stats/stats_instance.h"
#include "message_broker.h"
#include "poll_helper.h"
#include "../global.h"

static int __rrr_cmodule_common_read_final_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct rrr_cmodule_common_read_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_message *message_new = rrr_message_duplicate(callback_data->message);
	if (message_new == NULL) {
		RRR_MSG_0("Could not duplicate message in  __rrr_message_broker_cmodule_read_final_callback for instance %s\n",
				INSTANCE_D_NAME(callback_data->thread_data));
		ret = 1;
		goto out;
	}

//	printf ("read_from_child_callback_msg addr len: %" PRIu64 "\n", data->latest_message_addr.addr_len);

	// TODO : Look into warning "taking address of packed member of blabla latest_message_addr.addr"
	rrr_ip_buffer_entry_set_unlocked (
			entry,
			message_new,
			MSG_TOTAL_SIZE(message_new),
			(struct sockaddr *) &callback_data->addr_message,
			RRR_MSG_ADDR_GET_ADDR_LEN(&callback_data->addr_message),
			callback_data->addr_message.protocol
	);
	message_new = NULL;

	callback_data->count++;

	out:
	RRR_FREE_IF_NOT_NULL(message_new);
	memset(&callback_data->addr_message, '\0', sizeof(callback_data->addr_message));
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int __rrr_cmodule_common_read_callback (RRR_CMODULE_FINAL_CALLBACK_ARGS) {
	struct rrr_cmodule_common_read_callback_data *callback_data = arg;

	callback_data->addr_message = *msg_addr;
	callback_data->message = msg;

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->thread_data),
			NULL,
			0,
			0,
			__rrr_cmodule_common_read_final_callback,
			callback_data
	) != 0) {
		RRR_MSG_0("Could to write to output buffer in rrr_message_broker_cmodule_read_callback for instance %s\n",
				INSTANCE_D_NAME(callback_data->thread_data));
		return 1;
	}

	return 0;
}

static int __rrr_cmodule_common_read_from_forks (
		int *read_count,
		int *config_complete,
		struct rrr_instance_thread_data *thread_data,
		int loops
) {
	int ret = 0;

	*read_count = 0;

	struct rrr_cmodule_common_read_callback_data callback_data = {0};

	callback_data.thread_data = thread_data;

	return rrr_cmodule_read_from_forks (
			read_count,
			config_complete,
			thread_data->cmodule,
			loops,
			__rrr_cmodule_common_read_callback,
			&callback_data
	);

	*read_count = callback_data.count;
	return ret;
}

static int __rrr_cmodule_common_send_entry_to_fork_nolock (
		int *count,
		struct rrr_instance_thread_data *thread_data,
		pid_t fork_pid,
		struct rrr_ip_buffer_entry *entry
) {
	struct rrr_message *message = (struct rrr_message *) entry->message;

	struct rrr_message_addr addr_msg;
	int ret = 0;

	RRR_ASSERT(sizeof(addr_msg.addr) == sizeof(entry->addr), message_addr_and_ip_buffer_entry_addr_differ);

	// cmodule send will always free or take care of message memory
	entry->message = NULL;

//	printf ("perl5_input_callback: message %p\n", message);

	rrr_message_addr_init(&addr_msg);
	if (entry->addr_len > 0) {
		memcpy(&addr_msg.addr, &entry->addr, sizeof(addr_msg.addr));
		RRR_MSG_ADDR_SET_ADDR_LEN(&addr_msg, entry->addr_len);
	}

	if ((ret = rrr_cmodule_send_to_fork (
			count,
			thread_data->cmodule,
			fork_pid,
			message,
			&addr_msg
	)) != 0) {
		RRR_MSG_0("Passing message to instance %s fork using memory map failed.\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
		return ret;
}

struct rrr_cmodule_common_poll_callback_data {
	pid_t pid;
	int count;
	int max_count;
};

static int __rrr_cmodule_common_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	struct rrr_cmodule_common_poll_callback_data *callback_data = thread_data->cmodule->callback_data_tmp;

	int input_count = 0;

	ret = __rrr_cmodule_common_send_entry_to_fork_nolock (
			&input_count,
			thread_data,
			callback_data->pid,
			entry
	);

	if (ret != 0) {
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}

	callback_data->count += input_count;

	if (callback_data->count > callback_data->max_count) {
		ret = RRR_FIFO_SEARCH_STOP;
	}

	out:
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int __rrr_cmodule_common_poll_delete (
		int *count,
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *poll,
		pid_t target_pid,
		int wait_ms,
		int max_count
) {
	int ret = 0;

	*count = 0;

	struct rrr_cmodule_common_poll_callback_data callback_data = {
		target_pid,
		0,
		max_count
	};

	thread_data->cmodule->callback_data_tmp = &callback_data;

	if (rrr_poll_do_poll_delete (thread_data, poll, __rrr_cmodule_common_poll_callback, wait_ms) != 0) {
		RRR_MSG_ERR("Error while polling in instance %s\n",
			INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	*count = callback_data.count;
	return ret;
}

void rrr_cmodule_common_loop (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_stats_instance *stats,
		struct rrr_poll_collection *poll,
		pid_t fork_pid,
		int no_polling
) {
	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	int usleep_hits = 0;
	int from_senders_counter = 0;
	int from_child_counter = 0;

	int config_check_complete = 0;
	int config_check_complete_message_printed = 0;

	int tick = 0;
	int consecutive_nothing_happend = 0;
	uint64_t next_stats_time = 0;
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1 && fork_pid != 0) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		int from_fork_count = 0;
		if (__rrr_cmodule_common_read_from_forks (
				&from_fork_count,
				&config_check_complete,
				thread_data,
				10
		) != 0) {
			RRR_MSG_ERR("Error while reading from child fork in instance %s\n",
				INSTANCE_D_NAME(thread_data));
			break;
		}

		if (config_check_complete == 1 && config_check_complete_message_printed == 0) {
			RRR_DBG_1("Instance %s child config function (if any) complete, checking for unused values\n",
					INSTANCE_D_NAME(thread_data));
			rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);
			config_check_complete_message_printed = 1;
		}

		int input_count = 0;
		if (no_polling == 0) {
			if (__rrr_cmodule_common_poll_delete (&input_count, thread_data, poll, fork_pid, 0, 50) != 0) {
				break;
			}
		}

		if (from_fork_count != 0 || input_count != 0) {
			consecutive_nothing_happend = 0;
		}

		if (++consecutive_nothing_happend > 1000) {
	//			printf ("Nothing happened  1 000: %i\n", consecutive_nothing_happend);
			rrr_posix_usleep(250); // 250 us
		}
		if (++consecutive_nothing_happend > 10000) {
	//			printf ("Nothing happened 10 000: %i\n", consecutive_nothing_happend);
			rrr_posix_usleep (50000); // 50 ms
			usleep_hits++;
		}

		from_child_counter += from_fork_count;
		from_senders_counter += input_count;

		uint64_t time_now = rrr_time_get_64();

		if (time_now > next_stats_time) {
			int output_buffer_count = 0;
			int output_buffer_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&output_buffer_count,
					&output_buffer_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_ERR("Error while setting ratelimit in instance %s\n",
					INSTANCE_D_NAME(thread_data));
				break;
			}

			rrr_stats_instance_update_rate(stats, 2, "usleep_hits", usleep_hits);
			rrr_stats_instance_update_rate(stats, 3, "ticks", tick);
			rrr_stats_instance_update_rate(stats, 5, "input_counter", from_senders_counter);
			rrr_stats_instance_update_rate(stats, 6, "from_child_counter", from_child_counter);
			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_count", 0, output_buffer_count);

			struct rrr_fifo_buffer_stats fifo_stats;
			if (rrr_message_broker_get_fifo_stats (&fifo_stats, INSTANCE_D_BROKER_ARGS(thread_data)) != 0) {
				RRR_MSG_ERR("Could not get output buffer stats in perl5 instance %s\n", INSTANCE_D_NAME(thread_data));
				break;
			}

			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_total", 0, fifo_stats.total_entries_written);

			usleep_hits = tick = from_senders_counter = from_child_counter = 0;

			next_stats_time = time_now + 1000000;

			rrr_cmodule_maintain(INSTANCE_D_FORK(thread_data));
		}

		tick++;
	}

	if (config_check_complete == 0) {
		RRR_MSG_0("Warning: Instance %s never completed configuration function\n",
				INSTANCE_D_NAME(thread_data));
	}
}
