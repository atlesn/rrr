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

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/linked_list.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/message_addr.h"
#include "../lib/modules.h"
#include "../lib/poll_helper.h"
#include "../lib/threads.h"
#include "../lib/perl5.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../lib/rrr_strerror.h"
#include "../lib/rrr_socket_msg.h"
#include "../lib/common.h"
#include "../lib/stats_instance.h"
#include "../lib/mmap_channel.h"
#include "../lib/rrr_mmap.h"
#include "../lib/rrr_socket.h"
#include "../lib/message_broker.h"
#include "../lib/fork.h"
#include "../lib/log.h"

#include <EXTERN.h>
#include <perl.h>

#define PERL5_DEFAULT_SOURCE_INTERVAL_MS 1000
#define PERL5_CHILD_MAX_IN_FLIGHT 100
#define PERL5_CHILD_MAX_IN_BUFFER (PERL5_CHILD_MAX_IN_FLIGHT * 10)
#define PERL5_MMAP_SIZE (1024*1024*2)

struct perl5_data {
	struct rrr_instance_thread_data *thread_data;

	struct rrr_ip_buffer_entry_collection input_buffer_ip;

	struct cmd_argv_copy *cmdline;

	// Protects the pid, accessed from many contexes
	pthread_mutex_t child_mutex;
	pid_t child_pid_;

	uint64_t spawn_interval_ms;

	char *perl5_file;
	char *source_sub;
	char *process_sub;
	char *config_sub;

	int do_drop_on_error;

	struct rrr_message_addr latest_message_addr;

	int mmap_full_counter;

	struct rrr_mmap *mmap;
	struct rrr_mmap_channel *channel_to_child;
	struct rrr_mmap_channel *channel_from_child;
};

struct perl5_child_deferred_message {
	RRR_LL_NODE(struct perl5_child_deferred_message);
	struct rrr_message *msg;
	struct rrr_message_addr *msg_addr;
};

struct perl5_child_deferred_message_collection {
	RRR_LL_HEAD(struct perl5_child_deferred_message);
};

int deferred_message_destroy (struct perl5_child_deferred_message *msg) {
	RRR_FREE_IF_NOT_NULL(msg->msg);
	RRR_FREE_IF_NOT_NULL(msg->msg_addr);
	free(msg);
	return 0;
}

int deferred_message_push (struct perl5_child_deferred_message_collection *collection, struct rrr_message *msg, struct rrr_message_addr *msg_addr) {
	struct perl5_child_deferred_message *node = NULL;

	if ((node = malloc(sizeof(*node))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in perl5 deferred_message_push\n");
		return 1;
	}
	memset(node, '\0', sizeof(*node));
	node->msg = msg;
	node->msg_addr = msg_addr;
	RRR_LL_APPEND(collection, node);
	return 0;
}

struct perl5_child_data {
	struct perl5_data *parent_data;
	int child_fd;
	int received_sigusr1;
	struct rrr_perl5_ctx *ctx;
	struct rrr_message_addr latest_message_addr;
	struct perl5_child_deferred_message_collection deferred_messages;
//	struct rrr_fifo_buffer from_parent_buffer;
	uint64_t total_msg_mmap_from_parent;
	uint64_t total_msg_processed;
	uint64_t total_msg_deferred;
};

int perl5_child_data_init (struct perl5_child_data *data) {
	memset(data, '\0', sizeof(*data));
	return 0;
}

void perl5_child_data_cleanup (struct perl5_child_data *data) {
	// Since we are the writer, we must free the SHM blocks. Parent process
	// calls destroy()
//	printf("CHILD DATA BEFORE CLEANUP ========================\n");
//	rrr_mmap_dump_indexes(data->parent_data->channel_from_child->mmap);
//	printf("=================================================\n");

	rrr_mmap_channel_writer_free_blocks(data->parent_data->channel_from_child);

//	printf("CHILD DATA AFTER CLEANUP ========================\n");
//	rrr_mmap_dump_indexes(data->parent_data->channel_from_child->mmap);
//	printf("=================================================\n");
}

struct mmap_channel_callback_data {
	const struct rrr_message_addr *addr_msg;
	const struct rrr_message *msg;
};

int mmap_channel_write_callback (void *target, void *arg) {
	struct mmap_channel_callback_data *data = arg;

	void *msg_pos = target;
	void *msg_addr_pos = target + MSG_TOTAL_SIZE(data->msg);

	memcpy(msg_pos, data->msg, MSG_TOTAL_SIZE(data->msg));
	memcpy(msg_addr_pos, data->addr_msg, sizeof(*(data->addr_msg)));

	return 0;
}

static int xsub_send_message (
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr,
		void *private_data
) {
	struct perl5_child_data *child_data = private_data;
	int ret = 0;

	struct rrr_message_addr *msg_addr_tmp_dynamic = NULL;
	struct rrr_message_addr msg_addr_tmp = *message_addr;

	struct mmap_channel_callback_data callback_data = {
		&msg_addr_tmp,
		message
	};

	child_data->total_msg_processed++;

	if ((ret = rrr_mmap_channel_write_using_callback (
			child_data->parent_data->channel_from_child,
			MSG_TOTAL_SIZE(message) + sizeof(msg_addr_tmp),
			mmap_channel_write_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			goto out_defer;
		}
		RRR_MSG_ERR("Could not send address message on memory map channel in xsub_send_message_addr of perl5 instance %s.\n",
				INSTANCE_D_NAME(child_data->parent_data->thread_data));
		ret = 1;
		goto out;
	}

	goto out;

	out_defer:
		if ((msg_addr_tmp_dynamic = malloc(sizeof(*msg_addr_tmp_dynamic))) == NULL) {
			RRR_MSG_ERR("Could not allocate memory in xsub_send_message_addr\n");
			ret = 1;
			goto out;
		}

		*msg_addr_tmp_dynamic = msg_addr_tmp;

		if (deferred_message_push(&child_data->deferred_messages, message, msg_addr_tmp_dynamic) != 0) {
			RRR_MSG_ERR("Error while pushing deferred message in perl5 xsub_send_message\n");
			ret = 1;
			goto out;
		}
		msg_addr_tmp_dynamic = NULL;
		message = NULL;
		child_data->total_msg_deferred++;

	out:
		RRR_FREE_IF_NOT_NULL(msg_addr_tmp_dynamic);
		RRR_FREE_IF_NOT_NULL(message);
		return ret;
}

static char *xsub_get_setting(const char *key, void *private_data) {
	struct perl5_child_data *perl5_child_data = private_data;
	struct rrr_instance_settings *settings = perl5_child_data->parent_data->thread_data->init_data.instance_config->settings;

	char *value = NULL;
	if (rrr_settings_get_string_noconvert_silent(&value, settings, key)) {
		RRR_MSG_ERR("Warning: Setting '%s', requested by perl5 program in instance %s, could not be retrieved\n",
				key, INSTANCE_D_NAME(perl5_child_data->parent_data->thread_data));
		return NULL;
	}

	return value;
}

static int xsub_set_setting(const char *key, const char *value, void *private_data) {
	struct perl5_child_data *perl5_child_data = private_data;
	struct rrr_instance_settings *settings = perl5_child_data->parent_data->thread_data->init_data.instance_config->settings;

	int ret = rrr_settings_replace_string(settings, key, value);
	if (ret != 0) {
		RRR_MSG_ERR("Could not update settings key '%s' as requested by perl5 program in instance %s\n",
				key, INSTANCE_D_NAME(perl5_child_data->parent_data->thread_data));
	}

	return ret;
}

int preload_perl5 (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = (struct rrr_instance_thread_data *) thread->private_data;

	int ret = 0;

	struct cmd_argv_copy *cmdline;
	cmd_get_argv_copy(&cmdline, thread_data->init_data.cmd_data);

	if ((ret = rrr_perl5_init3(cmdline->argc, cmdline->argv, NULL)) != 0) {
		RRR_MSG_ERR("Could not initialize perl5 in preload_perl5 instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_cmdline;
	}

	out_destroy_cmdline:
	cmd_destroy_argv_copy(cmdline);

	return ret;
}

int data_init(struct perl5_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	if (rrr_mmap_new(&data->mmap, PERL5_MMAP_SIZE) != 0) {
		RRR_MSG_ERR("Could not allocate mmap in perl5\n");
		ret = 1;
		goto out;
	}

	if (rrr_mmap_channel_new(&data->channel_from_child, data->mmap) != 0) {
		RRR_MSG_ERR("Could not allocate mmap channel in perl5\n");
		ret = 1;
		goto out_destroy_mmap;
	}

	if (rrr_mmap_channel_new(&data->channel_to_child, data->mmap) != 0) {
		RRR_MSG_ERR("Could not allocate mmap channel in perl5\n");
		ret = 1;
		goto out_destroy_channel_from_child;
	}

	if (pthread_mutex_init (&data->child_mutex, NULL) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in perl5\n");
		ret = 1;
		goto out_destroy_channel_to_child;
	}

	cmd_get_argv_copy(&data->cmdline, thread_data->init_data.cmd_data);

	goto out;

//	out_destroy_mutex:
//		pthread_mutex_destroy(&data->child_mutex);
	out_destroy_channel_to_child:
		rrr_mmap_channel_destroy(data->channel_to_child);
	out_destroy_channel_from_child:
		rrr_mmap_channel_destroy(data->channel_from_child);
	out_destroy_mmap:
		rrr_mmap_destroy(data->mmap);
	out:
		return ret;
}

int perl5_start(struct perl5_child_data *data) {
	int ret = 0;

	ret |= rrr_perl5_new_ctx (
			&data->ctx,
			data,
			xsub_send_message,
			xsub_get_setting,
			xsub_set_setting
	);

	if (ret != 0) {
		RRR_MSG_ERR("Could not create perl5 context in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	RRR_DBG_1 ("perl5 instance %s starting perl5 interpreter pointer %p\n",
			INSTANCE_D_NAME(data->parent_data->thread_data), data->ctx->interpreter);

	ret |= rrr_perl5_ctx_parse(data->ctx, data->parent_data->perl5_file);

	if (ret != 0) {
		RRR_MSG_ERR("Could not parse perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_ctx_run(data->ctx);

	if (ret != 0) {
		RRR_MSG_ERR("Could not run perl5 file in perl5_start of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		goto out;
	}

	out:
	// Everything is cleaned up my perl5_stop, also in case of errors
	return ret;
}

#define CHILD_PID_LOCK_IN						\
	do {pthread_mutex_lock(&data->child_mutex);	\
	if (data->child_pid_ <= 0)					\
		goto out_unlock							\

#define CHILD_PID_LOCK_OUT						\
	pthread_mutex_unlock(&data->child_mutex);	\
	} while(0)

void terminate_child (struct perl5_data *data) {
	// Just do our ting disregarding return values
	pid_t pid = 0;

	CHILD_PID_LOCK_IN;
		pid = data->child_pid_;
		data->child_pid_ = 0;
	CHILD_PID_LOCK_OUT;

	RRR_DBG_1("perl5 instance %s SIGUSR1 to child process %i\n",
			INSTANCE_D_NAME(data->thread_data), pid);
	kill(pid, SIGUSR1);

	usleep(100000); // 100 ms

	RRR_DBG_1("perl5 instance %s SIGKILL to child process %i\n",
			INSTANCE_D_NAME(data->thread_data), pid);
	kill(pid, SIGKILL);

	goto out;
	out_unlock:
		pthread_mutex_unlock(&data->child_mutex);
	out:
		return;
}

void data_cleanup(void *arg) {
	struct perl5_data *data = arg;

	rrr_ip_buffer_entry_collection_clear(&data->input_buffer_ip);

	RRR_FREE_IF_NOT_NULL(data->perl5_file);
	RRR_FREE_IF_NOT_NULL(data->source_sub);
	RRR_FREE_IF_NOT_NULL(data->process_sub);
	RRR_FREE_IF_NOT_NULL(data->config_sub);

	terminate_child(data);

	if (data->channel_from_child != NULL) {
		// Don't free blocks SHM blocks, child as the writer does that
		rrr_mmap_channel_destroy(data->channel_from_child);
	}
	if (data->channel_to_child != NULL) {
		// Since we are the writer, we must free the SHM blocks
//		printf("PARENT DATA BEFORE CLEANUP =======================\n");
//		rrr_mmap_dump_indexes(data->channel_to_child->mmap);
//		printf("=================================================\n");

		rrr_mmap_channel_writer_free_blocks(data->channel_to_child);

//		printf("PARENT DATA AFTER CLEANUP =======================\n");
//		rrr_mmap_dump_indexes(data->channel_to_child->mmap);
//		printf("=================================================\n");

		rrr_mmap_channel_destroy(data->channel_to_child);
	}
	if (data->mmap != NULL) {
		rrr_mmap_destroy(data->mmap);
	}

	cmd_destroy_argv_copy(data->cmdline);
	pthread_mutex_destroy(&data->child_mutex);
}

int parse_config(struct perl5_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	ret = rrr_instance_config_get_string_noconvert_silent (&data->perl5_file, config, "perl5_file");

	if (ret != 0) {
		RRR_MSG_ERR("No perl5_file specified for perl5 instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_instance_config_get_string_noconvert_silent (&data->source_sub, config, "perl5_source_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->process_sub, config, "perl5_process_sub");
	rrr_instance_config_get_string_noconvert_silent (&data->config_sub, config, "perl5_config_sub");

	if (data->source_sub == NULL && data->process_sub == NULL) {
		RRR_MSG_ERR("No source or processor sub defined for perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_setting_uint uint_tmp = 0;
	if ((ret = rrr_instance_config_read_unsigned_integer(&uint_tmp, config, "perl5_source_interval")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error in setting perl5_source_interval of perl5 instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else {
			uint_tmp = PERL5_DEFAULT_SOURCE_INTERVAL_MS;
		}
		ret = 0;
	}
	else {
		if (data->source_sub == NULL) {
			RRR_MSG_ERR("perl5_source_interval of perl5 instance %s was set but no source function was defined with perl5_source_sub\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->spawn_interval_ms = uint_tmp;

	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("perl5_drop_on_error", do_drop_on_error, 0);

	out:
	return ret;
}

int worker_spawn_message(struct perl5_child_data *child_data) {
	int ret = 0;

	struct rrr_message *message = NULL;

	struct perl5_data *data = child_data->parent_data;
	struct rrr_perl5_ctx *ctx = child_data->ctx;

	struct rrr_perl5_message_hv *hv_message = rrr_perl5_allocate_message_hv(ctx);

	uint64_t now_time = rrr_time_get_64();

	if (rrr_message_new_empty (
			&message,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			now_time,
			0,
			0
	) != 0) {
		RRR_MSG_ERR("Could not initialize message in perl5 worker_spawn_messages of instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_perl5_message_to_hv(hv_message, ctx, message, NULL);
	rrr_perl5_call_blessed_hvref(ctx, data->source_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);

	out:
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int worker_process_message (
		struct perl5_child_data *child_data,
		const struct rrr_message *message,
		struct rrr_message_addr *message_addr
) {
	int ret = 0;

	struct perl5_data *data = child_data->parent_data;
	struct rrr_perl5_ctx *ctx = child_data->ctx;

	struct rrr_perl5_message_hv *hv_message = NULL;

	ret |= rrr_perl5_message_to_new_hv(&hv_message, ctx, message, message_addr);
	if (ret != 0) {
		RRR_MSG_ERR("Could not create rrr_perl5_message_hv struct in worker_process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	ret |= rrr_perl5_call_blessed_hvref(ctx, data->process_sub, "rrr::rrr_helper::rrr_message", hv_message->hv);
	if (ret != 0) {
		RRR_MSG_ERR("Could not call process function in worker_process_message of perl5 instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	rrr_perl5_destruct_message_hv (ctx, hv_message);
	return ret;

}

int perl5_input_callback (int *count, struct perl5_data *perl5_data, struct rrr_ip_buffer_entry *entry) {
	struct rrr_instance_thread_data *thread_data = perl5_data->thread_data;

	struct rrr_message *message = (struct rrr_message *) entry->message;
	struct rrr_message_addr addr_msg;
	int ret = 0;

	RRR_ASSERT(sizeof(addr_msg.addr) == sizeof(entry->addr), message_addr_and_ip_buffer_entry_addr_differ);

	if ((*count) > 10) {
		goto out_put_back;
	}

//	printf ("perl5_input_callback: message %p\n", message);

	rrr_message_addr_init(&addr_msg);
	if (entry->addr_len > 0) {
		memcpy(&addr_msg.addr, &entry->addr, sizeof(addr_msg.addr));
		RRR_MSG_ADDR_SET_ADDR_LEN(&addr_msg, entry->addr_len);
	}

	struct mmap_channel_callback_data channel_callback_data = {
			&addr_msg,
			message
	};

	if ((ret = rrr_mmap_channel_write_using_callback (
			perl5_data->channel_to_child,
			sizeof(addr_msg) + MSG_TOTAL_SIZE(message),
			mmap_channel_write_callback,
			&channel_callback_data
	)) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			perl5_data->mmap_full_counter++;
			ret = 0;
			goto out_put_back;
		}
		RRR_MSG_ERR("Passing message to perl5 instance %s fork using memory map failed.\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	(*count)++;

	goto out;
	out_put_back:
		// Since we are in read_clear_forward-context, the whole buffer is empty at this point. The
		// current message will be written at the beginning at the buffer, and any remaining messages
		// will be joined in after it.
//		printf ("perl5_input_callback: putback message %p\n", entry->message);
		rrr_ip_buffer_entry_incref_while_locked(entry);
		RRR_LL_APPEND(&perl5_data->input_buffer_ip, entry);
	out:
		rrr_ip_buffer_entry_unlock(entry);
		return ret;
}

int perl5_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct perl5_data *perl5_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) entry->message;

	RRR_DBG_3 ("perl5 instance %s Result from buffer ip addr len %u: timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), entry->addr_len, message->timestamp);

//	printf ("perl5_poll_callback: put message %p\n", entry->message);

	rrr_ip_buffer_entry_incref_while_locked(entry);
	RRR_LL_APPEND(&perl5_data->input_buffer_ip, entry);

	rrr_ip_buffer_entry_unlock(entry);

	return 0;
}

int send_config(struct perl5_child_data *child_data) {
	int ret = 0;

	struct perl5_data *data = child_data->parent_data;

	struct rrr_instance_settings *settings = data->thread_data->init_data.instance_config->settings;
	struct rrr_perl5_settings_hv *settings_hv = NULL;

	if (data->config_sub == NULL || *(data->config_sub) == '\0') {
		goto out;
	}

	if ((ret = rrr_perl5_settings_to_hv(&settings_hv, child_data->ctx, settings)) != 0) {
		RRR_MSG_ERR("Could not convert settings of perl5 instance %s to hash value\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_perl5_call_blessed_hvref(
			child_data->ctx,
			data->config_sub,
			"rrr::rrr_helper::rrr_settings",
			settings_hv->hv
	)) != 0) {
		RRR_MSG_ERR("Error while sending settings to sub %s in perl5 instance %s\n",
				data->config_sub, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	rrr_perl5_destruct_settings_hv(child_data->ctx, settings_hv);
	return ret;
}

struct child_read_callback_data {
	struct perl5_child_data *data;
};

int worker_socket_read_callback_msg (const struct rrr_message *message, void *arg) {
	struct child_read_callback_data *callback_data = arg;
	struct perl5_child_data *data = callback_data->data;

	int ret = 0;

	if ((ret = worker_process_message(data, message, &data->latest_message_addr)) != 0) {
		RRR_MSG_ERR("Error from message processing in perl5 child fork of instance %s\n",
				INSTANCE_D_NAME(data->parent_data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	memset(&data->latest_message_addr, '\0', sizeof(data->latest_message_addr));
	return ret;
}

int worker_socket_read_callback_addr_msg (const struct rrr_message_addr *message, void *arg) {
	struct child_read_callback_data *callback_data = arg;
	struct perl5_child_data *data = callback_data->data;

//	printf ("worker_socket_read_callback_addr_msg addr len: %" PRIu64 "\n", message->addr_len);

	int ret = 0;
	data->latest_message_addr = *message;

	return ret;
}

int worker_fork_mmap_channel_read_callback (const void *data, size_t data_size, void *arg) {
	struct child_read_callback_data *callback_data = arg;

	const struct rrr_message *msg = data;
	const struct rrr_message_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

//	printf ("worker fork mmap read ptr %p data size %li\n", msg, data_size);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in worker_fork_mmap_channel_read_callback %i+%lu != %lu\n",
				MSG_TOTAL_SIZE(msg), sizeof(*msg_addr), data_size);
	}

	callback_data->data->latest_message_addr = *msg_addr;
	callback_data->data->total_msg_mmap_from_parent++;

	return worker_socket_read_callback_msg(msg, arg);
}

int worker_fork_loop (struct perl5_child_data *child_data) {
	int ret = 0;

	if (preload_perl5 (child_data->parent_data->thread_data->thread) != 0) {
		RRR_MSG_ERR("Could not preload perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data->parent_data->thread_data));
		ret = 1;
		goto out_final;
	}

	if (perl5_start(child_data) != 0) {
		RRR_MSG_ERR("Could not compile and start perl5 in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data->parent_data->thread_data));
		ret = 1;
		goto out_sys_term;
	}

	if (send_config(child_data) != 0) {
		RRR_MSG_ERR("Could not send config to perl5 program in child fork of instance %s\n",
				INSTANCE_D_NAME(child_data->parent_data->thread_data));
		ret = 1;
		goto out_destroy_ctx;
	}

	// Read stuff
	int no_spawning = (child_data->parent_data->source_sub == NULL || *(child_data->parent_data->source_sub) == '\0' ? 1 : 0);

	struct child_read_callback_data callback_data = {
			child_data
	};

	// Control stuff
	uint64_t time_now = rrr_time_get_64();
	uint64_t next_spawn_time = 0;
	uint64_t spawn_interval_us = child_data->parent_data->spawn_interval_ms * 1000;
	uint64_t sleep_interval_us = 10 * 1000;

	if (sleep_interval_us > spawn_interval_us) {
		sleep_interval_us = spawn_interval_us;
	}

	int usleep_hits_a = 0;
	int usleep_hits_b = 0;

	uint64_t prev_total_processed_msg = 0;
	uint64_t prev_total_msg_mmap_from_parent = 0;
	int consecutive_nothing_happend = 0;

	uint64_t prev_stats_time = 0;

	while (child_data->received_sigusr1 == 0) {
		// Check for backlog on the socket. Don't process any more messages untill backlog is cleared up
		if (RRR_LL_COUNT(&child_data->deferred_messages) > 0) {
			usleep_hits_a++;
			usleep(5000); // 5 ms
			// Stop other sleep from running
			consecutive_nothing_happend = 0;
			RRR_LL_ITERATE_BEGIN(&child_data->deferred_messages, struct perl5_child_deferred_message);
				struct mmap_channel_callback_data channel_callback_data = {
						node->msg_addr,
						node->msg
				};
				if ((ret = rrr_mmap_channel_write_using_callback (
						child_data->parent_data->channel_from_child,
						sizeof(*(node->msg_addr)) + MSG_TOTAL_SIZE(node->msg),
						mmap_channel_write_callback,
						&channel_callback_data
				)) != 0) {
//					RRR_DBG_1("Note: Write to mmap channel failed in perl5 child fork of instance %s\n",
//							INSTANCE_D_NAME(child_data->parent_data->thread_data));
					RRR_LL_ITERATE_LAST();
				}
				else {
					RRR_LL_ITERATE_SET_DESTROY();
				}
			RRR_LL_ITERATE_END_CHECK_DESTROY(&child_data->deferred_messages, deferred_message_destroy(node));

			if (ret == 1) {
				break;
			}

			ret = 0;
			// Go to the top again in case there are more deferred messages
			continue;
		}

		time_now = rrr_time_get_64();

		if (next_spawn_time == 0) {
			next_spawn_time = time_now + spawn_interval_us;
		}

		for (int i = 0; i < 10; i++) {
			if ((ret = rrr_mmap_channel_read_all (
					child_data->parent_data->channel_to_child,
					worker_fork_mmap_channel_read_callback,
					&callback_data
			)) != 0) {
				if (ret != RRR_MMAP_CHANNEL_EMPTY) {
					RRR_MSG_ERR("Error from mmap read function in child fork of perl5 instance %s\n",
							INSTANCE_D_NAME(child_data->parent_data->thread_data));
					ret = 1;
					break;
				}
			}
			if (prev_total_msg_mmap_from_parent == child_data->total_msg_mmap_from_parent) {
				break;
			}
		}

		if (no_spawning == 0 && time_now >= next_spawn_time) {
			if (worker_spawn_message(child_data) != 0) {
				break;
			}
			next_spawn_time = 0;
		}

		if (	prev_total_msg_mmap_from_parent != child_data->total_msg_mmap_from_parent ||
				prev_total_processed_msg != child_data->total_msg_processed
		) {
			consecutive_nothing_happend = 0;
		}

		if (++consecutive_nothing_happend > 250) {
			usleep_hits_b++;
			usleep(sleep_interval_us);
//			if (usleep_hits_b % 10 == 0) {
//				printf("usleep hits child: %i/%i\n", usleep_hits_a, usleep_hits_b);
//			}
		}

		if (time_now - prev_stats_time > 1000000) {
//			printf("child total processed %" PRIu64 " total from parent %" PRIu64 " total deferred %" PRIu64 "\n",
//					child_data->total_msg_processed, child_data->total_msg_mmap_from_parent, child_data->total_msg_deferred);
			prev_stats_time = time_now;
		}

		prev_total_processed_msg = child_data->total_msg_processed;
		prev_total_msg_mmap_from_parent = child_data->total_msg_mmap_from_parent;
	}

	RRR_DBG_1("perl5 instance %s child worker loop complete, received_sigterm is %i ret is %i\n",
			INSTANCE_D_NAME(child_data->parent_data->thread_data),
			child_data->received_sigusr1,
			ret
	);

	out_destroy_ctx:
		rrr_perl5_destroy_ctx(child_data->ctx);
	out_sys_term:
		rrr_perl5_sys_term();
	out_final:
		RRR_LL_DESTROY(&child_data->deferred_messages, struct perl5_child_deferred_message, deferred_message_destroy(node));
		return ret;
}

int worker_fork_signal_handler (int signal, void *private_arg) {
	struct perl5_child_data *child_data = private_arg;

	if (signal == SIGUSR1 || signal == SIGINT) {
		RRR_DBG_1("perl5 child of instance %s received SIGUSR1 or SIGINT, stopping\n", INSTANCE_D_NAME(child_data->parent_data->thread_data));
		child_data->received_sigusr1 = 1;
	}

	return 0;
}

static void perl5_handle_sigchld (pid_t pid, void *arg) {
	struct perl5_data *data = arg;

	RRR_MSG_ERR("Child fork %i in perl5 instance %s exited\n",
			pid, INSTANCE_D_NAME(data->thread_data));

	pthread_mutex_lock(&data->child_mutex);
	pid = data->child_pid_;
	data->child_pid_ = 0;
	pthread_mutex_unlock(&data->child_mutex);
}

int start_worker_fork (struct perl5_data *data) {
	int ret = 0;

	pid_t pid = rrr_fork(INSTANCE_D_FORK(data->thread_data), perl5_handle_sigchld, data);

	if (pid < 0) {
		RRR_MSG_ERR("Could not fork in start_worker_fork of perl5 instance %s: %s\n",
				INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
		ret = 1;
		goto out_parent;
	}
	else if (pid > 0) {
		pthread_mutex_lock(&data->child_mutex);
		data->child_pid_ = pid;
		pthread_mutex_unlock(&data->child_mutex);
		RRR_DBG_1 ("=== FORK PID %i ========================================================================================\n", pid);
		goto out_parent;
	}

	// CHILD PROCESS CODE
	rrr_socket_close_all_no_unlink();

	struct perl5_child_data child_data;

	if (perl5_child_data_init(&child_data) != 0) {
		RRR_MSG_ERR("Could not initialize child data in start_worker_fork\n");
		ret = 1;
		goto out_child_error;
	}

	child_data.parent_data = data;

	rrr_signal_handler_remove_all();
	rrr_signal_handler_push(worker_fork_signal_handler, &child_data);

	RRR_DBG_1("perl5 instance %s forked, starting child worker loop\n", INSTANCE_D_NAME(data->thread_data));

	ret = worker_fork_loop(&child_data);

	perl5_child_data_cleanup(&child_data);

	out_child_error:
	RRR_DBG_1("perl5 instance %s child worker loop returned %i\n", INSTANCE_D_NAME(data->thread_data), ret);

	exit(ret);

	out_parent:
		return ret;
}

struct read_callback_data {
	struct perl5_data *data;
	int count;
	const struct rrr_message *message;
};

int read_from_child_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct read_callback_data *callback_data = arg;
	struct perl5_data *data = callback_data->data;

	int ret = 0;

	struct rrr_message *message_new = rrr_message_duplicate(callback_data->message);
	if (message_new == NULL) {
		RRR_MSG_ERR("Could not duplicate message in perl5 read_from_child_callback\n");
		ret = 1;
		goto out;
	}

//	printf ("read_from_child_callback_msg addr len: %" PRIu64 "\n", data->latest_message_addr.addr_len);

	// TODO : Look into warning "taking address of packed member of blabla latest_message_addr.addr"
	rrr_ip_buffer_entry_set_unlocked (
			entry,
			message_new,
			MSG_TOTAL_SIZE(message_new),
			(struct sockaddr *) &data->latest_message_addr.addr,
			RRR_MSG_ADDR_GET_ADDR_LEN(&data->latest_message_addr),
			data->latest_message_addr.protocol
	);
	message_new = NULL;

	callback_data->count++;

	out:
	RRR_FREE_IF_NOT_NULL(message_new);
	memset(&data->latest_message_addr, '\0', sizeof(data->latest_message_addr));
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

int read_from_child_mmap_channel_callback (const void *data, size_t data_size, void *arg) {
	struct read_callback_data *callback_data = arg;

	const struct rrr_message *msg = data;
	const struct rrr_message_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in read_from_child_mmap_channel_callback %i+%lu != %lu\n",
				MSG_TOTAL_SIZE(msg), sizeof(*msg_addr), data_size);
	}

	callback_data->data->latest_message_addr = *msg_addr;

	callback_data->message = msg;

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->data->thread_data),
			NULL,
			0,
			0,
			read_from_child_callback,
			callback_data
	) != 0) {
		RRR_MSG_ERR("Could to write to output buffer in perl5 instance %s\n",
				INSTANCE_D_NAME(callback_data->data->thread_data));
		return 1;
	}

	return 0;
}

int read_from_child_fork(int *read_count, struct perl5_data *data) {
	int ret = 0;

	*read_count = 0;

	struct read_callback_data callback_data = {
			data,
			0,
			NULL
	};

	for (int i = 0; i < 10; i++) {
		int prev_count = callback_data.count;
		if ((ret = rrr_mmap_channel_read_all (
				data->channel_from_child,
				read_from_child_mmap_channel_callback,
				&callback_data
		)) != 0) {
			if (ret == RRR_MMAP_CHANNEL_EMPTY) {
				ret = 0;
				break;
			}
			else {
				RRR_MSG_ERR("Error while reading from child mmap channel in perl5 instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				ret = 1;
				goto out;
			}
		}

		if (callback_data.count == prev_count) {
			break;
		}
	}

	out:
	*read_count = callback_data.count;
	return ret;
}

static void *thread_entry_perl5(struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll_ip;
	struct rrr_ip_buffer_entry_collection input_buffer_tmp = {0};

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initialize data in buffer instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	struct rrr_fork_unregister_exit_handler_data fork_unregister_data = {
			INSTANCE_D_FORK(thread_data), &data->child_pid_
	};

	rrr_poll_collection_init(&poll_ip);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_ip_buffer_entry_collection_clear_void, &input_buffer_tmp);
	pthread_cleanup_push(rrr_fork_unregister_exit_handler_void, &fork_unregister_data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto out_message;
	}

	if (start_worker_fork(data) != 0) {
		RRR_MSG_ERR("Error while starting perl5 for for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING_FORKED);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders(&poll_ip, thread_data);
	int no_polling = 1;
	if (rrr_poll_collection_count (&poll_ip) > 0) {
		if (!data->process_sub) {
			RRR_MSG_ERR("Perl5 instance %s cannot have senders specified and no process function\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		no_polling = 0;
	}

	RRR_DBG_1 ("perl5 instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	int usleep_hits_a = 0;
	int usleep_hits_b = 0;
	int input_counter = 0;
	int from_child_counter = 0;

	int tick = 0;
	int consecutive_nothing_happend = 0;
	uint64_t next_stats_time = 0;
	uint64_t next_bubblesort_time = 0;
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1 && data->child_pid_ != 0) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		int read_count = 0;
		// This will accept connection from child
		if (read_from_child_fork(&read_count, data) != 0) {
			break;
		}

		int input_count = 0;
		if (RRR_LL_COUNT(&data->input_buffer_ip) > 0) {
			int prev_mmap_full_counter = data->mmap_full_counter;

			RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&input_buffer_tmp, &data->input_buffer_ip);

			// Callback might add entries back into input buffer
			RRR_LL_ITERATE_BEGIN(&input_buffer_tmp, struct rrr_ip_buffer_entry);
				rrr_ip_buffer_entry_lock(node);

				int old_count = input_count;

				int ret_tmp = perl5_input_callback(&input_count, data, node);
				if (ret_tmp != 0) {
					rrr_ip_buffer_entry_unlock(node);
					RRR_LL_ITERATE_BREAK();
				}

				RRR_LL_ITERATE_SET_DESTROY();

				if (old_count == input_count) {
					RRR_LL_ITERATE_LAST();
				}
			RRR_LL_ITERATE_END_CHECK_DESTROY(&input_buffer_tmp, 0; rrr_ip_buffer_entry_decref_while_locked_and_unlock(node));

			RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&data->input_buffer_ip, &input_buffer_tmp);

			if (prev_mmap_full_counter != data->mmap_full_counter) {
				consecutive_nothing_happend = 0;
				usleep(5000); // 5 ms
				usleep_hits_a++;
			}
		}
		else if (no_polling == 0) {
			if (rrr_poll_do_poll_delete (thread_data, &poll_ip, perl5_poll_callback, 0) != 0) {
				break;
			}
		}

		if (read_count != 0 || input_count != 0) {
			consecutive_nothing_happend = 0;
		}

		if (++consecutive_nothing_happend > 1000) {
//			printf ("Nothing happened  1 000: %i\n", consecutive_nothing_happend);
			usleep(250); // 250 us
		}
		if (++consecutive_nothing_happend > 10000) {
//			printf ("Nothing happened 10 000: %i\n", consecutive_nothing_happend);
			usleep (50000); // 50 ms
			usleep_hits_b++;
		}

		from_child_counter += read_count;
		input_counter += input_count;

		uint64_t time_now = rrr_time_get_64();

		if (time_now > next_bubblesort_time) {
			// Speed up memory access. Sorting is usually only performed
			// when the first few thousand messages are received, after that
			// no sorting is needed.
			int was_sorted = 0;
			int max_rounds = 100;
			do {
				rrr_mmap_channel_bubblesort_pointers (data->channel_to_child, &was_sorted);
			} while (was_sorted == 0 && --max_rounds > 0);
			next_bubblesort_time = time_now + 500000; // 500ms
		}

		if (time_now > next_stats_time) {
			int output_buffer_count = 0;
			int output_buffer_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&output_buffer_count,
					&output_buffer_ratelimit_active,
					thread_data
			) != 0) {
				break;
			}

			rrr_stats_instance_update_rate(stats, 1, "usleep_hits_a", usleep_hits_a);
			rrr_stats_instance_update_rate(stats, 2, "usleep_hits_b", usleep_hits_b);
			rrr_stats_instance_update_rate(stats, 3, "ticks", tick);
			rrr_stats_instance_update_rate(stats, 4, "mmap_to_child_full_hits", data->mmap_full_counter);
			rrr_stats_instance_update_rate(stats, 5, "input_counter", input_counter);
			rrr_stats_instance_update_rate(stats, 6, "from_child_counter", from_child_counter);
			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_count", 0, output_buffer_count);
			rrr_stats_instance_post_unsigned_base10_text(stats, "input_buffer_count", 0, RRR_LL_COUNT(&data->input_buffer_ip));

			struct rrr_fifo_buffer_stats fifo_stats;
			if (rrr_message_broker_get_fifo_stats (&fifo_stats, INSTANCE_D_BROKER_ARGS(thread_data)) != 0) {
				RRR_MSG_ERR("Could not get output buffer stats in perl5 instance %s\n", INSTANCE_D_NAME(thread_data));
				break;
			}

			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_total", 0, fifo_stats.total_entries_written);

			usleep_hits_a = usleep_hits_b = tick = input_counter = data->mmap_full_counter = from_child_counter = 0;

			next_stats_time = time_now + 1000000;

			rrr_fork_handle_sigchld_and_notify_if_needed(INSTANCE_D_FORK(thread_data));
		}

		tick++;
	}

	out_message:
	RRR_DBG_1 ("perl5 instance %s thread %p exiting\n", INSTANCE_D_NAME(thread_data), thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_exit(0);
}

static int test_config(struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

int perl5_cancel (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct perl5_data *data = thread_data->private_data = thread_data->private_memory;
	RRR_MSG_ERR("Perl5 instance %s terminating child pid %i (if any) in cancel function\n",
			INSTANCE_D_NAME(thread_data), data->child_pid_);
	terminate_child(data);
	pthread_cancel(thread->thread);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_perl5,
		NULL,
		test_config,
		NULL,
		perl5_cancel
};

static const char *module_name = "perl5";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->start_priority = RRR_THREAD_START_PRIORITY_FORK;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy perl5 module\n");
}

