/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "bridge.h"
#include "bridge_enc.h"
#include "bridge_task.h"
#include "bridge_conf.h"
#include "log.h"

#include "../allocator.h"
#include "../util/rrr_time.h"

static void __rrr_raft_bridge_ack_set_term (
		struct rrr_raft_bridge *bridge,
		raft_term term
) {
	bridge->metadata.version++;
	bridge->metadata.term = term;
	bridge->metadata.voted_for = 0;
}

static int __rrr_raft_bridge_ack_read_file (
		char **data,
		size_t *data_size,
		ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	ssize_t bytes;
	char buf[65536];
	char *result = NULL, *result_new;
	size_t result_size = 0, result_pos = 0;

	do {
		if ((bytes = read_cb(name, buf, sizeof(buf), cb_data)) < 0) {
			ret = 1;
			goto out;
		}
		else if (bytes > 0) {
			if (result_pos + bytes > result_size) {
				if ((result_new = rrr_reallocate(result, result_size + sizeof(buf))) == NULL) {
					RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
					ret = 1;
					goto out;
				}
				result_size += sizeof(buf);
				result = result_new;
			}
			memcpy(result + result_pos, buf, bytes);
			result_pos += bytes;
		}
	} while (bytes > 0);

	*data = result;
	*data_size = result_pos;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_raft_bridge_ack_read_metadata (
		struct rrr_raft_bridge_metadata *metadata,
		ssize_t (*read_cb)(RRR_RAFT_BRIDGE_READFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	char *data = NULL;
	size_t data_size;
	int ok;

	metadata->version = 0;
	metadata->term = 0;
	metadata->voted_for = 0;

	if ((ret = __rrr_raft_bridge_ack_read_file (&data, &data_size, read_cb, name, cb_data)) != 0) {
		goto out;
	}

	if (data_size == 0) {
		goto out;
	}

	if (!rrr_raft_bridge_decode_metadata_size_ok(data_size)) {
		RRR_MSG_0("Warning: Incorrect size %llu for metadata file '%s', ignoring it\n", (unsigned long long) data_size, name);
		goto out;
	}

	rrr_raft_bridge_decode_metadata(&ok, metadata, data, data_size);

	if (!ok) {
		RRR_MSG_0("Warning: Metadata file '%s' could not be decoded\n", name);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(data);
	return ret;
}

static int __rrr_raft_bridge_ack_write (
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		const char *data,
		size_t data_size,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	size_t pos;
	ssize_t bytes;

	for (pos = 0; pos < data_size; pos += bytes) {
		if ((bytes = write_cb(name, data + pos, data_size - pos, cb_data)) < 0) {
			ret = 1;
			goto out;
		}
		assert(bytes > 0);
	}

	assert(pos == data_size);

	if ((bytes = write_cb(name, NULL, 0, cb_data)) < 0) {
		ret = 1;
		goto out;
	}
	assert(bytes == 0);

	out:
	return ret;
}

static int __rrr_raft_bridge_ack_write_metadata (
		struct rrr_raft_bridge *bridge,
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	(void)(bridge);

	uint64_t data[4];

	rrr_raft_bridge_encode_metadata(data, &bridge->metadata);

	return __rrr_raft_bridge_ack_write(write_cb, name, (const char *) data, sizeof(data), cb_data);
}

static int __rrr_raft_bridge_ack_write_first_closed_segment_with_configuration (
		char **result_conf_data,
		size_t *result_conf_data_size,
		const struct raft_configuration *conf,
		ssize_t (*write_cb)(RRR_RAFT_BRIDGE_WRITEFILE_CB_ARGS),
		const char *name,
		struct rrr_raft_task_cb_data *cb_data
) {
	int ret = 0;

	char *conf_data = NULL, *data = NULL;
	size_t conf_data_size, data_size;

	if ((ret = rrr_raft_bridge_encode_configuration (
			&conf_data,
			&conf_data_size,
			conf
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_raft_bridge_encode_closed_segment (
			&data,
			&data_size,
			conf_data,
			conf_data_size,
			1
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_raft_bridge_ack_write (
			write_cb,
			name,
			data,
			data_size,
			cb_data
	)) != 0) {
		goto out;
	}

	*result_conf_data = conf_data;
	*result_conf_data_size = conf_data_size;
	conf_data = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(conf_data);
	RRR_FREE_IF_NOT_NULL(data);
	return ret;
}

static void __rrr_raft_bridge_ack_start (
		struct raft_event *event,
		struct rrr_raft_bridge *bridge,
		raft_term term,
		raft_index start_index,
		struct raft_entry *entries,
		unsigned entry_count
) {
	assert(!(bridge->state & RRR_RAFT_BRIDGE_STATE_STARTED));

	event->time = rrr_time_get_64() / 1000; 
	event->capacity = 0;
	event->type = RAFT_START;

	event->start.term = term;
	event->start.voted_for = 0;
	event->start.metadata = NULL;
	event->start.start_index = start_index;
	event->start.entries = entries;
	event->start.n_entries = entry_count;
}

static void __rrr_raft_bridge_ack_push_task_write_metadata (
		struct rrr_raft_task_list *list_new,
		const struct rrr_raft_bridge *bridge
) {
	struct rrr_raft_task task_new;

	task_new.type = RRR_RAFT_TASK_WRITE_FILE;
	task_new.writefile.type = RRR_RAFT_FILE_TYPE_METADATA;
	task_new.writefile.name = rrr_raft_task_list_strdup (
			list_new,
			RRR_RAFT_FILE_NAME_METADATA(bridge->metadata.version)
	);
	rrr_raft_task_list_push(list_new, &task_new);
}

static void __rrr_raft_bridge_ack_push_task_write_configuration (
		struct rrr_raft_task_list *list_new
) {
	struct rrr_raft_task task_new;

	task_new.type = RRR_RAFT_TASK_WRITE_FILE;
	task_new.writefile.type = RRR_RAFT_FILE_TYPE_CONFIGURATION;
	task_new.writefile.name = rrr_raft_task_list_asprintf (
			list_new,
			RRR_RAFT_FILE_ARGS_CLOSED_SEGMENT(1, 1)
	);
	rrr_raft_task_list_push(list_new, &task_new);
}

static int __rrr_raft_bridge_ack_update_commit_index (
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	raft_index commit_index, i;
	const struct raft_entry *entry;

	commit_index = raft_commit_index(bridge->raft);

	if (commit_index != 0 && commit_index == bridge->snapshot_index) {
		assert(0 && "Update commit index with index of snapshot not implemented");
	}

	RRR_RAFT_BRIDGE_DBG_ARGS("update commit index to %llu last applied is %llu",
		(unsigned long long) commit_index,
		(unsigned long long) bridge->last_applied
	);

	if (bridge->last_applied == commit_index) {
		goto out;
	}

	for (i = bridge->last_applied + 1; i <= commit_index; i++) {
		if ((entry = rrr_raft_log_get(&bridge->log, i)) == NULL) {
			// This can happen while installing a snapshot
			// TODO : Why??
			goto out;
		}

	}

	out:
	return ret;
}

static void __rrr_raft_bridge_ack_update_state (
		struct rrr_raft_bridge *bridge
) {
	assert(bridge->prev_state != raft_state(bridge->raft));

	if (bridge->prev_state == RAFT_LEADER) {
		assert(0 && "Not implemented: Fail pending requests, not leader anymore");
		// LegacyFailPendingRequests(r)
		assert(0 && "Not implemented: Assert that pending request queue is empty");
	}

	if (raft_state(bridge->raft) == RAFT_LEADER) {
		assert(bridge->change == NULL);
	}

	if (bridge->state & RRR_RAFT_BRIDGE_STATE_SHUTTING_DOWN) {
		assert(0 && "Not implemented: Close any active leadership transfer");
		// if(r->transfer != NULL) LegacyLeadershipTransferClose(r);
		assert(0 && "Not implemented: Fail pending requests");
		// LegacyFailPendingRequests(r)
		assert(0 && "Not implemented: Fire completed requests");
		// LegacyFireCompletedRequests(r)
	}

	RRR_RAFT_BRIDGE_DBG_ARGS("state change from %s to %s",
		raft_state_name(bridge->prev_state),
		raft_state_name(raft_state(bridge->raft))
	);

	bridge->prev_state = raft_state(bridge->raft);
}

static void __rrr_raft_bridge_ack_update_current_term (
		struct rrr_raft_task_list *list_new,
		struct rrr_raft_bridge *bridge
) {
	raft_term term;

	term = raft_current_term(bridge->raft);

	bridge->metadata.version++;
	bridge->metadata.term = term;
	bridge->metadata.voted_for = 0;

	RRR_RAFT_BRIDGE_DBG_ARGS("update current term to %llu version is now %llu",
		(unsigned long long) bridge->metadata.term,
		(unsigned long long) bridge->metadata.version
	);

	__rrr_raft_bridge_ack_push_task_write_metadata(list_new, bridge);
}

#define TASK_LIST_RESOLVE(handle) \
    (rrr_raft_task_list_resolve(list, handle))

int rrr_raft_bridge_acknowledge (
		struct rrr_raft_task_list *list,
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	int ret_tmp = 0;
	struct rrr_raft_task *task, *tasks, task_new;
	struct rrr_raft_task_list list_new = {0};
	//struct raft_event event;
	struct raft_event event;
	struct raft_entry entry;
	struct raft_update update;
	struct rrr_raft_bridge_metadata metadata1, metadata2;
	char *conf_data = NULL;
	size_t conf_data_size;

//	uint64_t now;

	assert(list->count > 0);

	tasks = rrr_raft_task_list_get(list);

//	now = rrr_time_get_64() / 1000;

	for (size_t i = 0; i < list->count; i++) {
		task = tasks + i;

		switch (task->type) {
			case RRR_RAFT_TASK_TIMEOUT:
			// TODO : Check for early timeout
/*				if (time < now) {
					RRR_RAFT_BRIDGE_DBG("early timeout, set again");
					__rrr_raft_task_list_push(&list_new, task);
					break;
				}
				else {*/
					RRR_RAFT_BRIDGE_DBG("timeout");
					event.type = RAFT_TIMEOUT;
					event.time = rrr_time_get_64() / 1000;
					goto step;
//				}
			case RRR_RAFT_TASK_READ_FILE:
				switch (task->readfile.type) {
					case RRR_RAFT_FILE_TYPE_METADATA:
						if (strcmp((char *) TASK_LIST_RESOLVE(task->readfile.name), "metadata1") == 0) {
							RRR_RAFT_BRIDGE_DBG("loading metadata1");

							if ((ret = __rrr_raft_bridge_ack_read_metadata (
									&metadata1,
									task->readfile.read_cb,
									"metadata1",
									&task->readfile.cb_data
							)) != 0) {
								goto out_cleanup;
							}
						}
						else {
							RRR_RAFT_BRIDGE_DBG("loading metadata2");

							if ((ret = __rrr_raft_bridge_ack_read_metadata (
									&metadata2,
									task->readfile.read_cb,
									"metadata2",
									&task->readfile.cb_data
							)) != 0) {
								goto out_cleanup;
							}

							if (metadata1.version == 0 && metadata2.version == 0) {
								bridge->metadata.version = 0;
								bridge->metadata.term = 0;
								bridge->metadata.voted_for = 0;
							}
							else if (metadata1.version == metadata2.version) {
								RRR_MSG_0("Both metadata1 and metadata2 contained the same version number\n");
								ret = 1;
								goto out_cleanup;
							}
							else {
								if (metadata1.version > metadata2.version) {
									bridge->metadata = metadata1;
								}
								else {
									bridge->metadata = metadata2;
								}

								RRR_RAFT_BRIDGE_DBG("metadata loaded");

								bridge->state |= RRR_RAFT_BRIDGE_STATE_CONFIGURED;
							}

							if (!(bridge->state & RRR_RAFT_BRIDGE_STATE_CONFIGURED)) {
								RRR_RAFT_BRIDGE_DBG("no metadata loaded, calling for bootstrap");

								task_new.type = RRR_RAFT_TASK_BOOTSTRAP;
								rrr_raft_task_list_push(&list_new, &task_new);
							}
							else {
								assert(0 && "Load configuration not implemented");
								// __rrr_raft_bridge_ack_start(&event, bridge);
								goto step;
							}
						}
						break;
					default:
						RRR_BUG("BUG: Unknown read file type %i in %s\n",
							task->readfile.type, __func__);
				};
				break;
			case RRR_RAFT_TASK_BOOTSTRAP:
				__rrr_raft_bridge_ack_set_term(bridge, 1);

				if ((ret = rrr_raft_bridge_configuration_clone(&bridge->configuration, task->bootstrap.configuration)) != 0) {
					goto out_cleanup;
				}

				__rrr_raft_bridge_ack_push_task_write_metadata(&list_new, bridge);
				__rrr_raft_bridge_ack_push_task_write_configuration(&list_new);

				break;
			case RRR_RAFT_TASK_WRITE_FILE:
				switch (task->writefile.type) {
					case RRR_RAFT_FILE_TYPE_METADATA:
						if ((ret = __rrr_raft_bridge_ack_write_metadata (
								bridge,
								task->writefile.write_cb,
								(char *) TASK_LIST_RESOLVE(task->writefile.name),
								&task->writefile.cb_data
						)) != 0) {
							goto out_cleanup;
						}
						break;
					case RRR_RAFT_FILE_TYPE_CONFIGURATION:
						assert(conf_data == NULL);
						if ((ret = __rrr_raft_bridge_ack_write_first_closed_segment_with_configuration (
								&conf_data,
								&conf_data_size,
								&bridge->configuration,
								task->writefile.write_cb,
								(char *) TASK_LIST_RESOLVE(task->writefile.name),
								&task->writefile.cb_data
						)) != 0) {
							goto out_cleanup;
						}

						entry.term = 1;
						entry.type = RAFT_CHANGE;
						entry.buf.base = conf_data;
						entry.buf.len = conf_data_size;
						entry.batch = NULL;

						__rrr_raft_bridge_ack_start (
								&event,
								bridge,
								1,
								1,
								&entry,
								1
						);
						goto step;
					default:
						RRR_BUG("BUG: Unknown write file type %i in %s\n",
							task->writefile.type, __func__);
				};
				break;
			default:
				RRR_BUG("BUG: Unkown type %i in %s\n",
					task->type, __func__);
		};

		continue;

		step:

		if ((ret_tmp = raft_step(bridge->raft, &event, &update)) != 0) {
			RRR_MSG_0("Step failed in %s: %s\n", __func__, raft_strerror(ret_tmp));
			ret = 1;
			goto out_cleanup;
		}

		if (!update.flags) {
			RRR_RAFT_BRIDGE_DBG("no update flags");
			continue;
		}

		if (update.flags & RAFT_UPDATE_STATE) {
			__rrr_raft_bridge_ack_update_state(bridge);
		}

		if (update.flags & RAFT_UPDATE_SUGGEST_SNAPSHOT) {
			assert(0 && "Update suggest snapshot not implemented");
		}

		if (update.flags & RAFT_UPDATE_CURRENT_TERM) {
			__rrr_raft_bridge_ack_update_current_term(&list_new, bridge);
		}

		if (update.flags & RAFT_UPDATE_VOTED_FOR) {
			assert(0 && "Update voted for not implemented");
		}

		if (update.flags & RAFT_UPDATE_ENTRIES) {
			assert(0 && "Update entries not implemented");
		}

		if (update.flags & RAFT_UPDATE_SNAPSHOT) {
			assert(0 && "Update snapshot not implemented");
		}

		if (update.flags & RAFT_UPDATE_MESSAGES) {
			assert(0 && "Update messages not implemented");
		}

		if (update.flags & RAFT_UPDATE_COMMIT_INDEX) {
			if ((ret = __rrr_raft_bridge_ack_update_commit_index(bridge)) != 0) {
				goto out_cleanup;
			}
		}

		if (update.flags & RAFT_UPDATE_TIMEOUT) {
			// Ignore, only push timeout task if
			// there are no other tasks.
			RRR_RAFT_BRIDGE_DBG("request to update timeout, ignoring for now");
		}

		RRR_MSG_0("TODO: Check for pending leadership transfer request\n");
	}


	if (list_new.count == 0) {
		task_new.type = RRR_RAFT_TASK_TIMEOUT;
		task_new.timeout.time = raft_timeout(bridge->raft);
		rrr_raft_task_list_push(&list_new, &task_new);
	}

	rrr_raft_task_list_cleanup(list);
	*list = list_new;

	goto out_final;
	out_cleanup:
		rrr_raft_task_list_cleanup(&list_new);
		RRR_FREE_IF_NOT_NULL(conf_data);
	out_final:
		return ret;
}
