/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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


#include "../lib/instance_config.hpp"
#include "../lib/poll_helper.hpp"
#include "../lib/arrayxx.hpp"
#include "../lib/type.hpp"
#include "../lib/event/event_collection.hpp"
#include "../lib/msgdb/msgdb_client.hpp"
#include "../lib/magick/magick.hpp"
#include "../lib/message_holder/message_holder.hpp"

extern "C" {

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/instances.h"
#include "../lib/instance_friends.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/event/event.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/message_holder/message_holder_util.h"

#define RRR_OCR_DEFAULT_INPUT_TAG "ocr_input_data"
#define RRR_OCR_DEFAULT_DEBUG_FILE "/tmp/debug"

#define RRR_OCR_VERIFY_TOPIC "ocr/verify"
#define RRR_OCR_IMAGE_TAG "ocr_image"
#define RRR_OCR_VALUE_TAG "ocr_value"
#define RRR_OCR_SIGNATURE_TAG "ocr_signature"
#define RRR_OCR_GOOD_VERIFY_PROPABILITY 0.01

__attribute__((constructor)) void load(void);
void init(struct rrr_instance_module_data *data);
void unload(void);

} /* extern "C" */

#include <string>

struct ocr_data {
	struct rrr_instance_runtime_data *thread_data;

	rrr::event::collection events;
	rrr::msgdb::client msgdb_conn;

	std::string msgdb_socket;
	std::string input_data_tag;

	std::vector<rrr::magick::vectorpath_signature> paths;
	std::vector<std::string> values;
	std::vector<uint64_t> ages;

	size_t path_size_min;
	size_t good_match_threshold;

	size_t good_total_counter;

	ocr_data(struct rrr_instance_runtime_data *thread_data) :
		thread_data(thread_data),
		events(INSTANCE_D_EVENTS(thread_data)),
		msgdb_conn(),
		msgdb_socket(""),
		input_data_tag(""),
		paths(),
		values(),
		ages(),
		path_size_min(40),
		good_match_threshold(5000),
		good_total_counter(0)
	{
		rrr::magick::load();
		path_init();
	}

	~ocr_data() {
		rrr::magick::unload();
	}

	void path_init() {
		// Initial random match data
		static const std::string characters = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ0123456789";
		std::for_each(characters.begin(), characters.end(), [&](const char &c){
			path_push(rrr_rand(), std::string(&c, 1));
		});
	}

	void path_erase(const rrr::magick::vectorpath_signature &s) {
		auto it_values = values.begin();
		auto it_ages = ages.begin();
		for (auto it = paths.begin(); it != paths.end(); it++) {
			if (*it == s) {
				paths.erase(it);
				break;
			}
			it_values++;
			it_ages++;
		}
	}

	void path_push(const rrr::magick::vectorpath_signature &s, const std::string &v) {
		paths.push_back(s);
		values.push_back(v);
		ages.push_back(rrr_time_get_64());
	}

	template<typename F,typename G> void path_search(const rrr::magick::vectorpath_signature &s, F good, G partial) {
		std::map<size_t,size_t> partials;
		for (size_t i = 0; i < paths.size(); i++) {
			size_t diff = s.cmpto(paths[i]);
			//printf("<> %s : %lu\n", values[i].c_str(), diff);
			if (diff < good_match_threshold) {
				good((const rrr::magick::vectorpath_signature &) paths[i], (const std::string &) values[i], diff);
			}
			else {
				partials.emplace(diff, i);
			}
		}
		for (auto it = partials.rbegin(); it != partials.rend(); ++it) {
			partial((const rrr::magick::vectorpath_signature &) paths[it->second], (const std::string &) values[it->second], it->first);
		}
	}
};

static void ocr_data_cleanup(void *arg) {
	struct ocr_data *data = reinterpret_cast<struct ocr_data *>(arg);
	delete data;
}

struct ocr_send_verification_callback_data {
	struct ocr_data *data;
	const rrr::type::data_const &d;
	const rrr::magick::vectorpath_signature &s;
	const std::string &v;
};

static int ocr_send_verification_callback(struct rrr_msg_holder *entry, void *arg) {
	struct ocr_send_verification_callback_data *callback_data = reinterpret_cast<struct ocr_send_verification_callback_data *>(arg);

	rrr::msg_holder::unlocker unlocker(entry);

	int ret = 0;

	class rrr::array::array array;

	try {
		array.push_value_with_tag(RRR_OCR_IMAGE_TAG, callback_data->d);
		array.push_value_with_tag(RRR_OCR_VALUE_TAG, callback_data->v);
		array.push_value_with_tag(RRR_OCR_SIGNATURE_TAG, callback_data->s.data());

		struct rrr_msg_msg *msg = NULL;
		array.to_message(&msg, rrr_time_get_64(), RRR_OCR_VERIFY_TOPIC);

		entry->message = msg;
		entry->data_length = MSG_TOTAL_SIZE(msg);
		msg = NULL;
	}
	catch (rrr::exp::normal &e) {
		ret = e.num();
		RRR_MSG_0("Could not create verification message in OCR instance %s: %s\n",
			INSTANCE_D_NAME(callback_data->data->thread_data), e.what());
		goto out;
	}

	out:
	return ret;
}

static void ocr_send_verification(struct ocr_data *data, const rrr::magick::vectorpath_signature &s, const std::string &v, const rrr::type::data_const &d) {
	struct ocr_send_verification_callback_data callback_data = {
		data,
		d,
		s,
		v
	};

	rrr::exp::check_and_throw (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			ocr_send_verification_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	), std::string("while sending OCR verification message in instance %s") + INSTANCE_D_NAME(data->thread_data));
}

static void ocr_process_path (struct ocr_data *data, const rrr::magick::mappath &path, const rrr::magick::pixbuf &image, const size_t i) {
	static int filename_count = 0;
	filename_count++;

	if (path.count() < data->path_size_min) {
		return;
	}

	rrr::magick::pixbuf image_path_debug(image);
	rrr::magick::edges edges_path_debug = image_path_debug.edges_clean_get();
	rrr::magick::minmax<rrr::magick::mappos> minmax(path.m);

	// Verification image without path points
	Magick::Blob blob = image_path_debug.edges_dump_blob (
			edges_path_debug,
			minmax
	);

	std::string id = std::to_string(filename_count) + "-" + std::to_string(i);

	path.to_vectorpath_16([&](const rrr::magick::vectorpath_16 &v) {
		rrr::magick::vectorpath_signature s = v.normalize().signature();

		int good_count = 0;
		int partial_max = 2;

		try {
			data->path_search (
				s,
				[&](const rrr::magick::vectorpath_signature &s, const std::string &v, size_t score) {
					(void)(s);
					std::cout << "Good " << id << " score " << score << ": " << v << std::endl;
					good_count++;
					if (((++data->good_total_counter) % (size_t) (1.0/RRR_OCR_GOOD_VERIFY_PROPABILITY)) == 0) {
						std::cout << "Verify good '" << v << "'" << std::endl;
						ocr_send_verification (
								data,
								s,
								v,
								rrr::type::data_const(blob.data(), blob.length())
						);
					}
				},
				[&](const rrr::magick::vectorpath_signature &s, const std::string &v, size_t score) {
					(void)(s);
					(void)(score);
//					std::cout << "Partial " << id << " score " << score << ": " << v << std::endl;
					if (--partial_max == 0) {
						throw rrr::exp::eof();
					}
					ocr_send_verification (
							data,
							s,
							v,
							rrr::type::data_const(blob.data(), blob.length())
					);
				}
			);
		}
		catch (rrr::exp::eof &e) {
		}

		if (good_count == 0) {
			minmax.expand(10, image_path_debug.height(), image_path_debug.width());

			int count = 0;
			path.iterate ([&](const rrr::magick::mappos &p) {
				int colour = ++count % 10 == 0 ? 1 : 2;
				edges_path_debug.set(p, colour);
				//edges_debug.set_if_higher(p, colour);
			});
			v.walk([&](const rrr::magick::mappos &p){
				edges_path_debug.set(p, 3);
			});
			edges_path_debug.set(path.start(), 3);
			Magick::Blob blob = image_path_debug.edges_dump_blob (
					edges_path_debug,
					minmax
			);
			ocr_send_verification (
					data,
					s,
					"",
					rrr::type::data_const(blob.data(), blob.length())
			);
		}
	});
}

static void ocr_process_image (struct ocr_data *data, const rrr::magick::pixbuf &image, const float threshold) {
	std::vector<rrr::magick::mappath> paths_merged;
	rrr::magick::edges edges_debug = image.edges_clean_get();
	image.paths_get (
			image.edges_get(
					threshold,
					5,
					200000
			),
			10
	).split([&](const rrr::magick::mappath &path) {
			rrr::magick::mappath path_new(path.count());
			path.iterate (
					[&](const rrr::magick::mappos &p) {
						path_new.push(p);
					}
			);
			paths_merged.push_back(path_new);
	});
	printf("Merged %lu\n", paths_merged.size());
	std::sort (
			paths_merged.begin(),
			paths_merged.end(),
			[&](
				const rrr::magick::mappath &a,
				const rrr::magick::mappath &b
			) {
					return a.count() > b.count(); // Reverse
			}
	);

	for (size_t i = 0; i < paths_merged.size() && i < 1000; i++) {
		const rrr::magick::mappath &path = paths_merged[i];
		ocr_process_path(data, path, image, i);
	}
}

static void ocr_process_image (struct ocr_data *data, const rrr::array::array &array) {
	rrr::magick::pixbuf image(array.get_value_raw_by_tag(data->input_data_tag));

	for (float threshold = 0.1; threshold <= 1.0; threshold += 0.1) {
		try {
			ocr_process_image(data, image, threshold);
			break;
		}
		catch (rrr::exp::incomplete &e) {
			printf("- Max edges, increase threshold\n");
		}

	}

/*				filename_count++;
	printf("Dumping %i...\n", filename_count);
	image.edges_dump(std::string(RRR_OCR_DEFAULT_DEBUG_FILE) + "_" + std::to_string(filename_count), edges_debug);
	printf("DONE\n");
	rrr::magick::edges edges;*/
}

static void ocr_process_response (struct ocr_data *data, const rrr::array::array &array) {
	const rrr::type::data_const signature = array.get_value_raw_by_tag(RRR_OCR_SIGNATURE_TAG);
	const rrr::type::data_const value = array.get_value_raw_by_tag(RRR_OCR_VALUE_TAG);
	std::string value_str((const char *) value.d, value.l);

	std::cout << "OCR response for " << value_str << std::endl;

	data->path_erase(signature);
	data->path_push(signature, value_str);
}

static void ocr_poll_callback (struct rrr_msg_holder *entry, struct rrr_instance_runtime_data *thread_data) {
	struct ocr_data *data = reinterpret_cast<struct ocr_data *>(thread_data->private_data);
	const struct rrr_msg_msg *msg = reinterpret_cast<struct rrr_msg_msg *>(entry->message);

	RRR_MSG_1("Poll callback\n");

	rrr::msg_holder::unlocker unlocker(entry);

	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data)) != 0) {
		throw rrr::exp::eof();
	}

	try {
		const rrr::array::array array(msg);

		printf("Topic: %s\n", MSG_TOPIC_PTR(msg));

		if (rrr_msg_msg_topic_equals(msg, RRR_OCR_VERIFY_TOPIC)) {
			ocr_process_response(data, array);
		}
		else {
			ocr_process_image(data, array);
		}
	}
	catch (rrr::exp::soft &e) {
		RRR_MSG_0("Dropping message after soft error in ocr instance %s: %s\n", INSTANCE_D_NAME(thread_data), e.what());
	}
}

static int ocr_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = reinterpret_cast<struct rrr_thread *>(arg);
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(thread->private_data);

	rrr::poll_helper::amount a(*amount);
	RRR_EXP_TO_RET(poll_delete(a, thread_data, ocr_poll_callback));

	*amount = a.a;

	return 0;
}

static int ocr_event_periodic (void *arg) {
	struct rrr_thread *thread = reinterpret_cast<struct rrr_thread *>(arg);
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

static int ocr_parse_config (struct ocr_data *data, struct rrr_instance_config_data *config) {
	using namespace rrr::instance_config::parse;

	try {
		utf8_optional(data->input_data_tag, config, "ocr_input_data_tag", "");
		utf8_optional(data->msgdb_socket, config, "ocr_msgdb_socket", "");
	}
	catch (parse_error &e) {
		RRR_MSG_0("Configuration parsing failed for ocr instance %s: %s\n", config->name, e.what());
		return 1;
	}

	return 0;
}

static void *thread_entry_ocr (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = reinterpret_cast<struct rrr_instance_runtime_data *>(thread->private_data);
	struct ocr_data *data = new ocr_data(thread_data);
	thread_data->private_data = data;

	RRR_DBG_1 ("ocr thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(ocr_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (ocr_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("ocr instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 s
			ocr_event_periodic,
			thread
	);

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread ocr %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_ocr,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "ocr";

__attribute__((constructor)) void load(void) {
}

static struct rrr_instance_event_functions event_functions = {
	ocr_event_broker_data_available
};

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ocr module\n");
}
