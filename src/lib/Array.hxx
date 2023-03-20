/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#pragma once

#include <cassert>
#include <string>

extern "C" {
#include "array.h"
#include "messages/msg.h"
};

#include "util/E.hxx"
#include "util/ExtVector.hxx"

namespace RRR {
	class TypeValue {
		private:
		struct rrr_type_value *value;

		template <typename T, typename L> void blob_split(L l) const {
			const rrr_length element_length = value->total_stored_length / value->element_count;
			if (element_length == 0) {
				l((T *) nullptr, 0);
			}
			else {
				RRR::util::DynExtVector<T>(
					(T *) value->data,
					value->total_stored_length,
					element_length
				).iterate([l, element_length] (T *data) {
					l(data, element_length);
				});
			}
		}

		template <typename T, typename L> void primitive_split(L l) const {
			RRR::util::ExtVector<T> (
				value->data,
				value->total_stored_length
			).iterate([l] (T data) {
				l(data);
			});
		}

		template <typename L> void msg_split(L l) const {
			assert(value->total_stored_length >= sizeof(struct rrr_msg));

			rrr_length count = 0;
			rrr_length pos = 0;
			while (pos < value->total_stored_length) {
				rrr_length target_size = 0;
				const struct rrr_msg *msg = reinterpret_cast<const struct rrr_msg *>(pos);
				const rrr_length remaining_size = value->total_stored_length - pos;

				// The integrity of the message should have been
				// checked during importing
				assert(rrr_msg_get_target_size_and_check_checksum (
					&target_size,
					msg,
					value->total_stored_length - pos
				) == 0);

				l(msg, target_size);

				pos += target_size;
				count++;
			}
			assert(pos == value->total_stored_length);
			assert(count == value->element_count);
		}

		public:
		TypeValue(struct rrr_type_value *value) :
			value(value)
		{
		}

		bool is_signed() const {
			return RRR_TYPE_FLAG_IS_SIGNED(value->flags) != 0;
		}

		template <
			typename HOST, typename BLOB, typename MSG, typename FIXP, typename STR, typename VAIN
		> void iterate (
			HOST h, BLOB b, MSG m, FIXP f, STR s, VAIN v
		) const {
			switch (value->definition->type) {
				case RRR_TYPE_H:
					primitive_split<rrr_type_be>(h);
					break;
				case RRR_TYPE_MSG:
					msg_split(m);
					break;
				RRR_TYPE_CASE_BLOB:
					blob_split<const uint8_t>(b);
					break;
				case RRR_TYPE_FIXP:
					primitive_split<rrr_fixp>(h);
					break;
				RRR_TYPE_CASE_STR:
					blob_split<const char>(s);
					break;
				case RRR_TYPE_VAIN:
					v();
					break;
				default:
					RRR_BUG("Unsupported type %u in %s\n", value->definition->type, __func__);
			};
		}
	};

	class Array {
		private:
		struct rrr_array array;

		public:
		Array();
		~Array();

		class E : public RRR::util::E {
			public:
			E(std::string msg) : RRR::util::E(msg) {}
		};

		static void verify_tag(std::string tag) {
			if (tag.length() > RRR_TYPE_TAG_MAX) {
				throw E(std::string("Tag length exceeds maximum (") + std::to_string(tag.length()) + ">" + std::to_string(RRR_TYPE_TAG_MAX) + ")");
			}
		}

		rrr_biglength allocated_size();

		struct rrr_array * operator *() {
			return &array;
		}

		int count() {
			return rrr_array_count(&array);
		}

		void clear() {
			rrr_array_clear(&array);
		}

		void clear_by_tag(std::string tag) {
			rrr_array_clear_by_tag(&array, tag.c_str());
		}

		void to_message (struct rrr_msg_msg **final_message, uint64_t time, const char *topic, rrr_u16 topic_length);
		void add_from_message(uint16_t *version, const struct rrr_msg_msg *msg);
		void push_value_vain_with_tag(std::string tag);
		void push_value_str_with_tag(std::string tag, std::string value);
		void push_value_blob_with_tag_with_size(std::string tag, const char *value, rrr_length size);
		void push_value_64_with_tag(std::string tag, uint64_t value);
		void push_value_64_with_tag(std::string tag, int64_t value);
		void push_value_fixp_with_tag(std::string tag, rrr_fixp value);
		void push_value_fixp_with_tag(std::string tag, std::string string);

		template <
			typename HOST, typename BLOB, typename MSG, typename FIXP, typename STR, typename VAIN, typename C
		> void iterate (
			HOST h, BLOB b, MSG m, FIXP f, STR s, VAIN v, C c = [](std::string tag)->bool{return true;}
		) {
			RRR_LL_ITERATE_BEGIN(&array, struct rrr_type_value);
				if (!c(node->tag != NULL ? std::string(node->tag) : std::string())) {
					RRR_LL_ITERATE_NEXT();
				}
				const TypeValue type_value(node);
				type_value.iterate([h, &type_value](auto data){h(data, type_value.is_signed());}, b, m, f, s, v);
			RRR_LL_ITERATE_END();
		}
	};
};
