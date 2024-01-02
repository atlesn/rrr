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

//#include "v8-callbacks.h"
//#include "v8-persistent-handle.h"
extern "C" {
#include "../rrr_types.h"
};

#include <v8.h>
#include <memory>
#include <algorithm>
#include <forward_list>
#include <cassert>

#include "../util/Time.hxx"

namespace RRR::JS {
	class PersistentBus;
	class Persistable;
	class PersistableHolder;

	/*
	 * Message passing from Persistables to Sniffers:
	 *
	 *   A Sniffer receives a weak pointer along with messages which allows
	 *   it to check if any persistent actions are not longer relevant (the
	 *   Persistable has been destroyed). Due to this, any message passing
	 *   must be performed through the Persistent object which holds the shared
	 *   pointer to the Persistable object.
	 *
	 *   1. When a Persistable is registered, the pointer of the Persistent
	 *      object, which holds its memory, is stored in it.
	 *   2. The derived object calls the Persistable::pass() function to
	 *      send a message.
	 *   3. The pass function uses the stored pointer and calls the
	 *      Persistent::pass() function.
	 *   4. The Persistent object calls pass() in the MessageBus, but now
	 *      a weak pointer is created from the shared pointer holding memory
	 *      of the Persistable and passed along the message.
	 *   5. All Sniffers receive the message along with the weak pointer and
	 *      the argument. Depending on the message, the argument may be destined
	 *      either for the sniffer or for the Persistable object itself in the
	 *      acknowledgement call.
	 *   6. If a Sniffer decides to, it may immediately, or at a later time,
	 *      call the acknowledge function of the Persistable after checking
	 *      that the weak pointer is still valid. If it does, the argument
	 *      pointer must be passed.
	 */

	class PersistentSniffer {
		public:
		virtual bool accept(std::weak_ptr<Persistable>, const char *identifier, void *arg) = 0;
		virtual ~PersistentSniffer() = default;
	};

	class PersistentBus {
		private:
		std::vector<PersistentSniffer *> sniffers;

		public:
		void pass(std::weak_ptr<Persistable> origin, const char *identifier, void *arg) {
			bool used = false;
			std::for_each(sniffers.begin(), sniffers.end(), [&used, origin, identifier, arg](auto s){
				used = used || s->accept(origin, identifier, arg);
			});
			// One or more sniffers must be able to process a
			// message, and if not, we have a bug. The sniffer must
			// always return true if is able to process a message
			// event if the message could not be processed due to
			// error. The sniffers must throw exceptions in case
			// of bad errors.
			assert(used == true);
		}
		void push_sniffer(PersistentSniffer *sniffer) {
			sniffers.emplace_back(sniffer);
		}
	};

	class PersistentMessageIntermediate {
		public:
		virtual void pass(const char *identifier, void *arg) = 0;
	};

	class Persistable {
		private:
		int64_t total_memory = 0;
		PersistentMessageIntermediate *forwarder = nullptr;
		PersistableHolder *holder = nullptr;

		protected:
		// Derived classes must implement this and report the current
		// estimated size of the object so that we can report changes
		// to V8.
		virtual int64_t get_total_memory() = 0;

		// Pass a message
		void pass(const char *identifier, void *arg) {
			forwarder->pass(identifier, arg);
		}

		// Store an object as persistent. Returns positon to use
		// when pulling.
		unsigned long push_persistent(v8::Local<v8::Value> value);

		// Pull a persistent out for temporary use
		v8::Local<v8::Value> pull_persistent(unsigned long i);

		// Clear all persistents
		void clear_persistents();

		public:
		// Receive acknowledgement that a message has been processed by
		// a sniffer. The acknowledgement may be performed at a later
		// time for instance if the message initiates a timeout action
		// or is a promise. Persistables need not implement this if
		// they do not pass messages or do not need acknowledgements.
		virtual void acknowledge(void *arg) {};

		// Called reguralerly by storage to check if object
		// may be tagged for destruction. When the function
		// returnes true, the object may be garbage collected by
		// V8 once no more references to it exist.
		virtual bool is_complete() const {
			return true;
		}

		// Register message bus
		void register_bus(PersistentMessageIntermediate *forwarder) {
			this->forwarder = forwarder;
		}
		// Register persistent object holder
		void register_holder(PersistableHolder *holder) {
			this->holder = holder;
		}
		// Called reguralerly by storage
		int64_t get_unreported_memory() {
			int64_t total_memory_new = get_total_memory();
			int64_t diff = total_memory_new - total_memory;
			total_memory = total_memory_new;
			return diff;
		}
		// Called by storage before object is destroyed
		int64_t get_total_memory_finalize() {
			assert(total_memory >= 0);
			int64_t ret = total_memory;
			total_memory = 0;
			return ret;
		}
		// Called for statistics purposes
		int64_t get_total_memory_stats() const {
			return total_memory;
		}
		virtual ~Persistable() = default;
	};

	class PersistableHolder : public PersistentMessageIntermediate {
		friend class Persistable;
		friend class PersistentStorage;

		private:
		struct ValueHolder {
			public:
			bool done;
			std::unique_ptr<v8::Persistent<v8::Value>> value;
			ValueHolder(v8::Isolate *isolate, v8::Local<v8::Value> value);
		};
		std::vector<ValueHolder> values;
		bool is_weak;
		std::shared_ptr<Persistable> t;
		PersistentBus *bus;
		v8::Isolate *isolate;
		int64_t creation_time = 0;
		std::string name;

		protected:
		unsigned long push_value(v8::Local<v8::Value> value);
		v8::Local<v8::Value> pull_value(unsigned long i);
		void clear_values();
		void pass(const char *identifier, void *arg) final;
		int64_t get_unreported_memory();
		int64_t get_total_memory_finalize();
		bool is_done() const;
		void check_complete();
		static void gc(const v8::WeakCallbackInfo<void> &info);
		PersistableHolder(v8::Isolate *isolate, v8::Local<v8::Object> obj, const std::string &name, Persistable *t, PersistentBus *bus);
		PersistableHolder(const PersistableHolder &p) = delete;
	};

	/*
	 * Persistable life cycle:
	 *
	 * The memory of a Persistable is owned by a PersistableHolder object. The
	 * gc() of the PersistentStorage, which manages the holders,  is called
	 * reguraley to activate the GC cascade.
	 *
	 * The Persistable may push multiple V8 objects to its PersistableHolder.
	 * Destruction of the PersistableHolder, thus the Persistable and all V8
	 * objects, occurs  once all objects have been garbage collected by V8.
	 *
	 * The Persistable objects go through the following stats:
	 *
	 * 1. Persistable and objects are new, memory persists indefinately
	 * 2. check_complete() of the PersistableHolder is called
	 *    reguralerly. This function checks if is_complete() of the Persistable
	 *    is true, and once it is, SetWeak() is called on all V8 objects
	 *    held by the PersistableHolder, queueing them for garabage collection.
	 * 3. V8 GC runs, and once weak callback of all objects has run, is_done()
	 *    of the PersistableHolder returns true. This causes storage to
	 *    destroy the PersistableHolder and held objects.
	 *
	 * Notes:
	 * -  is_complete() of the Persistable, unless the default definition of the
	 *    Persistable is overridden by the derived class, returns true
	 *    immediately. This will start the GC cascade once no more references
	 *    to the objects contained by the PersistableHolder exist in the script.
	 */

	class PersistentStorage {
		v8::Isolate *isolate;

		std::forward_list<std::unique_ptr<PersistableHolder>> persistents;
		int64_t entries = 0;
		int64_t total_memory = 0;

		PersistentBus bus;

		public:
		PersistentStorage(v8::Isolate *isolate);
		PersistentStorage(const PersistentStorage &p) = delete;
		void report_memory(int64_t memory);
		//void push(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t);
		void push(v8::Isolate *isolate, v8::Local<v8::Object> obj, Persistable *t, const std::string &name);
		void register_sniffer(PersistentSniffer *sniffer);
		void gc(rrr_biglength *entries_, rrr_biglength *memory_size_);
	};
} // namespace RRR::JS
