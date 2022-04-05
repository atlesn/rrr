# CUSTOM RRR MODULES

Writing modules requires knowledge about the C programming language. In attempt to avoid confusion, RRR distinguishes between
a `module` and an `instance`. A `module` is a plugin which has capabilities to do different jobs, and it is loaded when needed.
A module may have many `instances` of itself running at the same time with different configurations. Each instance has it's own thread.

This document describes two different types of modules

* User `C-modules` which are easy to implement, this should cover most needs
* *Native* RRR-modules which allow for heavy customization

## Getting started with C-modules

A C-module script or program basically has three functions defined, `config`, `source` and `processor`.

* `config` is called once to pass configuration parameters
* `source` is called repeatedly to spawn new messages
* `process` is called every time a message comes in from another module

If you wish to write a simple `C-module`, please check out the man page for `rrr.conf` which describes this in more detail.
It is easy to create custom Perl or Python scripts.

Custom C-modules written in C are built after RRR is installed using the build system in `misc/cmodule_standalone`. Readme
for this is found in `README` in the same directory.

### Confusion

To create confusion, there are two things called cmodule:

* The RRR-module `cmodule` which allows developers to write simple `C-modules`. It basically only one has file
  `src/modules/p_cmodule.c`. Custom C-modules are run from this module and are expected to be found in `lib/rrr/cmodules`.
* The internal `cmodule` framework in the RRR library which takes care of messages, loops, forks etc., this is divided into
  multiple files in `src/lib/cmodule/`

### How C-modules work

The basic thought is relatively simple, but the implementation is complex. Here are some keywords:

* For each C-module (or Perl-script etc.) a process is forked to run the script
* The fork, or `worker`, takes care of when the different three functions are called, and sends messages which has been
  spawned or processed to the parent, which then let's other modules pick them up
* The `parent`, which is the thread in the main RRR-process, reads messages from other modules and sends messages to be
  processed to the worker
* The worker may choose not to send processed messages back, or to duplicate messages
* The communication between the parent thread and the worker  is performed on an "RRR Memory Map Channel". This method should
  both be fast when needed and not CPU-intensive when there's nothing to do. Fast means tens of thousands of messages
  (small ones that is) per second on an average home computer.
* When a C-module depends on external libraries, like Perl and Python, it is not allowed to call *any* of these library
  functions in the parent thread, all of this must be done in the worker after forking. These external libraries create
  all sorts of problems due to them using global variables and state. The only way to clean up properly
  after them is to stop the whole process, this is the main reason why the worker fork is needed.

### Implementation of scripting language module

If you wish to implement another scripting language, consider having this written as a native RRR-module instead, this will give
better structure to the program. Check out the modules `perl5`, `python3` and `cmodule` and copy one of them. `cmodule` is
the simplest one, it has the least code and has no external dependencies.

## Getting started with native modules

The details around how this works is not documented. Try to open the RRR source in an IDE like Eclipse and follow the function
calls to see what's going on. There's however very few function calls requried to be done from the native module itself.

To write a custom module, start by copying one existing module in the `src/modules/` directory. Update `Makefile.am` in the
same directory using the same naming convention as the other modules.

* To write a source module which only generates messages, copy the `dummy` module.
* To write a module which only processes data from other modules, copy the `raw` module.
* To write a module which both reads from other modules, processes it and lets other modules read from it, copy the `averager` module.

After a module is copied, replace all instances of the old name inside the file with your new name to avoid confusion.

All modules must provide an `init()` function which is used to provide information to Read Route Record about which functions
the module provides, its name and type. This can usually be left alone, just change the static `module_name` value to change
the informational name of the module. The `type` field, however, provides information about wether we expect a sender to
be specified or if we only are a source module (see `dummy` module vs `raw`); If the `event*_functions` pointer is 
set in the `init()` function, the module is expected to use event based reading from other modules and must do so.

The following module types are available:
- `RRR_MODULE_TYPE_SOURCE` - The module does not read from others, but it may be read from
- `RRR_MODULE_TYPE_PROCESSOR` - The module both reads from others and may be read from
- `RRR_MODULE_TYPE_DEADEND` - The module only reads from others
- `RRR_MODULE_TYPE_FLEXIBLE` - The module may be any of the three above depending on configuration
- `RRR_MODULE_TYPE_NETWORK` - The module is network oriented, it does not exchange messages with other modules

The `module_operations` struct provides pointers to our internal functions which other modules call. All values except `thread_entry
may be `NULL`. Reading modules should check whether a function really is available (not null) of senders before use, and be careful
about which types the return:
 
	struct module_operations {
		// Preload function - Run before thread is started in main thread context
		int (*preload)(...);
	
		// Main function with a loop to run the thread
		void *(*thread_entry)(...);
	
		// Post stop function - Run after thread has finished from main thread context
		void (*poststop)(...);
	
		// Inject any packet into buffer manually (usually for testing)
		int (*inject)(...);
	
		// Custom cancellation method (if we are hung and main wants to cancel us)
		int (*cancel_function)(...);
	};

The `rrr_instance_event_functions` structure holds pointers to default event callbacks, if the module is to use events.
Currently only one function is supported.

	struct rrr_instance_event_functions {
		// Called when messages from senders must be read
		int (*broker_data_available)(..);
	};

The event structure, if used, is allocated statically and a pointer to it must be set in the `init()` function.

All modules of type `PROCESSOR`, `DEADEND` and `FLEXIBLE`, which reads from other modules, must be event based.
The event framework has counters of how many messages a module is to receive, and these must match the actual number of messages at all times.
If a module reads messages without these counters being updated, the event queue will become full and cause message processing to stop.

In addition, one must specify the `load()` and `unload()` functions. These are called only once directly after loading the module and once just
before unloading it. That means they are not called for each instance. If a module is dependent on some external library which needs to
be initialized, this may be done in these functions.

### Writing to output buffer

All instances have an output buffer which other modules read from, also those which does not produce output in which this is simply not used.
The buffer provides locking and memory fences for data messages which are to move between threads. This is handled by the `message broker`.
Instances using the broker are called `costumers`.

The buffers of all modules are created prior to starting the modules. Whenever a function in the message broker is called, the existence of
the requested costumer is checked. If it does not exist, the call will fail. If it does exist, a reference count is incremented ensuring
the costumer is not deleted while it's being used.

All writes to the output buffer AND all writes to memory areas pointed to by data inside the buffer MUST happen inside the provided write methods.
Reads must also happen inside provided functions.

These methods are always available for an instance to use:

	rrr_message_broker_write_entry (
				INSTANCE_D_BROKER(data->thread_data), // Retrieves pointer to the message broker	
				INSTANCE_D_HANDLE(data->thread_data), // Gets the costumer handle of the current instance
				NULL,
				0,
				0,
				my_write_callback_function,
				&my_write_callback_data
	)

- The NULL and 0's are IP information which is not used in this case.
- The callback function must be provided by the instance, the actual writing happens here
- The callback data is used only by the callback function and instructs it on what to do

The callback function will receive a pre-allocated so called `rrr_msg_holder` or message holder. This struct holds IP address data (if any) and the message itself.
It also provides reference counting and locking.

Depending on how a module is written, we don't always know wether we should actually write to the buffer or not when calling a write functions. If
we do not wish to use the new message holder in the callback after all, the callback may return `RRR_MESSAGE_BROKER_DROP`. It's on the other hand also
possible to make the message broker call the callback again immediately if we wish to write another message holder (or try again) by `RRR_MESSAGE_BROKER_AGAIN`.
These two may be ORed together. For severe errors, return `RRR_MESSAGE_BROKER_ERR`. This makes the write function also return and error (non-zero).

The message holder must be filled with an RRR message as other modules expects this. The message must only be allocated and written to inside the 
write callback to provide proper memory fencing.

Before the callback returns, the message holder MUST be unlocked using `rrr_msg_holder_unlock()`. Reference counting can usually be disregarded in
the write callback.

Some fast write methods are available to use for entries which already have been allocated inside a write function (and not modified afterwards),
but which we now wish to write to the output buffer without allocating a new message holder. These functions are marked with `unsafe`.

	// Write to the output buffer
	rrr_message_broker_incref_and_write_entry_unsafe(...); 
	
	// Removes entries one by one from the given collection and puts it into the output buffer
	rrr_message_broker_write_entries_from_collection_unsafe(...);

If we cannot guarantee that a message holder has been written to exclusively inside a write function, we must clone it when we add it to
the output queue:

	// Allocate new memory and copy to it
	rrr_message_broker_clone_and_write_entry(...);

### Module with custom loop

Modules which do not read from other modules may use a simple processing loop as opposed to using the event framework.
Such modules should have some sleep or wait mechanism in their loop to prevent spinning.
The watchdog timer must be updated regularly, and checks for encourage stop signal must be performed.

	static void *thread_entry_my(struct rrr_thread *thread) {
		// This line is present in all modules at the top of the thread entry function. It casts the
		// void * private_data pointer, which the intermediate thread entry function has initialized,
		// to its actual type. The module may choose to use the `private_data` pointer to something
		// else than just pointing to the pre-allocated memory, like a custom allocation.
		struct rrr_instance_runtime_data *thread_data = thread->private_data = thread_data->private_memory;
		
		// Initialization
		...
		
		// Main thread loop, stop looping when encourage stop signal is received
		while (!rrr_thread_signal_encourage_stop_check(...)) {
			// Notify the watchdog that everything is still OK
			rrr_thread_watchdog_time_update(...);

			// Do custom stuff and possibly write messages to the message broker
		}
		
		// Cleanup
		...
	}
	
### Reading/polling from other modules (event loop, recommended form)

Modules must poll messages from other modules *exclusively* using the provided event callback.
This is to ensure that the event counter and number of messages to poll are consistent.

The minimal event callback for messages from senders looks like this. Note that the `amount` variable is
provided by the event framework, this variable *must not* be modified by the module, its pointer is passed
directly to the poll function. The poll callback function is otherwise identical to that of the non-event example.

	static int my_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
		struct rrr_thread *thread = arg;
		struct rrr_instance_runtime_data *thread_data = thread->private_data;

		return rrr_poll_do_poll_delete (amount, thread_data, my_poll_callback, 0);
	}

An event module has no while loop, the dispatch function is called instead.

	rrr_event_dispatch (
		INSTANCE_D_EVENTS(thread_data),
		1 * 1000 * 1000, // 1 second interval (recommended)
		rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
		thread
	);

A custom periodic function may be provided instead of the watchdog update function. If this is done, the periodic
function must call the watchdog updater and return its return value should it be non-zero (the thread is told to exit).

It is possible to create custom events, these should be organized in a statically allocated `rrr_event_collection` structure.
The collection must be cleared when the module exits. Look in `event_collection.h` and otherwise in modules using this.

When using events, the module is forced to poll all messages passed to it, and the event callback function will be called
in a busy loop until all pending messages have been polled. If the module wishes to pause incoming messages, it
can do this by providing a pause check callback to the event framework. The pause callback is consulted prior to
every call of the event callback.

	void my_pause_callback (int *do_pause, int is_paused, void *callback_arg) {
		struct rrr_instance_thread_data *thread_data = callback_arg;

		...

		// Set *do_pause to 1 to activate pausing or to 0 to resume
	}
	
	...

	rrr_event_callback_pause_set(INSTANCE_D_EVENTS(thread_data), my_pause_callback, thread);

The pause callback may be disabled by passing NULL as the function pointer to `rrr_event_callback_pause_set`.
Custom events are not affected by pausing.

An alternative to pausing is to break out of the dispatch loop by returning `RRR_EVENT_EXIT` in any callback and then do some
other module-specific processing before calling it again. Note that if this processing is slow, the thread will get cancelled
by the watchdog unless the watchdog timer is updated. Custom checks for encourage stop signal should also be present in tactical locations.

### Thread data

When a thread/instance starts with the specified entry function, it receives an `rrr_thread` struct. This has a pointer which is pre-
initialized with a `rrr_instance_runtime_data` struct. There are shortcut pointers here to command line argument struct from the main
program (`cmd_data` struct), data from the configuration file (`rrr_instance_settings`). The thread must free the `rrr_thread` struct
before shutting down (done by instance framework in intermediate thread entry function).

There is a slot of 8kB freely available in `rrr_instance_runtime_data` which the different modules use to hold their state, this is called
`char private_memory[RRR_MODULE_PRIVATE_MEMORY_SIZE]`. To use this, create a custom struct and point it to the `private_memory` address.
This allows us to always find the private data of our module event if we are in some callbacks where only the `rrr_thread` struct or the
`rrr_instance_runtime_data` struct is available.

Use the pthread framework `pthread_cleanup_push()` and `pthread_cleanup_pop()` to clean up a threads data on exit, look in the
existing modules how they do this. This will make sure data is cleaned up also if the thread is cancelled the hard way. If a thread
hangs on I/O and doesn't exit nicely, it will be left dangling in memory untill it recovers upon which it will clean up its memory.
A new instance will be created instead, and therefore we MUST NOT use statically allocated data in the module which might cause
corruption. Use the private memory provided instead.

### Memory allocation

All allocations must be performed using provided allocation functions from `allocator.h` which map to either jemalloc functions or default OS functions.
Functions like `rrr_allocate` and `rrr_free` are available, and it is not safe to use the standard `free()` or `malloc()` functions.

Messages and message holder structs are allocated using the `rrr_allocate_group()` function which allows debugging to be added into these functions if needed.

## Modules, threads and instances

The RRR threads use three different frameworks to operate. The lower level frameworks threads.c and modules.c operate independently. The
instances.c framework use both of these to load module files (.so) using the modules framework and start them as threads using the threads
framework. The instances framework is also responsible for controlling configuration parameters.

- threads.c
  - Lower level thread handling and watchdog functions
  - Starting, stopping, signalling and monitoring of threads through watchdog threads
  - Used both by main() to start threads an also by some individual modules which starts new threads themselves

- modules.c
  - Loads modules from (.so) files and finds symbols
  - Used by main() and cmodule framework.

- instances.c
  - One RRR instance is created for every section in the configuration file. The instane is a combination of a module and a thread along
    with other frameworks.
  - Uses threads.c and modules.c to start RRR instances of the modules based on configuration data.
  - An intermediate thread entry function allocates common RRR functionallity used by the different modules
    - The cmodule framework (config-source-process logic) is loaded for all threads (Perl5, Python3 etc. use this)
    - Message broker handle is registered, used by the modules to post messages to readers
    - Poll collection is initialized, used to read data from senders
    - Statistics handle is registered

Each configuration file loaded by a single RRR program is run by it's own fork. This forking does not have any dedicated
framework, it is handled mostly in rrr.c and main.c. There is however a global fork handling framework, fork.c, which wraps the
forking functionallity of the operating system. This framework keeps track of which child processes a parent process has, and
takes care of forwarding signals and watiing (periodically called functions).

The functions defined in each module are called from different contexts and at different points in time.

- `preload`, `poststop`, `cancel_function`: Run before a thread starts and after all threads have stopped. If a thread is ghost, the poststop call
  will be postponed. These are handled by the threads framework.

- `cancel_function` - If a cancel function is specified, this will be run instead of calling pthread_cancel() if a watchdog senses that it's thread is hung.
  The threads framework is responsible for these.

- `thread_entry`: The only function which is actually run by the thread of the instance. It should contain an infinite loop. Part of the 
  instances framework.

- `inject`: Used by test suite only, part of the instances framework.

## Important frameworks

The different frameworks are used both by RRR main() and instances framwork, and they are in some cases used stand-alone in different modules.

- allocator.c, rrr_mmap.c
  - Memory management

- rrr_config.c
  - Global configuration from command line parameters, like debuglevels

- log.c, log.h
  - Almost all source files are tightly coupled to these files (unless all logging is removed)
  - Handles the widely used log macros
  - Others may register handlers to receive log messages (like the journal module)
  - Global process-shared locking

- util/linked_list.h, util/map.h
  - Widely used set of macros to implement linked list functionallity
  - Iteration, manipulation, destruction etc.

- util/
  - Misc helper functions

- threads.c (see previous chapter)
  - Stand-alone framework to deal with threads

- modules.c (see previous chapter)
  - Stand-alone framework to deal loading .so files

- common.c - Signalling, exit handler
  - Global state (per fork)
  - Frameworks which need to check for signals may register a handler with the signal framework
  - Exit handlers are used to clean up after 3rd party libraries to easy memory leak debugging

- event.c, event_collection.c
  - Handles event processing

- fork.c
  - Handles forking, shutdown and waiting. Used both by main() and some modules.
  - Memory owned by main(), only one integer is global state which is used to set signal pending flag
  - Registers with signal framework to catch SIGCHLD

- mmap_channel.c
  - Used by individual modules to communicate with child worker forks
  - A round robin buffer wrapped in a read/write like interface

- configuration.c
  - Parses configuration file, creates instance config data for every section which is used by instances.c
  - Extracts all parameters (var=val pairs) without checking any names etc.
  - Parses loose array trees which modules may find and use when they start and configure themselves

- settings.c
  - Lower level module for handling settings
  - Has helper functions for finding and interpreting parameters

- fifo.c / fifo_protected.c
  - Linked list buffer with some high level functions like memory management
  - Functions for searching/iterating, delete individual elements
  - Nicknamed FIFO buffer
  - Can store any data
  - Callback-style interface
  - The `fifo_protected.c` framework also has locks which are held when inside callback to provide memory fence

- rrr_msg_holder - Internal struct, not network safe
  - Usually holds an rrr_msg_msg entry. The framework does not couple with any particular message type, but
    currently only standard RRR messages are used.
  - May contain IP address and protocol information 
  - Used by message_broker.c to hold messages being passed between instances
  - Has locking to provide memory fence and shared ownership using user count logic
  - Framework for an one-slot buffer used by message broker

- message_broker.c
  - Started by main() for each configuration fork
  - Uses FIFO buffer or slots to create output buffers for each module
  - Each thread registers itself and a handle (ID-number) is created which is safe to use even if the
    buffer it points to has been destroyed
  - Instances find other buffers using these handles and polls from them
  - Allocates and destroys rrr_msg_holder structures

- type.c
  - Type system used by the array framework
  - Parse input data for the different type, perform endian conversion, export values etc.

- array.c
  - Widely used structure to store data from RRR array messages in an intermediate structure
  - May act as a _definition_ before any data has been parsed, only describing the values it
    should be filled with
  - Manipulate values, add, remove etc. (is a simple linked list)
  - Export data back to RRR message packed format

- array_tree.c / condition.c
  - Using a tree hirarchy, combine conditional branches with array definitions to performed
    complex interpretation of input data
  - Trees cannot be exported. When a tree is used to parse input data, a plain rrr_array
    is produced.

- messages (multiple files) - Network safe structures
  - The base message is an rrr_msg which has a header with size, type and CRC32 checksum
  - Used both internally and sent over networks
  - rrr_msg_msg is the main RRR message which can hold either an array or data, as well as an MQTT topic
  - rrr_msg_setting holds settings (from settings.c)
  - rrr_msg_log holds log entries, usually sent from child worker forks to main
  - rrr_msg_addr is used to pass IP address information along with an rrr_msg_msg when it
    is not possible to wrap the message in an rrr_msg_holder structure
  - Endian conversion and checksum functions
  - Messages may have dynamic length, the needed space for data is allocated in addition to
    the size of the struct being used.
  - Messages are always a plain block of data, they are freed using just free()
  - Can be stored in rrr_msg_holder whos destroy function calls free() on it's data pointer. Currently
    only rrr_msg_msg is stored in rrr_msg_holder, and this is assumed in many places in the code and
    correctness for this is not checked.

- poll_helper.c
  - Helper framework to assist an instance looking up other instances and polling messages from them
    using the message broker.
  - Does topic filtering if specified in configuration (couples with rrr_msg_msg)

- instances.c (see previous chapter)
  - Works as a controller, couples with multiple frameworks

- ip.c
  - Provide helper functions for IP communication
  - Has graylisting for TCP hosts which does not reply
  - Should be combined with socket framework, nothing done here is actually IP-specific

- read.c
  - Provides logic to store data read from a client across multiple read calls
  - Users must provide a pre-parse function called `get_target_size` which returns the number of bytes
    the read function should read before calling the `final` callback
  - Any overshoot bytes are stored and re-used in the next call
  - Separates different datagram connections with the read session collection sister framework

- net_transport/net_transport.c
  - Wrapper framework for transparent plaintext TCP/IP and TLS TCP/IP connection management
  - Used for listening servers or connecting clients
  - Multiple servers/client of the same application can use the same net transport instance (which is either TLS or plain)
  - Management of connections and per-connection lifetime application data
  - No stream management, application must handle this
  - Automatic writing

- socket/rrr_socket_client.c
  - Protocol independent wrapper framework for connection management
  - File descriptors are created outside the framework and then "pushed" into a collection
  - Used for listening servers, connecting clients and datagram reading
  - Automatic reading streams of RRR-messages, array tree data and raw data
  - Automatic writing

- socket/rrr_socket.c
  - Global per-fork state
  - Keeps track of all open sockets and shuts down any left open on program exit
  - The fork framework use this state to shut down sockets from the parent process after forking
  - Some sister files provide different kind of helper functions to wrap socket-related complexity, these
    are coupled with frameworks like the message framework.

- helpers/string_builder.c / helpers/nullsafe_str.c
  - Helpers to reduce the amount of "manual" handling of strings needed in C
  - Have append and prepend and search functions
  - string_builder uses zero-terminated strings while nullsafe_str stores length separately

- msgdb_helper.c
  - Helper functions for modules which use the message DB framework

Some other high level frameworks used by individual modules:

- HTTP client/server
- MQTT
- Perl5
- Python3
- MariaDB/MySQL
- UDPstream
- C-module
- passwd

In addition, there are multiple smaller utilities.

## Thread state convention

Read Route Record creates one thread for every instance when it starts. All threads, when started, must first initialize their data
which other modules might use, and then wait for a START signal which RRR sends when all threads are initialized and
may read from each other. 

The threads should follow a strict pattern on how to initialize and close correctly. It is unsafe to use any global
frameworks like the socket framework while some thread is forking. We must therefore ensure that all threads are
waiting on a signal before the forking occurs (they can't do anything else while waiting) and that only one thread
is performing fork operation at one time.

During startup, the following occurs:
1.	Wait for all threads to set state `RRR_THREAD_STATE_INITIALIZED`
2.	For every thread, set signal `RRR_THREAD_SIGNAL_START_BEFOREFORK` and wait for it to set `RRR_THREAD_STATE_RUNNING_FORKED`
3.	Modules which fork child processes fork before switching state, others just change state immediately
4.	Set signal `RRR_THREAD_SIGNAL_START_AFTERFORK` on all threads

Two helper functions are used by the modules to make sure waiting is done correctly,
`rrr_thread_start_condition_helper_fork` and `rrr_thread_start_condition_helper_nofork`. The first one
has a callback which is called when it's time for forking, the latter function has no callback.

While a thread is running, it has to update a timer constantly using `rrr_thread_watchdog_time_update()`, or else it will be killed by the watchdog after five seconds.

When one or more threads for any reason exits, all instances from the same configuration file are stopped and restarted automatically.

If there are any dramatic crashes like segmentation faults, the whole RRR main process and all running configurations will terminate. Any
restart must then be handled by `SystemD`, `runit` etc. If the crash happens within a fork, like in Perl5 or Python3, the thread responsible
for the fork will just exit when it has detected the crash and all threads will restart.

If a thread does not set state `RRR_THREAD_STATE_STOPPED` within some reasonable timespan after it has been instructed to shut down, the
thread will become ghost. If it wakes up again at some later time, resources will be freed. There is potential for a memory leak to occur if
an instance repeatedly becomes ghost and the ghost never wakes up again. If this happens, the reason for why the thread hangs must be investigated.

## Assistant binaries in the source three
Some runnables are compiled to be used during development but are not installed. They use the same frameworks as
corresponding functionallity in the RRR modules. The binaries are found in `/src/`.

- `rrr_msgdb` will spin up a stand-alone message database (corresponds to the `msgdb` module)
- `rrr_http_client` can do simple HTTP request and print responses as well as sending websocket frames (corresponds to the `httpclient` module)
- `rrr_http_server` spins up a basic HTTP server (corresponds to the `httpserver` module)
