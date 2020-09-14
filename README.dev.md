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

If you wish to write a simple `C-module`, please check out the man page for `rrr.conf` which describes this in more detail. It's
basically so simple that it's no point coverering any technical details here.

### Confusion

To create confusion, there are two things called cmodule:

* The RRR-module `cmodule` which allows developers to write simple `C-modules`. It basically only one has file
  `src/modules/p_cmodule.c`. Custom C-modules are run from this module and are expected to be found in `src/cmodules/`.
* The internal `cmodule` framework in the RRR library which takes care of messages, loops, forks etc., this is divided into
  multiple files in `src/lib/cmodule/`

### How C-modules work

The basic thought is relatively simple, but the implementation is complex. Here are some keywords:

* For each C-module (or Perl-script etc.) a process is forked to run the script
* The fork, or `worker`, takes care of when the different three functions are called, and sends messages which has been
  spawned or processed to the parent, which then let's other modules pick them up
* The `parent`, which is a thread in the main RRR-process reads messages from other modules and sends messages to be
  processed to the worker
* The worker may choose not to send processed messages back, or to duplicate messages
* The communication between the parent thread and the worker  is performed on an "RRR Memory Map Channel". This method should
  both be fast when needed and not CPU-intensive when there's nothing to do. Fast means tens of thousands of messages
  (small ones that is) per second on an average home computer.
* When a C-module depends on external libraries, like Perl and Python, it is not allowed to call *any* of these library
  functions in the parent thread, all of this must be done in the worker after forking. These external libraries create
  all sorts of problems due to them using global variables and state. The only way to clean up properly
  after them is to stop the whole process, this is the main reason why the worker fork isis needed.

### Implementation of scripting language module

If you wish to implement another scripting language, consider having this written as a native RRR-module instead, this will give
better structure to the program. Check out the modules `perl5`, `python3` and `cmodule` and copy one of them. `cmodule` is
the simplest one, it has the least code and has no external dependencies.

The details around how this works is not documented, try to open the RRR source in an IDE like Eclipse and follow the function
calls to see what's going on. There's however very few function calls requried to be done from the native module itself.

## Getting started with native modules

To write a custom module, start by copying one existing module in the `src/modules/` directory. Update `Makefile.am` in the
same directory using the same naming convention as the other modules.

* To write a source module which only generates messages, copy the `dummy` module.
* To write a module which only processes data from other modules, copy the `raw` module.
* To write a module which both reads from other modules, processes it and lets other modules read from it, copy the `averager` module.

After a module is copied, replace all instances of the old name inside the file with your new name to avoid confusion.

All modules must provide an `init()` function which is used to provide information to Read Route Record about which functions
the module provides, its name and type. This can usually be left alone, just change the static `module_name` value to change
the informational name of the module. The `type` field, however, provides information about wether we expect a sender to
be specified or if we only are a source module (see `dummy` module vs `raw`);

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
		int (*inject)(RRR_MODULE_INJECT_SIGNATURE);
	
		// Custom cancellation method (if we are hung and main wants to cancel us)
		int (*cancel_function)(...);
	};

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
	rrr_message_broker_incref_and_write_entry_unsafe_no_unlock(...); 
	
	// Write to the delayed write queue of the output buffer
	rrr_message_broker_incref_and_write_entry_delayed_unsafe_no_unlock(...);
	
	// Removes entries one by one from the given collection and puts it into the output buffer
	rrr_message_broker_write_entries_from_collection_unsafe(...);

A delayed write can be performed while still being inside the callback of a write function or a poll callback (read further down) of the buffer we are writing to.

If we cannot guarantee that a message holder has been written to exclusively inside a write function, we must clone it when we add it to
the output queue:

	// Allocate new memory and copy to it
	rrr_message_broker_clone_and_write_entry(...);

### Reading/polling from other modules

The action of retrieving messages from the output buffers of other instances is called polling. The structures needed for polling are 
initialized automatically for every instance in the intermediate thread entry functions. It contains information about all the senders
specified in the configuration file, or it is empty if there are no senders.

It is possible to manipulate the poll structure in the module or create "custom" poll collections, but currently no modules do this.

Here is an example of the minimum structure needed to perform polls in a module. The dots are where other code goes.

	static int my_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
		struct rrr_msg_msg *message = entry->message;
		
		// Other return values possible depending on wether we use delete or search.
		// In buffer.c see
		// - rrr_fifo_buffer_read_clear_forward for poll delete
		// - rrr_fifo_buffer_search for poll search 
		int ret = RRR_FIFO_OK;
		
		... (do stuff with message)
		
		// Message holder must ALWAYS be unlocked
		rrr_msg_holder_unlock(entry);
		return ret;	
	}

	static void *thread_entry_my(struct rrr_thread *thread) {
		// This line is present in all modules at the top of the thread entry function. It casts the
		// void * private_data pointer, which the intermediate thread entry function has initialized,
		// to its actual type.
		struct rrr_instance_runtime_data *thread_data = thread->private_data;	
		
		...
		
		// Main thread loop
		while (...) {
			// Do the polling and call the callback if data was polled. When callback returns, the polled
			// data is deleted. Calling rrr_poll_do_poll_search lets callback choose wether polled data
			// is deleted or not. The callback will be called multiple but a finite number of times
			// if there are mulitple elements in the buffer.
			if (rrr_poll_do_rrr_poll_delete (thread_data, &thread_data->poll, my_poll_callback, 0) != 0) {
				break;
			}
		}
		
		...
	}
	

The message holder struct may be used directly in linked lists. If it is added to another list in the callback, the
user count must be incremented using `rrr_msg_holder_incref_while_locked`. It cannot be part of two linked lists
at the same becuse the linked list pointers are inside it, thus it will always exists only in one instance at a time.

Clone functions are available if an entry is to be used in multiple places simultaneously.

Inside the poll callback function, the entry can be directly written to the output buffer using `rrr_message_broker_incref_and_write_entry_unsafe_no_unlock`.

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
A new instance will be created insted, and therefore we MUST NOT use statically allocated data in the module which might cause
corruption. Use the private memory provided instead.

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

- rrr_config.c
  - Global configuration from command line parameters, like debuglevels

- log.c, log.h
  - Almost all source files are tightly coupled to these files (unless all logging is removed)
  - Handles the widely used log macros
  - Others may register handlers to receive log messages (like the journal module)
  - Global process-shared locking

- linked_list.h
  - Widely used set of macros to implement linked list functionallity
  - Iteration, manipulation, destruction etc.

- threads.c (see previous chapter)
  - Stand-alone framework to deal with threads

- modules.c (see previous chapter)
  - Stand-alone framework to deal loading .so files

- common.c - Signalling, exit handler
  - Global state (per fork)
  - Frameworks which need to check for signals may register a handler with the signal framework
  - Exit handlers are used to clean up after 3rd party libraries to easy memory leak debugging

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

- buffer.c
  - Linked list buffer with some high level functions like memory management
  - Callback-style interface, locks are held when inside callback to provide memory fence
  - Functions for searching/iterating, delete individual elements
  - Nicknamed FIFO buffer
  - Can store any data

- rrr_msg_holder - Internal struct, not network safe
  - Usually holds an rrr_msg_msg entry. The framework does not couple with any particular message type, but
    currently only standard RRR messages are used.
  - May contain IP address information 
  - Used by message_broker.c to hold messages being passed between instances
  - Has locking to provice memory fence and shared ownership using user count logic

- message_broker.c
  - Started by main()
  - Uses FIFO buffer to create output buffers for each module
  - Each thread registers itself and a handle (ID-number) is created which is safe to use even if the
    buffer it points to has been destroyed
  - Instances find other buffers using these handles and polls from them
  - Allocates and destroy rrr_msg_holder

- type.c
  - Type system used by the array framework
  - Parse input data for the different type, perform endian conversion, export values etc.

- array.c
  - Widely used structure to store data from RRR array messages in an intermediate structure
  - May act as a _definition_ before any data has been parsed, only describing the values it
    should be filled with
  - Manipulate values, add, remove etc. (is a simple linked list)
  - Export data back to RRR message packed format

- array_tree.c
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
  - rrr_msg_addr is used to pass IP address information along with and rrr_msg_msg when it
    is not in an rrr_msg_holder structure
  - Endian conversion and checksum functions
  - Messages may have dynamic length, the needed space for data is allocated in addition to
    the size of the struct being used.
  - Messages have no pointers, they are freed using just free()
  - Can be stored in rrr_msg_holder whos destroy function calls free() on it's data pointer

- poll_helper.c
  - Helper framework to assist an instance looking up other instances and polling messages from them
    using the message broker.
  - Does topic filtering if specified in configuration (couples with rrr_msg_msg)

- instances.c (see previous chapter)
  - Works as a controller, couples with multiple frameworks

- rrr_socket.c
  - Global per-fork state
  - Keeps track of all open sockets and shuts down any left open on program exit
  - The fork framework use this state to shut down sockets from the parent process after forking
  - Some sister files provide different kind of helper functions to wrap socket-related complexity, these
    are coupled with frameworks like the message framework.

- ip.c
  - Provide helper functions for IP communication
  - Has graylisting for TCP hosts which does not reply
  - Should be combined with socket framework, nothing done here is actually IP-specific

- read.c
  - Provides logic to store data read from a client across multiple read calls
  - Users must provide a pre-parse function called `get_target_size` which returns the number of bytes
    the read function should read before calling the `final` callback
  - Any overshoot bytes are stored and re-used in the next call
  - Separates different UDP connections with the read session collection sister framework

- net_transport.c
  - Wrapper framework for plaintext TCP and TLS TCP

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

The threads should follow a strict pattern on how to initialize and close correctly. This has to be done to prevent readers to use
functions in other modules which are not ready when we start the program.

Threads which create forks should be started prior to network modules. Module priorities are:

0. `RRR_THREAD_START_PRIORITY_NORMAL` - No particular priority, started immediately.
1. `RRR_THREAD_START_PRIORITY_FORK` - Threads using this must set `RUNNING_FORKED` state after forks have been made
2. `RRR_THREAD_START_PRIORITY_NETWORK` - Uses sockets and should start after forking threads. Will receive start signal last.

The basic state flow of a module/thread is like this (see `threads.h` for internal names):

0. `FREE` - Thread is new
1. `STOPPED` - Thread has stopped
2. `INIT` - Thread is currently initializing its data and we have to wait for it to finish before we proceed
3. `INITIALIZED` - Thread has initialized its data and is waiting for start signal. When all threads reach
   this state, we tell them to start in a calculated order.
4. `RUNNING` - Thread sets this state after receiving start signal. If an instance is told to wait for another thread before starting, it will be started when the other thread sets `RUNNING`.
5. `RUNNING FORKED` - Thread sets this state after being started and any process forks are done (used by python and perl).

It is very important that a thread does not read from other threads before it has received the start signal.

A thread has to update a timer constantly using `update_watchdog_time()`, or else it will be killed by the watchdog after five seconds.

If one or more threads exit, all threads are stopped and restarted automatically.

