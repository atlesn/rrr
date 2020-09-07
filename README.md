![RRR logo](https://raw.githubusercontent.com/atlesn/rrr/master/misc/rrr-not-tall.svg)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/atlesn/rrr.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/atlesn/rrr/context:cpp)
![Build master](http://www.goliathdns.no/rrr/build-master.svg?a "Build status master")
![Build development](http://www.goliathdns.no/rrr/build-development.svg?a "Build status master")

RRR (Read Route Record) is a general purpose acquirement, transmission and processing daemon supporting HTTP,
MQTT, TCP, UDP and other I/O devices. RRR has a variety of different modules which can be chained
together to retrieve, transmit, modify and save messages.

RRR can read data of different types from external programs or sensors using UDP, TCP, UNIX sockets,
piping or files. It is also possible to run self made scripts inside of RRR to modify messages as
they pass through.

As part of an application, RRR will handle tasks like networking, daemonizing, logging and buffering,
allowing developers to focus on more specialized tasks.

Among other things, RRR can be used to:

- Acquire/capture messages, telegrams and data using piping, UNIX sockets, UDP/TCP-packets, HTTP or MQTT
- Transfer messages using HTTP, MQTT, UDP or TCP
- Modify messages using Perl or Python
- Save messages using InfluxDB, MySQL or a customized save method

Application examples may include:

- Barcode scanners
- Sensors (temperature, pressure, voltage etc.)
- Communication with PLCs
- Message forwarding, media or protocol conversion etc.
- Host monitoring, logging
- Print spooling
- General capture and acquisition of all kinds of data, messages and telegrams

RRR is used by starting one or more modules with different capabilities that read messages from each other. Some modules
also use networking to communicate with different types of devices or with RRR programs on other hosts. Once a message
enters RRR, it is stored in an internal format, an `RRR-message`, which is supported by all the different modules. It is
also possible to generate these messages externally based on the header files.

To send data to RRR, the data should be in some form of predictable binary or textual format. Data may
also be acquired directly by RRR if you write a custom Perl or Python script to acquire readings from
the source, for instance when the data source is a device on a computer.

Message processing in RRR is designed to work with as little state as possible. By default, messages are passed through
without the need for any complex data structures in memory or persistently open TCP connections.
This design enhances stability, but also requires that larger applications using RRR have the same mentality. For network connections
which require some state, like MQTT, RRR will transparently make sure that a connection is available at all times, relieving
application designers from the burden of implementing this.

Before starting up and configuring RRR to use networking, read the **SECURITY** section at the end.

The directory `/examples/` in the source tree or on github.com/atlesn/rrr contains larger application examples.
The `.md` files contain the examples, and the source scripts and configuration files used in the examples are found alongside these.  

## SUPPORTED SYSTEMS

RRR supports being run by SystemD and runit and has native Debian/Ubuntu, Fedora and ArchLinux packages. In addition, RRR
may be compiled and run on FreeBSD or other Linuxes including Raspbian, Void and SUSE. Other systems might work but
are not supported.

Among distributions known *not* to work out of the box, are  OpenBSD and NetBSD. These do not work
due to lack of support for process shared locks.

Please create an issue on the GitHub page https://github.com/atlesn/rrr if you are unable to use a
particular device with RRR or if it doesn't run on a particular distribution.

## LICENSES

RRR is released under the GPLv3 with *exceptions for self written modules*. Please check out
the `LICENSE.*`-files regarding this.

## DEVELOPMENT

It is possible to write custom modules in Perl, Python and C. All three have similar easy to use
interfaces to RRR. The man page for rrr.conf has more information on this, also check out [README.dev.md](README.dev.md).

The RRR library provides many protocol implementations and networking tools. While it is possible to link
other programs to the RRR library, there is currently some initialization of different data structures
for logging etc. which needs to be done. If you wish to do this, please open an issue on the GitHub page
to discuss it there.

If you are a developer and would like to see more functionality or have some ideas, please consider
forking the GitHub repository.

## QUICK START

### DOWNLOAD

#### Compile from source

	$ git clone https://github.com/atlesn/rrr.git
	$ cd rrr

Some systems have customized branches, choose one of the following if appropriate:

	$ git checkout archlinux
	$ git checkout freebsd
	$ git checkout ubuntu

The master branch of RRR contains a native Debian package.

See the *COMPILE* section below for further information.

#### Pre-compiled package for Debian Buster amd64/i386 using APT

	$ su -
	# apt install curl gnupg
	# curl -s https://apt.goliathdns.no/atle.gpg.key | apt-key add -
	# curl -s https://apt.goliathdns.no/debian/buster.list > /etc/apt/sources.list.d/goliathdns.list
	# apt update
	# apt install rrr

#### Pre-compiled package for Ubuntu Focal amd64 using APT

	$ curl -s https://apt.goliathdns.no/atle.gpg.key | sudo apt-key add -
	$ sudo sh -c "curl -s https://apt.goliathdns.no/ubuntu/focal.list > /etc/apt/sources.list.d/goliathdns.list"
	$ sudo apt update
	$ sudo apt install rrr

#### Pre-compiled Fedora package using yum

	$ sudo su -
	# curl https://yum.goliathdns.no/goliathdns.repo > /etc/yum.repos.d/goliathdns.repo
	# yum install rrr

When asked to install the GPG key for the GoliathDNS repository, answer 'yes'.

#### Install from ArchLinux AUR repository

	$ yay -S rrr

The latest RRR release will be downloaded and built. When prompted after compilation, enter your password to complete the installation.
	
#### Packages available on the APT mirrors

- rrr
- rrr-mod-python3
- rrr-mod-mysql / rrr-mod-mariadb
- librrr1
- librrr-dev
- rrr-mod-python3-dbgsym
- librrr1-dbgsym

Note that on Ubuntu RRR supports MySQL, and on Debian RRR supports MariaDB. If you need to use for instance
MySQL on Debian and the standard package doesn't work, consider building from source with `dpkg-buildpackage`
on the Ubuntu branch (`git checkout ubuntu`).

Packages for Debian Bullseye (testing release) are also available on the APT mirror, replace `buster` with `bullseye` in the above guide. These are
built from the `debian-testing` branch.

### COMPILE

Compiling the source requires some basic knowledge on how to build a program using Autotools. Usually,
some extra packages must be installed prior to compilation.

On SUSE, the following packages should be installed to build RRR:

	$ sudo zypper install git perl libmariadb-devel python3-devel openssl-devel autoconf automake gcc libtool

On Debian, Ubuntu and derived systems, the following should be installed:
	
	$ sudo apt install libperl-dev git libmariadb-dev-compat python3-dev libssl-dev autoconf automake gcc libtool

On other systems, packages with similar names also exist.

See `./configure --help` for flags to use for disabling modules with dependencies (perl, mysql etc.).

	$ autoreconf -i
	$ ./configure
	$ make
	$ sudo make install		-- Skip if you do not wish to install RRR on the filesystem

You may turn off Python3 and MySQL support when configuring, look at `./configure --help`. This will remove the
need for development packages being installed for these. Perl bindings can also be disabled, but usually it needs to be 
installed to run the tools which build RRR. OpenSSL bindings may be disabled.

It is also possible, if you are on Ubuntu, Debian or similar, to build a `.deb` package. Look online
on detailed information about this and on which packages you need to build `.deb` packages.

	$ dpkg-buildpackage
	$ sudo dpkg -i ../rrr*.deb

### RUN MANUALLY

To start the program with modules, a config file must first be made. Write this into a file
called `rrr.conf`.

	[my_source]
	module=dummy
	dummy_no_generation=no
	
	[my_target]
	module=raw
	senders=my_source
	raw_print_data=yes

Then, run the following command:

	$ rrr --debuglevel 2 rrr.conf

You can see that `my_source` generates messages which `my_target` then reads. Since RRR is designed to run forever,
use `Ctrl+C` to exit. RRR might produce some error messages when the different modules shut down, this is normal.

Keep reading below for more examples, and refer to `man rrr`, `man rrr_post` and `man rrr.conf` for more detailed information on how to configure `rrr`.

### RUN AND READ MANUALS WITHOUT INSTALLATION

	$ cd /directory/to/rrr/source/which/you/have/already/compiled
	$ man ./src/misc/man/rrr.conf.5
	$ man ./src/misc/man/rrr.1
	$ man ./src/misc/man/rrr_post.1
	$ ./src/rrr my_rrr_test_configuration.conf

### RUN WITH RUNIT/SYSTEMD

If you installed one of the provided packages, RRR will have configured `systemd` or `runit` and might already be running using a dummy configuration.

Configuration files are placed in `/etc/rrr.conf.d/`. RRR will start one process fork for every configuration file in this folder (which ends with `.conf`).
Place files in this folder and restart RRR with `sudo systemctl restart rrr` or `sv restart rrr`. Logs are delivered to syslog like other daemons.

For testing purposes, RRR can be started to start all configuration files in a directory by using `rrr /etc/rrr.conf.d/`.

When compiling from source, there are configuration flags available to enable and disable `systemd` and `runit`.

### OPENSSL/LIBRESSL

When compiling RRR, the configuration script will search for both OpenSSL and LibreSSL installations. By default, the latter takes precedence if both are present.

### VIEW LIVE LOGS FROM DAEMONIZED PROCESS

By default, the RRR daemon is started with the `-s` flags, enabling the statistics engine. Each running fork will create a socket in `/tmp/` to which
the binary `rrr_stats` can connect. If there is only one fork, `rrr_stats` will find it and connect to the correct socket without any additional arguments.

To view log output instead of statistics, run `rrr_stats -j`.

Note that if you produce a lot of debug output, having `rrr_stats` running can cause crashes. By default, RRR only prints out errors and warnings.

## ARRAYS
Instead of just passing chunks of data around, RRR can organize data into arrays. The array system is designed so that messages/telegrams
from external sources can be parsed directly into an RRR array and used by the different modules.

An array definition describes the data RRR will receive, and all data is validated against these definitions. RRR messages may contain
either raw data or an RRR array. Some modules, like the `buffer` module, do not care about what kind of messages they handle, these will
just forward all messages. Capable modules may on the other hand pick data from the array in the message or perform modifications.

An RRR array consist of multiple positions where each position has one or more value of a certain type and length,
possible tagged with a name.

The array definition specifies data types, sizes and tags. Some types need to have a specified length, and other types
figure out the length automatically. RRR will always make sure that it is possible to determine the length
of each record, this is necessary to be able to separate the records from each other upon receival. In a single position,
all sizes must be equal.

If you are unsure about whether a definition is valid, just try to use it and RRR will give you an error message if it isn't.

Below is the specification for array definitions, more detailed descriptions of the types are found in the section **ARRAY TYPES**.

	type1[length1][s|u|][@count1][#tag1][,type2[length2][s|u|][@count2][#tag2]][,...]
	
- `type` - Identifier name of the type
- `length` - Length in bytes of the type (if required)
- `count` - Item count of the specific type, defaults to 1 if not specified
- `tag` - Optional custom identifier tag of the type

### ARRAY EXAMPLE

Let's say we have incoming messages on UDP and wish to parse them. We use the IP module to
receive the messages and separate them from one another.

- Each message begins with 10 integeres af 1 bytes each, whereof the last nine are to be grouped together
- After this, there is a quoted string of arbitrary length which we have to parse, but which we mostly ignore later
- Then, two integeres with one byte each follow
- At the end there is an 8 byte arbitrary value which is to be split into two parts followed by a carriage return which we do not use

Here's a graphical representation of the array with the tags we want to use to address the different elements when processing the message:

	 +--------+-----------------+---------------------------+----------+----------+-------------+----+
	 | my_int |   my_integers   |                           | same_tag | same_tag | split_blob  |    |
	 |   1    |1|2|3|4|5|6|7|8|9| "String data without tag" |    11    |    12    | blob | abcd | CR |
	 +--------+-----------------+---------------------------+----------+----------+-------------+----+

The 2D way of representing the same array, it kindof looks like this internally in RRR after it has been parsed:

	 +--------+-------------+---------------------------+----------+----------+------------+----+
	 | my_int | my_integers |                           | same_tag | same_tag | split_blob |    |
	 |   1    |     1       | "String data without tag" |    11    |    12    |    blob    | CR |
	 |        |     2       |                           |          |          |    abcd    |    |
	 |        |    ...      |                           |          |          |            |    |
	 |        |     9       |                           |          |          |            |    |
	 +--------+-------------+---------------------------+----------+----------+------------+----+

The array definition in the configuration for the IP module will look like this:

	ip_input_types=be1#my_int,be1@9#my_integers,str,be1#same_tag,be1#same_tag,blob4@2#split_blob,sep1

The internal RRR array will always preserve the location of the different elements. The tags are not in a
hash table, the array is always stored as it was first parsed.

If the same message is to be converted back to raw data and sent over the network, let's say from the 
IP module, the data will be written out mostly as it was received, including the quotes on the string.
Note that integer values always are represented internally with 64 bits (eight bytes). When exported,
they will also be this big, there is no method of reducing their size. If it is important to preserve
the sizes of integers, use the **blob** type instead. Note that multi-byte integers parsed using blobs
will not undergo endian-conversion, they will always be represented in their original endian inside RRR. 

The MQTT client module has the ability to export raw array values into PUBLISH message bodies.

The Perl5 and Python3 modules have functionality for array manipulation if messages need to be modified
or processed in some way inside of RRR.

### ARRAY BRANCHING

Array branching (or array trees) allows a single definition to be used for different input data. If you for instance
have a protocol with
different message types, an indicator byte at the beginning of each message can be used to identify which branch to use.

An array with branches is just like a standard array with one or more IF blocks in between the values.
The IF blocks may be nested.

Let us say we want to receive two different message types. We use an indicator byte to distinguish them, and this byte is
set to either 1 or 2. We specify this array tree in our configuration file.

	 {MY_ARRAY}
	 be1#indicator
	 IF ({indicator} == 1)
	 	blob16#message_small
	 	;
	 ELSIF ({indicator} == 2)
	 	blob32#message_big_a,
	 	blob32#message_big_b
	 	;
	 ELSE
	 	err
	 	;
	 sep1#separator
	 ;

If the indicator byte is set to 1, we parse a 16 byte message.
If it is two, we parse two 32 byte messages.
In both cases, we expect a separator character at the end (like `ETX`, `CR`, `LF` etc.).

After a branched array has been successfully parsed, all values which were encountered while we parsed and checked
conditions reside in a single standard array. The receiver of these arrays must be adapted to receive all possible different arrays the array tree may produce.

When using branching, it's important to consider all possible outcomes.
If we receive invalid data, we should branch to a block with the **err** value defined.
This is a dummy value which doesn't parse anything but instead always produces an error to make the parsing stop. 

Most standard operators are available, like `+ * - << & || &&` etc.
It is possible to use `AND` and `OR` as well, those are aliases for `&&` and `||`.

A condition is considered to be true if it evaluates to non-zero.

Array trees may be specified in configuration files (outside instance definitions) with a header with a name like
`{MY_ARRAY}`. The tree
must end with a `;` (this also goes for each `IF`, `ELSIF` or `ELSE` block).
All modules which have array definitions parameters may either specify an array tree like `ip_input_types=be4,be4`
or reference an array from elsewhere in the configuration like `ip_input_types={MY_ARRAY}`.

If the array tree is specified directly at the parameter, no newlines may occur within the tree (which may become messy).
The terminating semicolon is optional when array trees are defined in a configuration parameter. 

Although this example covers most of the branching-stuff, more detail can be found in the **rrr_post(1)** manual page.

## MODULES

Here's a short list of modules to start with, more are listed in the `rrr.conf` man page.

### ip (read and send data records using UDP and TCP)
This module handles inbound and outbound IP traffic. It can parse incoming data and organize it into RRR arrays,
and also send data to external hosts based on address information in the messages it receives from other modules.

The IP module is the binding link between RRR and external devices using IP networking. The module will handle
both TCP and UDP simultaneously. If using TCP, one connection is by default created for every outbound message. This
is to avoid problems with TCP connections staying open for longer periods.

The IP module does not use packet boundaries to separate data records. When using UDP, it is therefore important
to make sure that data is not split into many packets which might cause parts of a message to disappear without this
being detected.

Serial to ethernet converters often split up messages into many datagrams by default, make sure they are configured
correctly and check that there is only one message per datagram with a network analyzer like `Wireshark`. If fragmentation
is a problem or the messages are too big to fit in single datagrams, use TCP instead.

#### Usage example with barcode reader and ACK messages
A simple setup using the IP module can be to process barcodes from a scanner and send ACK back. The IP information
in an RRR message (where it came from) is always preserved internally in RRR. This makes it possible to simply return
a message to the IP module if we wish to send a reply.

1. Scanner sends a barcode to RRR using UDP (for instance STX 'BLABLA128' ETX)
2. IP module receives and parses the UDP packet
3. A Perl or Python script does some processing of the barcode
4. The contents of the reply ACK message is added to the message (for instance STX 'A' ETX)
5. The IP Module sends the packet back to the scanner.

In this configuration example, an instance of the IP module both gives data to the Perl module instance, and also reads
data from it.
The data which IP receives from network is put into an RRR Array Message with three fields: `start`, `message` and `end`.
If the syntax in the received data is not correct, the data is ignored. By saving the start and end values, we don't have to
worry about what they actually are when processing the message.

When the Perl module generates the reply, it creates an additional array value called `reply`. The IP module is then configured
to find three fields `start`, `reply` and `end` in messages from Perl and send them out concatenated together.
While the RRR message still contains the original `barcode` field once it returns to the IP module,
this field is ignored in this example. Messages from the barcode reader(s) are delivered to UDP port 3333.

The following RRR config script `rrr-devicemaster.conf` will set everything up:

	[instance_ip]
	module=ip
	senders=instance_perl5
	ip_input_types=stx1#start,nsep#barcode,sep1#end
	ip_udp_port=3333
	ip_array_send_tags=start,reply,end
	
	[instance_perl5]
	module=perl5
	senders=instance_ip
	perl5_file=/home/rrr/devicemaster.pl
	perl5_process_sub=process
	
The following Perl script `/home/rrr/devicemaster.pl` will process the messages:

	#!/usr/bin/perl -w

	package main;

	use rrr::rrr_helper;
	use rrr::rrr_helper::rrr_message;

	sub process {
        	my $message = shift;
		
		# Do message processing
		my $processing_succeeded = 1;
		
		# Send reply if everything is OK
		if ($processing_succeeded) {
			# Push ACK reply value to the message and send it
			
			$message->push_tag_blob("reply", "A", 1);

			# IP information is already in the message, as well as
			# start and end separators. This call will cause the IP
			# module to receive the message.
			$message->send();
		}
		
		return 1;
	}
}

There are some more advanced example configuration files in `/misc/test_configs`, including how to read the barcode.

### mqttbroker (run an MQTT broker)
Starts an MQTT broker which any MQTT client can use to exchange messages. The broker supports TLS, ACL and authentication, have
a look at `man rrr.conf`.

### mqttclient (run an MQTT client)
Starts an MQTT client which can connect to any MQTT server. Messages can be read from other modules and published
to a MQTT broker, and it is possible to subscribe to topics to receive messages other modules can receive. Two RRR MQTT
clients can exchange RRR messages through any MQTT broker, and an arbitrary number of clients can run in each RRR program.

Below follows an example configuration which uses RRR to receive data records from an external MQTT client and save it to
an InfluxDB database:

	[my_mqtt_broker]
	module=mqttbroker
	
	[my_mqtt_client]
	module=mqttclient
	mqtt_server=localhost
	mqtt_subscribe_topics=a/+/#

	# Array definition of the data received from the MQTT broker
	mqtt_receive_array=fixp#loadavg,sep1,ustr#uptime,str#hostname
	
	[my_influxdb]
	module=influxdb

	# Read messages from the MQTT client
	senders=my_mqtt_client

	# Parameters used when writing to the InfluxDB server
	influxdb_server=localhost
	influxdb_database=mydb
	influxdb_table=stats

	# Tags and fields to retrieve from the received RRR messages and write to InfluxDB
	influxdb_tags=hostname
	influxdb_fields=uptime,loadavg->load

Use your favorite MQTT client to publish a message with a data record to the RRR broker
which the RRR MQTT client then receives and parses. Refer to the `ARRAYS` section
below on how to specifiy different data types.

	mosquitto_pub -t "a/b/c" -m "3.141592,12345678\"myserver.local\""
	
Please note that RRR does not provide a stand-alone MQTT client.

### ipclient (send messages between RRR instances over UDP)
This module is useful when messages need to be transferred over lossy connections where TCP doesn't work very well.

The `ipclient` module keeps track of all messages and makes sure that they are delivered excactly once (like MQTT QOS2).

The module may function both as a server which accepts connections and a client (also simultaneously).

An RRR native protocol is used to transfer messages which means that an RRR program only can communicate with other RRR
programs using this module.

### mysql (store messages to database)
Reads messages from other modules and stores them in a MySQL database.

### influxdb (store messages to database)
Reads messages from other modules and stores them in a an InfluxDB database.

### socket (read data records from a UNIX socket)
The socket module listens on a socket and parses data records it receives before forwarding them
as RRR messages to other modules. It expects to receive records with data types defined in an `array definition`. This
is useful when it's practical to pass over data to RRR locally using scripts.

A binary, `rrr_post`, is provided to communicate with the socket module. The type of input data is defined in its
arguments, and an RRR array message for every record is created and sent into RRR over the socket.

Below follows an example configuration where a data record is created locally and then sent to RRR using `rrr_post`
to be saved in an InfluxDB database.

	[my_socket]
	module=socket
	socket_path=/tmp/my_rrr_socket.sock
	socket_receive_rrr_message=yes

	[my_influxdb]
	module=influxdb

	# Read messages from the socket module
	senders=my_socket

	# Parameters used when writing to the InfluxDB server
	influxdb_server=localhost
	influxdb_database=mydb
	influxdb_table=stats

	# Tags and fields to retrieve from the received RRR messages and write to InfluxDB
	influxdb_tags=hostname
	influxdb_fields=uptime,loadavg->load

Use `rrr_post` to parse the input data record, which in this case is provided on standard input.

	echo "3.141592,12345678,\"myserver.local\"" | rrr_post /tmp/my_rrr_socket.sock -a fixp#loadavg,sep1,ustr#uptime,sep1,str#hostname -f - -c 1

### python3 (generate and/or modify messages by a custom python program)
The python3 module use a custom user-provided program to process and generate messages. Special RRR-
objects which resemble RRR internals are provided.

A custom python program might look like this, check out `man rrr.conf` on how to make it run.

       from rrr_helper import *
       import time
       
       my_global_variable = ""

       def config(rrr_config: config):
            global my_global_variable

            # retrieve a custom setting from the configuration file. The get()
            # will update the "was-used" flag in the setting which stops a
            # warning from being printed.
            print ("Received configuration parameters")
            my_global_variable = config.get("my_global_variable")

            return True

       def process(socket: rrr_socket, message: rrr_message):
            # Return False if something is wrong
            if my_global_variable == "":
                 print("Error: configuration failure")
                 return False

            # modify the retrieved message as needed
            message.timestamp = message.timestamp + 1

            # queue the message to be sent back (optional) for python to give to readers
            socket.send(message)

            return True

       def source(socket: rrr_socket, message: rrr_message):
            # Set an array value in the template message
            my_array_value = rrr_array_value()
            my_array_value.set_tag("my_tag")
            my_array_value.set(0, "my_value")

            my_array = rrr_array()
            my_array.append(my_array_value)

            message.set_array(my_array)

            # queue the message to be sent back (optional) for python to give to readers
            socket.send(message)

            # sleep to limit output rate
            time.sleep(1)

            return True



The `rrr_helper` Python module is built into RRR and is only available when the script is called from this program.

### perl5 (generate and/or modify messages by a custom perl script)
The perl5 module makes it possible to process and generate messages in a custom-written
perl script. The first and only argument to the source- and generate-functions
is always a message. Modifications to the message in the script will be done to the
original message, hence there is no need to return the message.

A message can however be duplicated one or more times by calling its send()-method.

Below follows an example perl script.

	#!/usr/bin/perl -w

	package main;

	use rrr::rrr_helper;
	use rrr::rrr_helper::rrr_message;
	use rrr::rrr_helper::rrr_settings;

	my $global_settings = undef;

	sub config {
		# Get the rrr_settings-object. Has get(key) and set(key,value) methods.
		my $settings = shift;

		# If needed, save the settings object
		$global_settings = $settings;

		# Custom settings from the configuration file must be read to avoid warning messages
		# print "my_custom_setting is: " . $settings->get("my_custom_setting") . "\n";

		# Set a custom setting
		$settings->set("my_new_setting", "5");

		return 1;
	}

	sub source {
		# Receive a newly generated template message
		my $message = shift;

		# Do some modifications
		$message->{'timestamp'} = $message->{'timestamp'} - $global_settings->get("my_custom_setting");

		print "source:  new timestamp of message is: " . $message->{'timestamp'} . "\n";

		# Return 1 for success and 0 for error
		return 1;
	}

	sub process {
		# Get a message from senders of the perl5 instance
		my $message = shift;

		# Do some modifications to the message
		$message->{'timestamp'} = $message->{'timestamp'} - $global_settings->get("my_custom_setting");

		print "process: new timestamp of message is: " . $message->{'timestamp'} . "\n";

		# This can be used to duplicate a message. Not needed if we are not duplicating
		# $message->send();

		# Return 1 for success and 0 for error
		return 1;
	}

### cmodule (generate and/or modify messages by a custom C module)
A C-module has `config`, `source` and `process` functions just like Perl and Python scripts, and the excact same internal
RRR framework handles these semantics.

Custom C-modules are usually compiled inside the RRR source tree. Read `/src/cmodules/README` for information on how to do this, usually
only a single C-file is needed to create a module.

### raw (drain output from other modules)
Read output from any module and delete it. Can also print out some information for each message it receives.

### dummy (generate dummy measurements)
Create dummy messages with current timestamp as value at some interval. 

## RRR-MESSAGES

An RRR-message contains some metadata and a class specifier which tells us what kind of
information and/or value it stores.
* Metadata for a message:
  * `Timestamp`
    Usually specified when a message was created.
  * `Topic`
     A topic to be used by MQTT modules
  * `Class` and `Data` 
    Raw data of a message or Array data
  * `Source-address`
    IP-address of a sender for messages which originated remotely.

On the network, all multibyte fields are in Big Endian format.

## SECURITY

If you use RRR for networking tasks, please note that there are no authentication or any kind of security
on many network functions. Although some modules have rate limiting causing them to drop incoming data if
they are overloaded, this is merely to avoid filling up memory with buffered messages.

If RRR is configured to read raw data from other hosts, this should happend on *closed networks* protected
by a firewall. A firewall should run on a separate machine to prevent accidental openings, do not rely
on software firewall rules on the machine running RRR.

The MQTT modules support both TLS and authentication. It is recommended, if security is needed, to use a
custom CA-certificate to validate certificates when receiving and making connections. The brokers
and clients must then use certificates signed with this CA-certificate to identify themselves. It is not safe
to rely on external CA-authorities, these are only safe when connecting to remote hosts using DNS. Anyone may
obtain such certificates.

In the configuration, specify a *ca_path* or *ca_file* to prevent the TLS library to look in standard system
directories for public CA-certificates. Even better: If the public certificates are not used for anything else,
delete them.

Make sure that *plain* listening mode is disabled for modules if you wish to require TLS, and also double check
afterwards that RRR does not listen to unsafe ports.

Note that RRR does not check for revoked certificates. If some certificate has been leaked and is compromised,
the CA-certificate used to signed this and all other certificates must be removed from all hosts and replaced. RRR
does not validate hostnames in certificates.

The HTTP modules can also use TLS in this setup for authentication, but there are no usernames or passwords. The
*ipclient* module, providing assured delivery over UDP, has no TLS. This also goes for the raw networking *ip* module.  

With the default RRR configuration file (dummy configuration), no networking is started. 

## ARRAY TYPES

### FIXED LENGTH TYPES
These types require the `length` field to be specified.

- `be` - Unsigned number in big endian binary format. Length must be in the range 1-8.
- `le` - Unsigned number in little endian binary format. Length must be in the range 1-8.
- `h` - Unsigned number in the endianness of the machine. Might be unsafe for network transfer. Length must be in the range 1-8.
- `blob` - Arbitrary binary data. Length must be in the range 1-1024.
- `sep` - One or more separator characters. Matches ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~ NULL ETX EOH LF CR and TAB.
Length must be in the range 1-64.
- `stx` - One or more STX or SOH characters. Length must be in the range 1-64.

Types `be`, `le` and `h` may be followed by an `s` after the length specifier to indicate that the input number is signed. If instead
`u` or nothing is set here, the value is treated as unsigned. No other types may have the sign flag set.

### WEAK DYNAMIC LENGTH TYPES
The lengths of these types are identified automatically and must not be set. They
cannot be at the end of a definition, nor follow after each other.

- `ustr` - An unsigned integer encoded with ASCII characters 0-9. Stored with 64-bits.
- `istr` - A signed integer encoded with ASCII characters 0-9 optionally preceeded by - or +. Stored with 64-bits.
- `fixp` - The RRR fixed decimal type encoded with ASCII characters 0-9 (and A-F). May include a single dot . to separate integer from fraction,
and the integer part may be preceded with a sign (- or +). Stored with 64-bits where 1 bit is the sign, 39 bits are the integer and
24 bits are the fraction. May be preceeded with 10# or 16# to indicate use of base 10 or base 16 conversion, default is base 10.

### STRONG DYNAMIC LENGTH TYPES
The lengths of these types are identified automatically and must not be set. They may be at the end of a definition.

- `msg` - A full RRR message complete with headers and checksums. A message has its length inside the message header.
- `str` - An arbitrary length string of characters beginning and ending with double quotes ". Double quotes inside the string must be escaped with \.
The surrounding quotes are not included in the final string.
- `nsep` - Match any numbers of bytes until a separator character NULL, SOH, STX, ETX, EOH, LF, CR or TAB is found. The separator itself will not be
included in the result, a sep should follow afterwards to take care of it.

### NOTES

* A space is not considered a separator, as spaces often exist inside different messages.
* The `nsep` type is not a complete negation of the `sep` type, the latter matches many more characters. The reason behind this is that messages with
arbitrary text and an end delimeter then can be matched using the simple definition `nsep,sep1`. The `nsep` will match letters, punctuations, spaces etc.,
and the `sep1` will match for instance a newline or ETX byte.

## CONTACT

github.com/atlesn/rrr

