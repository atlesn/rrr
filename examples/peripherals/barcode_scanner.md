# RRR BARCODE SCANNER RECEIVER (USB/Serial/TCP/UDP)

## Introduction

A barcode scanner reads barcodes of different formats, like Code128, checksums
the readings etc. and sends data to a more high-level device for processing.

The scanners are usually very configurable when it comes to which codes they accept
and reject and what sent messages look like. Some may also send multiple codes in
the same message.

If the scanner only has serial interface, a serial to Ethernet converter is used
to make UDP or TCP packets. RRR can also read directly from USB and serial scanners
connected to a computer.

## Application

Whenever there is a need for receiving barcodes from scanners and do something with
them, like storing them in a database, RRR can be used for this. RRR will handle
all networking and message validation and parsing.

## Configurations

### barcode\_ip\_to\_mqtt.conf

	[instance_ip]
	module=ip
	ip_udp_port=3000
	# Uncomment to listen also on TCP port
	# ip_tcp_port=3000
	ip_input_types=nsep#barcode,sep1
	
	[instance_mqttclient]
	module=mqttclient
	senders=instance_ip
	mqtt_server=localhost
	mqtt_publish_topic=barcode
	mqtt_publish_array_values=barcode
	
	# [instance_mqttbroker]
	# module=mqttbroker

This configuration parses incoming barcodes which is received on UDP
port 3000 and publishes them to an MQTT broker. 

* The **ip** module is set up to listen on UDP port 3000
* Since the barcodes we receive are encoded in ASCII, we parse it using the
  type 'nsep' (non-separator) which will read any number of non-special characters
* The scanners sends a newline, carriage return etc. at the end of the barcode,
  we will accept any kind of commonly used terminator/separator
* The **mqttclient** module receives one RRR message from the **ip** module for
  every received barcode
* The value tagged with 'barcode' (**ip** did this) is extracted from the message
  and put into an MQTT message and published on a broker running on localhost under
  the topic 'barcode'
  
If you don't already have a broker running, you may install a standard broker
like Mosquitto or uncomment the two last lines to run the RRR MQTT broker. The MQTT
brokers usually work out-of-the-box without any configuration.

** Do not run brokers openly on the Internet, special configuration is required for this **

RRR will accept data even if it is split up into multiple packets. With UDP this can become
a problem when using serial to Ethernet converters if a long barcode is split up into multiple UDP
packets and one of the packets in the middle is lost. To solve this without moving over to
TCP (which may cause timeout/state problems), the serial to ethernet converter should be
configured not to send any data until it receives the terminator character from the scanner.

To play around with this setup, we will open three terminal windows at once. One window will function
as the scanner, one window will run RRR, and one window will subscribe to the 'barcode' topic on
the MQTT broker.

For this test you need to have **netcat**, which will be our barcode scanner, and a stand-alone MQTT
client installed, like **mosquitto-clients**.

* Make sure all three terminal windows are visible at the same time
* Start RRR in the second window `rrr -d 3 barcode_ip_to_mqtt.conf`, we enable
  some debugging with `-d 3` to see what's going on
* Start the MQTT subscribing client in the third window `mosquitto_sub -t barcode`
* In the first window, scan a barcode using `echo "BARCODEFTW" | nc -u localhost 3000`. The `echo`
  command will add a newline for us after the barcode.
* The barcode should be printed out by the subscribing MQTT client. Note that `mosquitto_sub` will
  print a newline for every message received, which is not actually present in the message.

### barcode\_different\_scanners.conf

	{TELEGRAM}
	be1#prefix
	IF ({prefix} != 0x02 && {prefix} != 0x01)
		REWIND1
		;
	nsep#barcode,sep1
	;
	
	[instance_ip]
	module=ip
	ip_udp_port=3000
	ip_input_types={TELEGRAM}
	
	[instance_raw]
	module=raw
	senders=instance_ip
	raw_print_data=yes


This configuration parses incoming barcodes from two different types of scanners.
One type sends data in the format `<STX>barcode<ETX>` and the other type uses `barcode<CR>`.

* Since array tree conditional branching is required, the definition is placed by itself in the configuration file.
This allows us to use newlines in the definitions to enhance readability.
Also note that the first semicolon terminates the `IF` block, and the last one the whole array tree.
* First, a byte is parsed and saved with the tag `prefix`. We use `be1` to match any byte.
* If this byte is an `STX` (ASCII decimal 2), we continue parsing the barcode followed by a separator
* If the byte is not an `STX`, we `REWIND` one array position before starting to parse the barcode
* For convenience, we also allow `SOH` (ASCII decimal 1) in addition to `STX`

Since we're only playing around, we use the raw module to dump all (valid) data received in the IP module.

To test this, use two terminals. In the first one, run the program with debuglevel 2 set `rrr -d 2 barcode_different_scanners.conf`. In the second one, use netcat to send different telegrams:

* `echo -ne "\002WITH PREFIX STX\003" | nc -u localhost 3000`
* `echo -ne "\001WITH PREFIX SOH\004" | nc -u localhost 3000`
* `echo -ne "WITHOUT PREFIX\r" | nc -u localhost 3000`

Study the output of RRR which now dumps parsed array values.
Notice that the `prefix` value is only present when we send `STX` first in our telegram.

### barcode\_usb\_serial.conf

	[instance_file]
	module=file
	file_directory=/dev
	file_prefix=intermec
	file_input_types=nsep#barcode,sep1
	file_try_keyboard_input=yes
	file_topic=my_barcode_topic
	
	[instance_raw]
	module=raw
	senders=instance_file
	raw_print_data=yes

The RRR **file** module can read from files, sockets, FIFO pipes and character devices. While running, **file** will probe the specified directory periodically to find new entries opens them. A prefix may be specified
to filter out which files to use.

If you are using Linux, you may use **udev** to give different devices aliases when they are connected. In this example, a **udev** rule has been added to the file `/etc/udev/rules.d/99-intermec.rules` which creates
symbolics links like `/dev/intermec-scanner0`. **file** then finds these and ignore other files not starting with `intermec`. The program `udevadm` can be used to figure out how to match a device in a udev rule.

	ACTION=="add", ATTRS{manufacturer}=="Intermec", SUBSYSTEM=="input", PROGRAM="/bin/sh -c 'logger -p user.info New barcode scanner detected, used as keyboard'", MODE="0660", OWNER="rrr", GROUP="rrr", SYMLINK+="intermec-scanner%n"
	ACTION=="add", ATTRS{manufacturer}=="Intermec", SUBSYSTEM=="tty", PROGRAM="/bin/sh -c 'logger -p user.info New barcode scanner detected, used as serial port'", MODE="0660", OWNER="rrr", GROUP="rrr", SYMLINK+="intermec-scanner%n"

If you do not have **udev**, you can specify the full filename of the device you wish to read from in `file_prefix` like `ttyS0`, or `ttyS` to read from all serial ports. Don't specify `/dev` without
any `file_prefix`, this will cause RRR to try to read from everything in there.

USB scanners can often be configured to act either as a keyboard or as a virtual serial port. Currently,
keyboard scanners are only supported on Linux and FreeBSD. When keyboard scanners are opened, they are *hijacked* so that
the input from them is not used by the X-window system or terminals. Make sure you don't allow RRR to open
your real keyboard as it might then become unusable while RRR is running.

If keyboard devices are opened without `file_try_keyboard_input` being set to `yes` or on non-Linux/FreeBSD systems,
the raw event data (key up, key down etc.) will be received by RRR. While it may be a bit cumbersome to implement, it is certainly possible to parse this data into and RRR array and have a Perl or Python script convert the keys into characters.


### barcode\_all.conf

	{TELEGRAM}
	be1#prefix
	IF ({prefix} != 0x02 && {prefix} != 0x01)
		REWIND1
		;
	nsep#barcode,sep1
	;
	
	{LOCAL}
	nsep#barcode,sep1
	;
	
	[instance_ip]
	module=ip
	ip_udp_port=3000
	# Uncomment to listen also on TCP port
	# ip_tcp_port=3000
	ip_input_types={TELEGRAM}
	
	[instance_file]
	module=file
	file_directory=/dev
	file_prefix=intermec
	file_input_types={LOCAL}
	file_try_keyboard_input=yes
	file_topic=my_barcode_topic
	
	[instance_mqttclient]
	module=mqttclient
	senders=instance_ip,instance_file
	mqtt_server=localhost
	mqtt_publish_topic=barcode
	mqtt_publish_array_values=barcode

This configuration enables reading from TCP, UDP and local scanners at the same time, publishing
the barcodes to an MQTT broker.
