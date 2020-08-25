# RRR NETWORK PRINT SPOOLER

## Introduction

Many printers have networking and support receiving prints in either PS (PostScript) or their
native format. They have an internal queue which allows multiple different to hosts to connect
to them and send data. These queues are however usually quite small, and when it is full, the
printer might stop accepting new connections or stop receiving data on connections which are
already open.

To handle these blocking situations, hosts must have some kind of send buffer. On a desktop computer,
the printer drivers will take care of this, but if we just need to send data which already is in
a format the printer understands, we don't need to use the driver.

## Application

Sending PostScript or some native format like ZPL to a TCP capable printer and manage print spooling.

## Configurations

### print\_spooler.conf
	
	[instance_mqttclient]
	module=mqttclient
	mqtt_server=localhost
	mqtt_subscribe_topics=prints
	
	[instance_ip]
	module=ip
	senders=instance_mqttclient
	ip_send_multiple_per_connection=yes
	ip_smart_timeout=yes
	ip_send_timeout=5
	ip_timeout_action=drop
	ip_ttl_seconds=500
	ip_preserve_order=yes
	ip_target_host=localhost
	ip_target_port=9100
	ip_target_protocol=tcp
	ip_force_target=yes
	
	# Uncomment to run RRR MQTT broker
	# [instance_mqttbroker]
	# module=mqttbroker

The **ip** module is used to talk to the printer. It receives jobs from MQTT, print data arrives
in PUBLISH messages with the topic *prints* and their full body is the data to print. A single
print should arrive in a single PUBLISH packet to ensure it is not split up.

* A connection is made to the printer only when data is to be sent
* If there are multiple prints waiting to be sent, they may be sent on the same connection
* When a few messages have been sent, the connection is closed again
* Smart timeout means that messages further back in the queue time do not time out as long
  as other messages in the queue are being successfully sent
* If the printer does not respond at all, timeout occurs after 5 seconds, and messages are dropped
* If messages are stuck in the queue for more than 500 seconds, regardless of wether other
  ones have been sent in the mean time, they are dropped.
* Messages are sent in order according to when they were put into the queue
* Prints are delibered to `localhost` on TCP port 9100, and any IP information in the RRR messages
  is ignored.

The parameters `ip_smart_timeout` and `ip_preserve_order` have some performance penalty if there
is a lot (many thousands) of messages in the queue. The size of each message does not matter, usually
this is fine in this application. In addition to this, the penalty only becomes prominent when messages
are undeliverable and build up in the queue. 

To test this configuration, we use the program `mosquitto_pub` to publish our print to the MQTT broker
and netcat `nc` to act as the printer. If a broker is not currently running on the machine, the RRR broker
can be enabled in the configuration file.

Begin by creating a file containing the print job, put something like this into a file called `print`:

	XXXX
	X THIS IS MY PRINT
	XXXX

Have three terminal windows visible at the same time.

* In the first window, start RRR with some debugging enabled `rrr -d 2 print_spooler.conf`
* In the second window, start the netcat printer `while sleep 3; do nc -vv -l -p 9100; done`
* In the third window, publish the print to the MQTT broker using `mosquitto_pub -t prints -s < print`

To simulate a slow printer, netcat only accepts new connections every three seconds. If we publish many
prints, some will become blocked while netcat is not running. Messages like

	<0> <examples/peripherals/print_spooler.conf> Host '[127.0.0.1:9100]' graylisting for 2000 ms following connection error

may be printed by RRR before the messages are delivered after netcat starts listening. Graylisting prevents
spamming the network with connection attempts. The timer can be changed by setting ` ip_graylist_timeout_ms`. 
If we shut down netcat completely, timeout will occur for the messages:

	 <0> <examples/peripherals/print_spooler.conf> Send timeout for 1 messages in ip instance instance_ip

Since we specify `localhost` as the target for the **ip** module, both IPv6 and IPv4 connections will be
attempted. **ip** will always try to connect with all addresses a name resolves to and will use the first
one which succeeds. Warnings will be produced for the addresses which fail. Specifying `127.0.0.1` instead
as a target will enforce IPv4 use. If you have OpenBSD-style netcat, you can also listen on both adresses
by specifying `-46`.

### print\_spooler\_drop\_folder.conf

	[instance_file]
	module=file
	file_directory=/tmp/print_jobs
	file_prefix=job
	file_read_all_to_message=yes
	file_unlink_on_close=yes
	
	[instance_ip]
	module=ip
	senders=instance_file
	# Use this instead to combine with the MQTT-example
	# senders=instance_file,instance_mqttclient
	ip_send_multiple_per_connection=yes
	ip_smart_timeout=yes
	ip_send_timeout=5
	ip_timeout_action=drop
	ip_ttl_seconds=500
	ip_preserve_order=yes
	ip_target_host=localhost
	ip_target_port=9100
	ip_target_protocol=tcp
	ip_force_target=yes
	
Here, a local print job drop folder is used to pick up prints. The **ip** configuration is equal to
the previous example except that it reads from an instance of the **file** module.

The file module will look for files beginning with `job` in the directory `/tmp/print_jobs`. The full
contents of each file is put into RRR messages, and the file is afterwards deleted.

Create a file called `print` as in the previous example, and also create the drop folder `mkdir /tmp/print_jobs`. Have three terminal windows visible at the same time.

* In the first window, start RRR with some debugging enabled

	rrr -d 2 print_spooler_drop_folder.conf

* In the second window, start the netcat printer

	while sleep 3; do nc -vv -l -p 9100; done

* In the third window, put prints into the drop folder

	cp print /tmp/print_jobs/job-`date -Iseconds`

By default, **file** will probe for new files every 5 seconds. This timer can be changed with `file_probe_interval_ms`. Had `file_unlink_on_close` no been specified, the files in the directory
had not been deleted and same print jobs would have been sent over and over again.

If big jobs are to be printed, there's a chance that **file** will try to read the job before its completely
written out to disk. To prevent this, a file should first be called something which does not match the prefix in
`file_prefix` and then renamed by using `mv` when writing is complete.