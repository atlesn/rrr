# RRR BARCODE SCANNER RECEIVER

## Introduction

A barcode scanner reads barcodes of different formats, like Code128, checksums
the readings etc. and sends data to a more high-level device for processing.

The scanners are usually very configurable when it comes to which codes they accept
and reject and what sent messages look like. Some may also send multiple codes in
the same message.

If the scanner only has serial interface, a serial to Ethernet converter is used
to make UDP or TCP packets.

## Application

Whenever there is a need for receiving barcodes from scanners and do something with
them, like storing them in a database, RRR can be used for this. RRR will handle
all networking and message validation and parsing.

## Configurations

This configuration parses incoming barcodes which is received on UDP
port 3000 and publishes them to an MQTT broker. 

### barcode\_ip\_to\_mqtt.conf

	[instance_ip]
	module=ip
	ip_udp_port=3000
	ip_input_types=nsep#barcode,sep1
	
	[instance_mqttclient]
	module=mqttclient
	senders=instance_ip
	mqtt_server=localhost
	mqtt_publish_topic=barcode
	mqtt_publish_array_values=barcode
	
	# [instance_mqttbroker]
	# module=mqttbroker

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

