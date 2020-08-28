# RRR HTTP PUSH SERVER WITH MQTT

## Introduction

A HTTP server processes request from clients and generates responses.
In this example, a web browser keeps a connection to the RRR HTTP server open on which it receives push requests.
The client opens a normal connection and sends a request, but it does not get a response until some data becomes ready.

Before trying out this example, you might want to look at a [simpler RRR HTTP-server configuration](http_server.md).

## Application

* Asynchronus messages to web browsers using HTTP push technique

## Configuration

The configuration uses the **httpserver**, **mqttclient** and **perl5** modules. A Perl5 program receives
requests from the HTTP server, but does not generate any responses until it receives some data from an
MQTT client. A handle is used to distinguish the clients (push receivers) from each other and the clients
receives only messages addressed to their handle.

The particular files used to run example are somewhat large, open them using these links:

* [http\_push\_mqtt.conf](http_push_mqtt.conf) - RRR configuration file
* [http\_push\_mqtt.pl](http_push_mqtt.pl) - The Perl script which handles HTTP requests
* [http\_push\_mqtt.html](http_push_mqtt.html) - A HTML file to open in a browser which gets push request

The setup consists of four parts:

* **httpserver** handles HTTP connections at a low-level (just parses and forwards data)
* **mqttclient** receives push messages which are to be sent to the clients (web browsers)
* **perl5**
  * Keeps track of open connections and their handle IDSs
  * Stores unsent messages coming from **mqttclient**
  * Runs its `source` subroutine on a regular basis to check if anything is to be sent/_pushed_ to the clients currently connected
* A **web broser** runs a Javascript which ensures that a connection to the server is always open

How it works:

* The client (run by the browser) uses a Javascript to connect to the RRR HTTP server. Whenever a connection is complete, it reconnects.
* **httpserver** receives HTTP requests and finds the `handle` parameter in the GET data
* The timeouts in **httpserver** have been set high to allow for HTTP push
* The `http_server_get_raw_response_from_senders` parameter prevents a response from being generated, and the connection is kept open as the HTTP server
  waits for a reply from some other module (in this case Perl5)
* The Perl5 program receives an RRR array message from the HTTP server containing the `handle` parameter and the topic to
  use when a response is to be generated
* The handle and topic are temporarily saved, but no response is immediately created.
* Since the clients are identified using `handle`, any new connections with the same `handle` will replace existing ones.
* Whenever the MQTT client receives a PUBLISH matching the topic `push/+`, the Perl5 will receive it.
* The latter part of the MQTT topic (after `/`) is the handle of the client to which the message is destined for.
* The messages are stored in a hash, and any new messages received with the same handle replace any old messages with matching handles.
* The `sub source` subroutine in the Perl5 program is run on a regular basis and checks if an active connection has received any message
* If a message matching the handle is found, an HTTP response with some JSON data is generated which the HTTP server then passes on to the client
* The message is deleted from the Perl5 program and the HTTP client closes the connection and immediately opens a new one
* If no message is found for a handle after five seconds, an empty response is sent to the client causing a new connection to be made

## Run the example

This example requires having two terminal windows and a browser open.

* In the browser, open the HTML file from locally on the filesystem (using an URL like `file:///home/...../http_push_mqtt.html`)
* In the first terminal, run RRR from inside the `examples/http`-directory. We use debuglevel 2 to see what's going on.

	``$ rrr -d 2 http_push_mqtt.conf``

* If a broker is not running on your machine, uncomment the MQTT broker lines in the configuration file
* When RRR is running and the browser has connected, the connection counter in the browser will increment once every five seconds as the Perl5 program generates empty responses
* Use `mosquitto_pub` to publish messages to the MQTT broker.

	``$ mosquitto_pub -d -t "push/1" -m "`date`"``

* In the topic, the `1` can be replaced with something else to use another handle.
* If the handle used in the topic matches the handle used by the client, it will receive the messages immediately

## Notes

In a production environment, care must be taken so that messages for unused handles **do not accumulate**.
This can be done by storing timestamps along with the messages.
This example has no queue for messages, and if they are generated too fast,
some of them will be overwritten before they are sent to the clients.

There is no need to check if a client is alive in the Perl5 program.
If it was to generate messages for disconnected or hung clients, the HTTP server will drop these.

Both messages from MQTT and the HTTP server are received by the Perl5 program in the same subroutine, `sub process`. Here, the
type of message is checked and appropriate actions and error handling are performed. The `sub source` function is run every 100 ms and
performs housekeeping as well as generating responses when messages are ready to be sent.

Raw HTTP including headers must be _manually_ generated by the Perl5 program, there are no helper functions in RRR to generate HTTP data.
You can however probably find some module on `CPAN` which assists in generating more complex HTTP responses.

By allowing long-lived connections, the HTTP server becomes vulnerable to **Denial of Service** attacks. Use on closed networks only. To allow
more simultaneous connections, increase the number of running threads with the parameter `http_server_worker_threads`. There is a minor CPU penalty by
having many threads running.

To achieve smooth operation, The HTTP server should always send a response to the web browser before it gives up.
This is achived by sending an empty response if no message has been sent after five seconds have passed (done by the Perl5 `source` subroutine during housekeeping).
The connection timeouts in the Javascript and RRR HTTP server configuration have in this example been set to ten seconds which ensures that a normal response is sent before any timeout occurs.

In some environments with one client per IP-address, the address can be used as a handle to ensure uniqueness.
The source IP can be extracted from messages in the Perl5 program by using `my ($ip, $port) = $message->ipget();`. In other cases some other more complex technique might be needed.

The HTTP server will drop messages if they have no GET or POST data, use some dummy parameter `?dummy=0` or configuration parameter `http_server_allow_empty_messages` to work around this or pass the raw HTTP request to Perl5 by using `http_server_receive_raw_data`. If the latter is used, two RRR messages might be generated for every incoming non-emtpy request.

In this example, the HTTP endpoint used (the part of the URL which is not the server address) does not matter.
If different endpoints are wanted, the parameter `http_server_receive_full_request` makes the HTTP server put different HTTP information in the RRR messages it generates, including the endpoint. Some logic which checks the endpoint can then be used in the  Perl5 program (read about **httpserver** in `man rrr.conf`).

The Python module can be used instead of the Perl5 module to process HTTP requests. 
