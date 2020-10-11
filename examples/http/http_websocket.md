# RRR HTTP WEBSOCKET SERVER

## Introduction

A HTTP server processes request from clients and generates responses.
In this example, a web browser opens up a Websocket connection to the RRR HTTP server.
A Websocket connections starts out as a normal HTTP connection which is then upgraded to exchange Websocket frames.

## Application

* Asynchronus messages to and from web browsers using Websocket technique

## Configuration

The configuration uses the **httpserver** and **perl5** modules. The HTTP server negotiates websocket
with the web browsers. Messages received from the browser is sent to the **perl5** module, and the 
**perl5** module periodically generates messages for the browsers currently connected.

A unique ID for every HTTP connection is used internally in RRR to distinguish the browsers from each other.

The particular files used to run example are somewhat large, open them using these links:

* [http\_websocket.conf](http_websocket.conf) - RRR configuration file
* [http\_websocket.pl](http_websocket.pl) - The Perl script which handles and generates Websocket frames
* [http\_websocket.html](http_websocket.html) - An HTML file to open in a browser which creates a Websocket connection

The setup consists of three parts:

* **httpserver** handles HTTP- and Websocket connections
* A **browser** runs a Javascript which ensures that a Websocket connection to the server is always open
* **perl5**
  * Keeps track of open connections and their HTTP unique IDs
  * Saves the last received message from each clients
  * Runs its `source` subroutine on a regular basis and sends back the last received message to each connected browser

How it works:

* The `http_server_websocket_topic_filters=#` parameter in the configuration tells the HTTP server to allow Websocket connection upgrades on client request, regardless of the URL used (but the endpoint in the URL may not be empty).
* The **httpserver** and **perl5** modules are set up to read messages from each other.
* The client (run by the browser) uses a Javascript to connect to the RRR HTTP server. Whenever a connection is lost, it reconnects.
* The client sends 'alive' messages periodically. The Perl5 script receives these messages and identifies that a connection is open.
* The Perl5 scripts sends a message back to the client every two seconds containing the latest received data from the client
* If a browser is disconnected, the Perl5 script eventually detects that no messages are being sent from the browser, and it stops generating messages.

## Run the example

This example requires having one terminal window and a browser open.

* In the browser, open the HTML file from locally on the filesystem (using an URL like `file:///home/...../http_websocket.html`)
* In the first terminal, run RRR from inside the `examples/http`-directory. The Perl5 script will print some information about messages being received and generated without any debuglevel being active.

	``$ rrr http_websocket.conf``

* If the HTML file is opened in the browser prior to the RRR web server being started, the browser might wait a bit before it tries to reconnect.
* When the browser has connected, a green box will appear confirming that a websocket connection has been initiated.
* All messages received by the browser will be logged in the message box
* Custom messages can be sent over the Websocket connection by using the provided input form
* Note that in this particular example there is no immediate response by the Perl5 script to a received message, it only generates a message every two seconds

## Notes

By allowing long-lived connections, the HTTP server becomes vulnerable to **Denial of Service** attacks. Use on closed networks only. To allow
more simultaneous connections, increase the number of running threads with the parameter `http_server_worker_threads`. There is a minor CPU penalty by
having many threads running.

The Python module can be used instead of the Perl5 module to process Websocket messages. 

## See also
* [HTTP Push Server with MQTT](http_push_mqtt.md)
