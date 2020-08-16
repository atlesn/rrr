# RRR HTTP FORWARDER

## Introduction

A HTTP forwarder receives requests from clients and passes them on to a remote server.
The original requests are copied and forwarded untouched, and the responses are also sent back in their original state.

The forwarder is **not** a proxy server, each setup may only forward messages to one remote server at a single time.
It is however possible to forward requests to a proxy server.

## Application

There are multiple applications for a HTTP forwarder:

* Combine multiple requests into a single HTTP connection using keep-alive
* Convert plain-text connections into TLS connections
* Buffer requests in case remote server is unreachable
* "Tap" off requests and responses and process them in another RRR module, like for logging purposes

## Configurations

The modules **httpserver** and **httpclient** are designed to work together to achieve forwarding capabilities.
Both of them can take raw data from requests and responses and put them into RRR messages, as well as taking raw data from messages and using as request and response.

The simplest configuration works like this:

1. The **httpserver** module receives a request from some client
2. The full request (after figuring out it's length) is put into an RRR message with a *topic* containing a unique ID
3. **httpclient** polls the newly created message from **httpserver**
4. A connection is established (if not done previously) to the remote server, and the whole request is sent untouched.
5. The remote server sends a response back to **httpclient**
6. Using the same *topic* as in the RRR message containing the request, an RRR message is created with the response.
7. The **httpserver** module picks up the response, checks the unique ID in the *topic* and sends the response back to the client.

### http\_forwarder.conf (minimum for forwarding)

	[instance_httpserver]
	module=httpserver
	senders=instance_httpclient
	http_server_port_plain=8000
	http_server_receive_raw_data=yes
	http_server_get_raw_response_from_senders=yes
	
	[instance_httpclient]
	module=httpclient
	senders=instance_httpserver
	http_server=localhost
	http_keepalive=yes
	http_message_timeout_ms=1000
	http_receive_raw_data=yes
	http_send_raw_data=yes

* Both modules have each other specified as senders
* There are two options for each module controlling "raw" mode. They may also be used independently, but all are needed to achieve forwarding capability
* The connection from the originating client to httpserver will be kept open until a response is received from httpclient or a fixed timeout has elapsed
* httpclient will keep on trying to send each request to the remote server until the specified timeout is reached
* The keepalive parameter in httpclient causes the connection to the remote server to be held open untill the server closes it.
  When the server closes the connection, the next message to be sent will produce a socket error.
  A new connection is then made and the message will be sent again.

### http\_forwarder\_intercept.conf (observe traffic going through)

It's possible to duplicate the messages received to log them or process them in some way or another.
In this example, the raw module is used to print out the requests going from httpserver to httpclient.

	[instance_httpserver]
	module=httpserver
	senders=instance_httpclient
	http_server_port_plain=8000
	http_server_receive_raw_data=yes
	http_server_get_raw_response_from_senders=yes
	http_server_receive_full_request=yes
	http_server_allow_empty_messages=yes
	
	[instance_duplicator]
	module=buffer
	senders=instance_httpserver
	buffer_do_duplicate=yes
	
	[instance_httpclient]
	module=httpclient
	senders=instance_duplicator
	topic_filter=httpserver/raw/+
	http_server=localhost
	http_keepalive=yes
	http_receive_raw_data=yes
	http_send_raw_data=yes
	http_message_timeout_ms=1000
	
	[instance_drain]
	module=raw
	senders=instance_duplicator
	raw_print_data=yes

In addition to the last example, we tell the httpserver to put some data from the requests into RRR array messages using the full request parameter.
We also specify to allow empty messages so that zero-length requests are also catched.

Now, for every request, two RRR messages will be generated.
One with raw data, like in the last example, and one with array data containing information about the request along with any request body.
Since the httpclient module only handles the raw message, we set a topic filter on its input so that only these are received.

The buffer module is used between httpserver and httpclient to create copies of each message.
The raw module then reads from this buffer, and if debuglevel 2 is set, we can see the requests passing through in the output of the RRR program.