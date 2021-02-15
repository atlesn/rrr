# RRR HTTP SERVER

## Introduction

A HTTP server processes request from clients and generates responses.
In this example, we use the **httpserver** module to receive requests and then the Perl5 module to generate responses.

In HTTP it is very easy go generate header fields, but they are very difficult to parse.
The **httpserver** therefore only help us out with parsing HTTP data, and not generating header values in some high-level way.
The Perl5 script will due to this create the HTTP header itself.

## Application

* Receive messages from other machines or devices and process them i a custom way
* Avoid the need for a full HTTP server just to solve simple tasks
* Use the same Perl5 script for messages coming in on multiple protocols, like MQTT

## Configuration

The configuration uses the **httpserver** and **perl5** modules, which both read from each other.

### http\_server.conf

	[instance_httpserver]
	module=httpserver
	senders=instance_perl5
	http_server_port_plain=8000
	http_server_receive_full_request=yes
	http_server_fields_accept_any=yes
	http_server_allow_empty_messages=yes
	http_server_get_response_from_senders=yes
	
	[instance_perl5]
	module=perl5
	senders=instance_httpserver
	perl5_file=http_server.pl
	perl5_process_sub=process
	perl5_do_include_build_directories=yes

* **httpserver** receives HTTP requests, parses them, and puts any fields from GET, PUT or POST into an RRR array message.
  In addition, the requested endpoint, HTTP method etc. is put into the array message due to the full request parameter.
* The server is configured to allow empty messages (zero length body, no GET/POST fields and no fields in URI)
* The perl5 module receives the request and prints out all received fields
* A response is generated and handed back to the httpserver
* The Perl5 is set to look for the required RRR Perl5 objects in build directories,
  this option is not required if RRR is properly installed on the system.

### http\_server.pl

	(File available in the source directory)
	
Had the **http_server_get_response_from_senders**-parameter not been set, the **httpserver** would instead have generated **204 No Content** for all requests.
Doing this removes the need of creating the response in the Perl5 script, if generating a specific response is not needed.
	
The process subroutine is called once per request.
All received fields are printed out and a HTTP response is generated.
The message is sent back to the httpserver preserving it's topic, it will then be sent back to the same connection from which the request originated.

To test things out, run `rrr http_server.conf` and use a web browser to access `http://localhost:8000/`.
You can also try to add some fields in the query string like `http://localhost:8000/?but_did_you_die=1`.
Watch the output from RRR as you access the URL.

The Python module can also be used instead of Perl5.  
