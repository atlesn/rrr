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
	http_server_get_raw_response_from_senders=yes
	
	[instance_perl5]
	module=perl5
	senders=instance_httpserver
	perl5_file=http_server.pl
	perl5_process_sub=process
	perl5_do_include_build_directories=yes

* **httpserver** receives HTTP requests, parses them, and puts any field from GET or POST into an RRR array message.
  In addition, the requested endpoint, HTTP method etc. is put into the array message due to the full request parameter.
* The server is configured to allow empty messages (zero length body, no GET/POST fields and not fields in URI)
* The perl5 module receives the request and prints out all received fields
* A raw response is generated and handed back to the httpserver
* The Perl5 is set to look for the required RRR Perl5 objects in build directories,
  this option is not required if RRR is properly installed on the system.
	
Had the **http_server_get_raw_response**-parameter not been set, the **httpserver** would instead have generated **204 No Content** for all requests. Doing this removes the need of creating the response in the Perl5 script.

### http\_server.pl

	#!/usr/bin/perl -w
	
	package main;
	
	use rrr::rrr_helper;
	use rrr::rrr_helper::rrr_message;
	use rrr::rrr_helper::rrr_settings;
	use rrr::rrr_helper::rrr_debug;
	
	my $debug = { };
	bless $debug, rrr::rrr_helper::rrr_debug;
	
	my $server_name = "RRR Perl5 HTTP server";
	
	sub process {
		my $message = shift;
	
		my @fields = $message->get_tag_names();
	
		$debug->msg(1, "Received a HTTP request in $server_name, topic was " . $message->{'topic'} . "\n");
		
		$debug->msg(1, "Dumping received fields:\n");
		foreach my $field (@fields) {
			my $to_print = "\t$field: ";
			$to_print .= join (", ", $message->get_tag_all($field));
			$to_print .= "\n";
			$debug->msg(1, $to_print);
		}
	
		my $response = "$server_name: ";
		$response .= (defined $message->get_tag_all("but_did_you_die") ? "No" : "Success!");
		
		my $http = "HTTP/1.1 200 OK\r\n";
		$http .= "Content-Type: text/plain\r\n";
		$http .= "Content-Length: " . (length $response) . "\r\n\r\n";
		$http .= $response;
		
		$message->clear_array();
	
		$message->{'data'} = $http;
		$message->{'data_len'} = length $http;
		$message->{'topic'} =~ s/request/raw/;
	
		$debug->msg(1, "Created a HTTP response in $server_name, topic is now " . $message->{'topic'} . "\n");
		
		$message->send();
	
		return 1;
	}
	
The process subroutine is called once per request.
All received fields are printed out and a raw HTTP response is generated.
Note that the array values must be cleared from the message before we add the raw data since array values overrides raw data and both cannot co-exist in a message.

We also need to modify the topic since **httpserver** expects **/httpserver/raw/xxx** topics back,
we simply replace the _request_ word with _raw_.  

To test things out, run `rrr http_server.conf` and use a web browser to access `http://localhost:8000/`.
You can also try to add some fields in the query string like `http://localhost:8000/?but_did_you_die`.
Watch the output from RRR as you access the URL.

The Python module can also be used instead of Perl5.  
