#!/usr/bin/perl -w

# Copyright 2020 Atle Solbakken <atle@goliathdns.no>

# This script is in the PUBLIC DOMAIN.
# It may be used in any way without any restrictions.

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

