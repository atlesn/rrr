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

	$debug->msg(2, "Received a HTTP request in $server_name, topic was " . $message->{'topic'} . "\n");
	
	$debug->msg(2, "Dumping received fields:\n");
	foreach my $field (@fields) {
		my $to_print = "\t$field: ";
		$to_print .= join (", ", $message->get_tag_all($field));
		$to_print .= "\n";
		$debug->msg(2, $to_print);
	}

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];

	my $response = "<!DOCTYPE HTML>\n<html>\n<head><title>$server_name</title></head>\n\n<body>\n";

	if ($endpoint !~ /frame/) {
		$response .= "<iframe src=\"/frame$endpoint\" style=\"border: 0px solid #000; background-color: #ddd;\"></iframe>\n";
	}
	else {
		$response .= (defined $message->get_tag_all("but_did_you_die") ? "No" : "Success!");
	}
	
	$response .= "</body></html>";

	$message->clear_array();

	$message->push_tag_str("http_content_type", "text/html");
	$message->push_tag_str("http_body", $response);

	$debug->msg(2, "Created a HTTP response in $server_name, topic is now " . $message->{'topic'} . "\n");
	
	$message->send();

	return 1;
}

