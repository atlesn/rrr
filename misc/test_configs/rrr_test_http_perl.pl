#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub process {
	my $message = shift;

	my $endpoint = $message->get_tag_all("http_endpoint");
	my $topic = $message->{"topic"};

	print "Endpoint: $endpoint\n";

	$message->clear_array();

	$message->push_tag_str("http_response_code", 200);
	$message->push_tag_str("http_content_type", "text/plain");
	$message->push_tag_str("http_body", "This is the response for endpoint $endpoint\n");

	$message->send();

	return 1;
}
