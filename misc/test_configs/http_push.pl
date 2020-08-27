#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

#	my $fixp_5 = ($message->get_tag_all("my_fixp_5"))[0];

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	$message->clear_array();

	my $content = "It works!";

	my $response = "HTTP/1.1 200 OK\r\n";
	$response .= "Content-Type: text/plain\r\n";
	$response .= "Content-Length: " . (length $content) . "\r\n\r\n$content";

	$message->{'data'} = $response;
	$message->{'data_len'} = length $response;

	$message->{'topic'} =~ s/request/raw/;

	sleep(10);

	$message->send();

	return 1;
}
