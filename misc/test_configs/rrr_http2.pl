#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $global_settings = undef;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	my $protocol = ($message->get_tag_all("http_protocol"))[0];

	$message->{'topic'} =~ s/request/raw/;
	$message->clear_array();

	my $body = "blabla\n";

	$message->{'data'} = "";

	if ($protocol == 1) {
		$message->{'data'} .= "HTTP/1.1 200 OK\r\nContent-Length: " . (length $body) . "\r\n\r\n";
	}

	$message->{'data'} .= $body;

	$message->send();

#	print "Send reply protocol \"$protocol\" topic \"$message->{'topic'}\" data \"$message->{'data'}\"\n";

	# Return 1 for success and 0 for error
	return 1;
}

