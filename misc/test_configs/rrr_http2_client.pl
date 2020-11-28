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

sub source {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	$message->push_tag("http_server", "localhost");
	$message->push_tag("http_endpoint", "/");
	$message->push_tag("http_port", "443");
	$message->push_tag("a", "aaa");
	$message->push_tag("b", "bbbbbbbbb");

	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

