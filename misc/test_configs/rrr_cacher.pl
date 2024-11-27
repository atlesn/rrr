#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $global_settings = undef;

sub process {
	my $message = shift;

#	$debug->msg(1, "Got a message, topic is " . $message->{'topic'} . "\n");

	$message->clear_array();
	$message->push_tag("my_data", " " x 256);
	$message->send();

	return 1;
}
