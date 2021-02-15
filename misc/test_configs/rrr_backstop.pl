#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub source {
	# Receive a template message
	my $message = shift;

	$debug->msg(1, "Created a message in source sub\n");

	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	$debug->msg(1, "Received a message in process sub\n");

	# Return 1 for success and 0 for error
	return 1;
}

