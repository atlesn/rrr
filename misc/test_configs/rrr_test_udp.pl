#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	# Do some modifications to the message
	$message->{'timestamp_from'} = $message->{'timestamp_from'} - $global_settings->get("my_custom_setting");

	# print "process: new timestamp of message is: " . $message->{'timestamp_from'} . "\n";

	# This can be used to duplicate a message, no need if we are not duplicating
	# $message->send();

	# Return 1 for success and 0 for error
	return 1;
}

