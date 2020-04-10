#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	print "process: timestamp of message is: " . $message->{'timestamp_from'} . "\n";

	print "control array array_values: " . $message->{'array_values'} . "\n";
	print "control array array_values: " . $message->{'array_tags'} . "\n";
	print "control array array_values: " . $message->{'array_types'} . "\n";

	push @{$message->{'array_values'}}, "test value";
	push @{$message->{'array_tags'}}, "test_tag";
	push @{$message->{'array_types'}}, "str";

	# This can be used to duplicate a message, no need if we are not duplicating
	# $message->send();

	# Return 1 for success and 0 for error
	return 1;
}

