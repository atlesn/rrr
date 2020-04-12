#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	print "perl5 process: timestamp of message is: " . $message->{'timestamp_from'} . "\n";

#	print "control array array_values: " . $message->{'array_values'} . "\n";
#	print "control array array_values: " . $message->{'array_tags'} . "\n";
#	print "control array array_values: " . $message->{'array_types'} . "\n";

	push @{$message->{'array_values'}}, "test value 1";
	push @{$message->{'array_tags'}}, "test_tag";
	push @{$message->{'array_types'}}, "str";

	push @{$message->{'array_values'}}, "test value 2";
	push @{$message->{'array_tags'}}, "test_tag_2";
	push @{$message->{'array_types'}}, "str";

	my @values = (1, 2, 3, 4);

	push @{$message->{'array_values'}}, \@values;
	push @{$message->{'array_tags'}}, "test_tag_3";
	push @{$message->{'array_types'}}, "h";

	push @{$message->{'array_values'}}, "A";
	push @{$message->{'array_tags'}}, "test_tag_blob";
	push @{$message->{'array_types'}}, "blob";

	# This can be used to duplicate a message, no need if we are not duplicating
	$message->send();
	#$message->send();
	#$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

sub source {
	my $message = shift;

	print "perl5 source: timestamp of message is: " . $message->{'timestamp_from'} . "\n";

	push @{$message->{'array_values'}}, "test value";
	push @{$message->{'array_tags'}}, "test_tag_str";
	push @{$message->{'array_types'}}, "str";

	my @values = (1, 2, 3, 4);

	push @{$message->{'array_values'}}, \@values;
	push @{$message->{'array_tags'}}, "test_tag_h";
	push @{$message->{'array_types'}}, "h";

	push @{$message->{'array_values'}}, "A";
	push @{$message->{'array_tags'}}, "test_tag_blob";
	push @{$message->{'array_types'}}, "blob";

	$message->send();

	return 1;
}
