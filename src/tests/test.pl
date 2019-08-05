#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

sub config {
	my $settings = shift;

	print "perl5 senders: " . $settings->get("senders") . "\n";

	return 1;
}

sub source {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'};

	return 1;
}

sub process {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'};

	print "perl5 timestamp: " . $message->{'timestamp_from'} . "\n";

	return 1;
}
