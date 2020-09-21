#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub config {
	# Get the rrr_settings-object. Has get(key) and set(key,value) methods.
	my $settings = shift;

	sleep(2);

	return 1;
}

sub source {
	# Receive a template message
	my $message = shift;

	$debug->msg(1, "Alive\n");

	return 1;
}
