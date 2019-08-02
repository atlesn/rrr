#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

sub config {
	# Get the rrr_settings-object. Has get(key) and set(key,value) methods.
	my $settings = shift;

	# If needed, save the settings object
	$global_settings = $settings;

	# Custom settings from the configuration file must be read to avoid warning messages
	print "my_custom_setting is: " . $settings->get("my_custom_setting") . "\n";

	# Set a custom setting
	$settings->set("my_new_setting", "5");
	print "my_new_setting is: " . $settings->get("my_new_setting") . "\n";

	return 1;
}

sub source {
	# Receive a template message
	my $message = shift;

	# Do some modifications
	$message->{'timestamp_from'} = $message->{'timestamp_from'} - $global_settings->get("my_custom_setting");

	print "source:  new timestamp of message is: " . $message->{'timestamp_from'} . "\n";

	# Sleep to ratelimit
	sleep 1;

	# Return 1 for success and 0 for error
	return 1;
}

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	# Do some modifications to the message
	$message->{'timestamp_from'} = $message->{'timestamp_from'} - $global_settings->get("my_custom_setting");

	print "process: new timestamp of message is: " . $message->{'timestamp_from'} . "\n";

	# This can be used to duplicate a message, no need if we are not duplicating
	# $message->send();

	# Return 1 for success and 0 for error
	return 1;
}
