#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my %global_settings;

sub config {
	my $settings = shift;
	$global_settings{"data_size_min"} = $settings->get("data_size_min");
	$global_settings{"data_size_max"} = $settings->get("data_size_max");
	return 1;
}

sub source {
	# Receive a template message
	my $message = shift;

	my $size = rand($global_settings{"data_size_max"} - $global_settings{"data_size_min"}) +
		$global_settings{"data_size_min"};

	my $data = "x" x $size;

#	print "Size: $size\n";

	$message->set_tag_str("data", $data);
	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}
