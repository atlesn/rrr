#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $count = 0;

sub send_message {
	my $message = shift;
	my $server = shift;
	my $port = shift;
	my $count = shift;

	$message->clear_array();
	$message->push_tag_str ("http_server", $server);
	$message->push_tag_str ("http_port", $port);

	for (my $i = 0; $i < $count; $i++) {
		$message->send();
	}
}

sub source {
	my $message = shift;

	if ($count < 50) {
		# Use invalid server to create HOL blocking situation
		# in httclient.
		send_message($message, "1.1.1.1", "9999", 5);
	}
	elsif ($count == 50) {
		# Send message with valid destination. The invalid
		# messages should be graylisted prior to this message
		# getting timed out.
		send_message($message, "localhost", "8880", 1);
	}
	else {
		# Done
	}

	$count++;

	return 1;
}
