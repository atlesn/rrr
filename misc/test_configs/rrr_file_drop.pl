#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $current_time = undef;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	my $time = ($message->get_tag_all("time"))[0];
	my $class = ($message->get_tag_all("class"))[0];
	my $text = ($message->get_tag_all("text"))[0];

	if (defined $time) {
		# Process time header
		$current_time = $time;
	}
	elsif (!defined $class) {
		$debug->msg(0, "Field 'class' missing in message\n");
	}
	elsif (!defined $text) {
		$debug->msg(0, "Field 'text' missing in message\n");
	}
	elsif (!defined $current_time) {
		$debug->msg(0, "Time header was not yet retrieved, ignoring message\n");
	}
	else {
		# Remove right-pad 
		$text =~ s/\s+$//;
		$class =~ s/\s+$//;

		$debug->dbg(2, "$current_time <$class> $text\n");

		# Remove all fields from message
		$message->clear_array();

		# Push back all values as well as newline to make
		# the MQTT PUBLISH message look nice

		$message->set_tag_str("time", $current_time);
		$message->push_tag_blob("", "\n", 1);

		$message->set_tag_str("class", $class);
		$message->push_tag_blob("", "\n", 1);

		$message->set_tag_str("text", $text);
		$message->push_tag_blob("", "\n", 1);

		$message->send();
	}

	# Always return success, all errors are handled
	return 1;
}
