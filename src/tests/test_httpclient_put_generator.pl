#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $loops = 0;

my $PRIO_TOPIC_PREFIX = "prio";
my $NONPRIO_TOPIC_PREFIX = "nonprio";
my $PER_TOPIC_COUNT = 20;

sub source {
	my $message = shift;

	if ($loops == 0) {
		my $value;

		for (my $i = 0; $i < $PER_TOPIC_COUNT; $i++) {
			$message->{'topic'} = "$PRIO_TOPIC_PREFIX/$i";
			$message->send();
			$message->clear_array();

			$message->{'topic'} = "$NONPRIO_TOPIC_PREFIX/$i";
			$message->send();
			$message->clear_array();
		}
	}
	else {
		return 1;
	}

	$loops++;

	return 1;
}

sub process {
	my $message = shift;


	return 1;
}
