#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	if (rand(10) > 5) {
		$message->{'topic'} = "";
		for (my $i = 0; $i < 100; $i++) {
			if ($i > 40) {
				$message->{'topic'} = "4";
			}
			$message->send();
		}
	}

	return 1;
}

sub process {
	my $message = shift;

#	print "Process $message->{'topic'}\n";

	if (rand(10) > 8) {
		$message->send();
	}

	return 1;
}

