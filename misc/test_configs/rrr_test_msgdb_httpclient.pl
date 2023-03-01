#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $counter = 0;

sub source {
	my $message = shift;

	if (rand(100) > 95) {
		sleep(1);
	}

	$message->{'topic'} = "topic/" . int(rand(10000));
	$message->push_tag_str('method', rand(10) >= 9 ? "PUT" : "GET");
	$message->send();

	return 1;
}
