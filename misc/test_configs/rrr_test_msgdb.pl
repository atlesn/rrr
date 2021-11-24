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

my $topic_counter = 0;

sub process {
	my $message = shift;

	$message->{'topic'} = "topic/$topic_counter";
	$message->send();

	$topic_counter++;

	return 1;
}
