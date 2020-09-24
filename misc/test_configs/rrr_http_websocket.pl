#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my @connections;

sub source {
	my $message = shift;

	my $data = "{\"Hello\"}";

	foreach my $topic (@connections) {
		$message->{'data'} = $data;
		$message->{'data_length'} = length $data;
		$message->{'topic'} = $topic;
		print "Send topic " . $topic . "\n";
		$message->send();
	}

	return 1;
}

sub process {
	my $message = shift;

	print "Received topic " . $message->{'topic'} . "\n";

	push @connections, $message->{'topic'};

	return 1;
}
