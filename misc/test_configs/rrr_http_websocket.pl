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

my %connections;

sub source {
	my $message = shift;

	my $data = "{\"msg\": \"Hello\"}";

	my $timeout_limit = time - 10;

	my @to_destroy;

	foreach my $topic (keys(%connections)) {
		if ($connections{$topic}->{'time'} < $timeout_limit) {
			print "Destroy " . $topic . "\n";
			push @to_destroy, $topic;
		}
		$message->{'data'} = $data;
		$message->{'data_length'} = length $data;
		$message->{'topic'} = $topic;
		print "Send topic " . $topic . "\n";
		$message->send();
	}

	foreach my $topic (@to_destroy) {
		delete $connections{$topic};
	}


	return 1;
}

sub process {
	my $message = shift;

	print "Received topic " . $message->{'topic'} . "\n";

	$connections{$message->{'topic'}} = {
		"time" => time
	};

	return 1;
}
