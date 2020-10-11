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

sub escape {
	my $msg = shift;

	$msg =~ s/\\/\\\\/;
	$msg =~ s/"/\\"/;

	return $msg;
}

sub source {
	my $message = shift;

	my $timeout_limit = time - 10;

	my @to_destroy;

	foreach my $topic (keys(%connections)) {
		my $msg_truncated = $connections{$topic}->{'msg'};
		if (length $msg_truncated > 20) {
			$msg_truncated =~ /^(.{15}).+(.{4})$/;
			$msg_truncated = $1 . "..." . $2;
		}

		my $msg_escaped = escape($msg_truncated);
		my $data = "{\"msg\": \"Hello! Last message received was '$msg_escaped'\"}";

		if ($connections{$topic}->{'time'} < $timeout_limit) {
			print "Destroy " . $topic . "\n";
			push @to_destroy, $topic;
		}
		else {
			$message->{'data'} = $data;
			$message->{'data_length'} = length $data;
			$message->{'topic'} = $topic;

			print "Send topic " . $topic . "\n";

			$message->send();
		}
	}

	foreach my $topic (@to_destroy) {
		delete $connections{$topic};
	}


	return 1;
}

sub process {
	my $message = shift;

	print "Received topic " . $message->{'topic'} . " message length " . (length $message->{'data'}) . "\n";

	$connections{$message->{'topic'}} = {
		"time" => time,
		"msg" => $message->{'data'}
	};

	return 1;
}
