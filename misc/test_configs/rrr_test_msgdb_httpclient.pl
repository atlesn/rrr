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

# Note : Source and process are run by different instances

sub source {
	my $message = shift;

	my $dummy_4kb_string = "a" x 4096;

	if ($counter > 10000) {
		return 1;
	}

	my $base = "topic/" . int(rand(10000));

	if (rand(10) >= 9) {
		$message->push_tag_str('method', "PUT");
		$message->{'topic'} = $base . "/a";
		$message->send();
		$message->{'topic'} = $base . "/b";
		$message->send();
		$message->{'topic'} = $base . "/c";
		$message->send();
	}
	else {
		$message->push_tag_str('method', "GET");
		$message->send();
	}

	$message->push_tag("payload", $dummy_4kb_string);

	$counter++;

	return 1;
}

my %received_a;

sub process {
	my $message = shift;

	if (($message->get_tag_all("http_method"))[0] eq "GET") {
		$message->push_tag_str("http_response_code", 200);
	}
	else {
		($message->get_tag_all("http_endpoint"))[0] =~ /(\d+)\/(\w)/;

		my $pos = $1;
		my $letter = $2;

		if (!defined $letter || !defined $pos) {
			$message->push_tag_str("http_response_code", 200);
		}
		elsif ($letter eq "a") {
			$received_a{$pos} = 1;
			$message->push_tag_str("http_response_code", 200);
		}
		elsif (exists $received_a{$pos}) {
			print "Accept $pos\n";
			$message->push_tag_str("http_response_code", 200);
		}
		else {
			print "Reject $pos\n";
			$message->push_tag_str("http_response_code", 409);
		}
	}

	$message->send();

	return 1;
}
