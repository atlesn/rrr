#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my %results;

my $id_max = 3;
my $endpoint_prefix = "rrr/increment";
my @endpoint_suffixes = qw/A B C/;

my $TOPIC_CACHE = "cacher-test-3";
my $TOPIC_RESPONSE = "cacher-ok";

my $stage = 0;
my $result_count = 0;
my $request_count = 0;

sub source {
	my $message = shift;

	# - Source function should be called every 500 ms

	$message->{'topic'} = "cacher-test-3";

	if ($stage == 0) {
		$dbg->msg(1, "Send response\n");
		$message->set_tag_str("data", "data");
		$message->send();
		$stage = 1;
	}
	elsif ($stage == 1) {
		# Expect result from memory
		$dbg->msg(1, "Send request 1/2\n");
		$message->set_tag_str("request", "1");
		$message->send();
		$stage = 2;
		$request_count++;
	}
	elsif ($stage == 2) {
		# Expect result from msgdb
		$dbg->msg(1, "Send request 2/2\n");
		$message->set_tag_str("request", "1");
		$message->send();
		$stage = -1;
		$request_count++;
	}

	return 1;
}

sub process {
	my $message = shift;

	my $data = ($message->get_tag_all("data"))[0];

	if (!defined $data) {
		$dbg->msg(0, "Field 'data' missing in response\n");
		return 0;
	}

	$dbg->msg(1, "Process $message->{'topic'} (data '$data') $result_count<>$request_count stage $stage\n");

	if (++$result_count == $request_count && $stage == -1) {
		$message->{'topic'} = $TOPIC_RESPONSE;
		$message->send();
	}

	return 1;
}
