#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $stage = 0;
my @responses;

sub check_response {
	my $topic = shift;
	my $field_hash = shift;

	my $response = shift @responses;

	if (!defined $response) {
		$dbg->msg(1, "Waiting for response with topic '$topic'\n");
		return 0;
	}

	if ($response->{'topic'} ne $topic) {
		die("Topic mismatch '$topic'<>'$response->{'topic'}' in response\n");
	}

	for my $key (%{$field_hash}) {
		my $value = ($response->get_tag_all($key))[0];

		if (!defined $value) {
			die("Value for field '$key' missing in message with topic '$topic'\n");
		}

		if ($value ne $field_hash->{$key}) {
			die("Value mismatch for '$key' in message with topic '$topic' '$value'<>'$field_hash->{'key'}'\n");
		}
	}

	$dbg->msg(1, "Received response with topic '$topic' containing fields '" . join("', '", sort(keys(%{$field_hash}))) . "'\n");

	return 1;
}

sub source {
	my $message = shift;

	# - Source function should be called every 500 ms

	$dbg->msg(1, "Stage $stage\n");

	$message->{'topic'} = "cacher-test-3";

	if ($stage == 0) {
		$dbg->msg(1, "Send store\n");
		$message->{'topic'} = "";
		$message->set_tag_str("data", "data 0");
		$message->send();
	}
	elsif ($stage == 1) {
		if (!check_response("", {"data" => "data 0"})) {
			$stage--;
		}
	}
	elsif ($stage == 2) {
	}

	$stage++;

	return 1;
}

sub process {
	my $message = shift;

	push @responses, $message;

	return 1;
}
