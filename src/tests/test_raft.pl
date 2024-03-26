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

sub push_response {
	my $message = shift;

	my %fields;

	foreach my $key ($message->get_tag_names()) {
		$fields{$key} = ($message->get_tag_all($key))[0];
	}

	my %response = (
		'topic' => $message->{'topic'},
		'fields' => \%fields
	);

	push @responses, \%response;
}

sub check_response {
	my $topic = shift;
	my $field_hash = shift;

	my $response = shift @responses;

	if (!defined $response) {
		$dbg->msg(1, "Waiting for response with topic '$topic'\n");
		return 1;
	}

	if ($response->{'topic'} ne $topic) {
		die("Topic mismatch '$topic'<>'$response->{'topic'}' in response\n");
	}

	for my $key (keys %{$field_hash}) {
		my $value = $response->{'fields'}->{$key};

		if (!defined $value) {
			die("Value for field '$key' missing in message with topic '$topic'\n");
		}

		if ($value ne $field_hash->{$key}) {
			$dbg->msg(1, "Value mismatch for '$key' in message with topic '$topic' '$value'<>'$field_hash->{$key}'\n");
			return 2;
		}
	}

	$dbg->msg(1, "Received response with topic '$topic' containing fields '" . join("', '", sort(keys(%{$field_hash}))) . "'\n");

	return 0;
}

sub source {
	my $message = shift;

	# - Source function should be called every 500 ms

	$dbg->msg(1, "Stage $stage\n");

	if ($stage == 0) {
		my $res = check_response("", {
			"raft_command" => "PUT",
			"raft_status" => 1,
			"raft_reason" => "OK",
			"raft_topic" => "data/0"
		});

		if (!$res) {
			# OK
		}
		else {
			$dbg->msg(1, "Send store\n");
			$message->{'topic'} = "data/0";
			$message->set_tag_str("data", "data 0");
			$message->send();

			$stage--;
		}
	}
	elsif ($stage == 1) {
		$message->{'topic'} = "raft-ok";
		$message->send();
	}

	$stage++;

	return 1;
}

sub process {
	my $message = shift;

	push_response($message);

	return 1;
}
