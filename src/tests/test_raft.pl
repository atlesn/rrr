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
my %CMD_IGNORE = (
	"LEADERSHIP TRANSFER" => 1
);

sub push_response {
	my $message = shift;

	my %fields;

	foreach my $key ($message->get_tag_names()) {
		$fields{$key} = ($message->get_tag_all($key))[0];
	}

	my %response = (
		'topic' => $message->{'topic'},
		'data' => $message->{'data'},
		'fields' => \%fields,
	);

	push @responses, \%response;
}

sub check_response {
	my $response_values = shift;
	my $topic = shift;
	my $data = shift;
	my $field_hash = shift;

	my $ret = 0;

	again:

	my $response = shift @responses;

	if (!defined $response) {
		$dbg->msg(1, "Waiting for response with topic '$topic'\n");
		$ret = 1;
		goto out;
	}

	if (defined $response->{'fields'}->{'raft_command'} &&
	    defined $CMD_IGNORE{$response->{'fields'}->{'raft_command'}}
	) {
		$dbg->msg(1, "Ignoring result for {$response->{'fields'}->{'raft_command'}} command\n");
		goto again;
	}

	if ($response->{'topic'} ne $topic) {
		die("Topic mismatch '$topic'<>'$response->{'topic'}' in response\n");
	}

	for my $key (keys %{$field_hash}) {
		my $value = $response->{'fields'}->{$key};

		$response_values->{$key} = $value;

		if (!defined $value) {
			die("Value for field '$key' missing in message with topic '$topic'\n");
		}

		if ($value ne $field_hash->{$key}) {
			$dbg->msg(1, "Value mismatch for '$key' in message with topic '$topic' '$value'<>'$field_hash->{$key}'\n");
			$ret = 2;
			# Don't goto out, store all values for return
		}
	}

	if ($ret == 2) {
		goto out;
	}

	if (length $data > 0 and $response->{'data'} ne $data) {
		die("Data mismatch '$data'<>'$response->{'data'}' in response\n");
	}

	$dbg->msg(1, "Received response with topic '$topic' containing expected values for fields '" . join("', '", sort(keys(%{$field_hash}))) . "'\n");
	$dbg->msg(1, "There are " . scalar @responses . " more responses\n");

	out:
	return $ret;
}

my @randoms;

sub source {
	my $message = shift;

	my %result_values;

	# - Source function should be called every 500 ms

	$dbg->msg(1, "Stage $stage\n");

	if ($stage == 0) {
		# The ACK message has no topic itself. The topic
		# of the message it refers to is in an array field.
		if (defined $randoms[$stage]) {
			$dbg->msg(1, "- Checking result of PUT command\n");

			my $res = check_response(\%result_values, "", "", {
				"raft_command" => "PUT",
				"raft_status" => 1,
				"raft_reason" => "OK",
				"raft_topic" => "raft/2"
			});

			if ($res) {
				if ($res == 1) {
					# No response yet, wait
					$stage--;
				}
				elsif ($result_values{"raft_reason"} eq "NOT LEADER") {
					# Node is not yet leader
					$dbg->msg(1, "- Node is not yet leader, try again\n");
					$randoms[$stage] = undef;
					$stage--;
				}
				else {
					die("Unexpected response values");
				}
			}
		}
		else {
			$randoms[$stage] = int(rand(10));

			$dbg->msg(1, "- Send store to node 2\n");
			$message->{'topic'} = "raft/2";
			$message->set_tag_str("data", "data $randoms[$stage]");
			$message->send();

			$stage--;
		}
	}
	elsif ($stage == 1) {
		if (defined $randoms[$stage]) {
			# Check that data is number stored by previous stage
			my $res = check_response(\%result_values, "", "data $randoms[$stage - 2]", {
				"raft_command" => "GET",
				"raft_status" => 1,
				"raft_reason" => "OK",
				"raft_topic" => "data/0"
			});

			if ($res) {
				if ($res == 1) {
					# No response yet, wait
					$stage--
				}
				else {
					die("Unexpected response values");
				}
			}
		}
		else {
			$randoms[$stage] = int(rand(10));

			$dbg->msg(1, "- Send get to node 1\n");
			$message->{'topic'} = "raft/1";
			$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_GET);
			$message->send();

			$stage--
		}

	}
	elsif ($stage == 2) {
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
