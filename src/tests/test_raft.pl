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
		$dbg->msg(0, "Topic mismatch '$topic'<>'$response->{'topic'}' in response\n");
		$ret = 3;
		goto out;
	}

	for my $key (keys %{$field_hash}) {
		my $value = $response->{'fields'}->{$key};

		$response_values->{$key} = $value;

		if (!defined $value) {
			$dbg->msg(0, "Value for field '$key' missing in message with topic '$topic'\n");
			$ret = 3;
			goto out;
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

	$dbg->msg(1, "Received response with topic '$topic' containing expected values for fields '" . join("', '", sort(keys(%{$field_hash}))) . "'\n");
	$dbg->msg(1, "There are " . scalar @responses . " more responses\n");

	out:
	return $ret;
}

my @randoms;

sub source {
	my $message = shift;

	my $res;
	my %result_values;

	# - Source function should be called every 500 ms

	if ($stage == 0) {
		unless (defined $randoms[$stage]) {
			$randoms[$stage] = int(rand(10));
			$dbg->msg(1, "- Send store to node 1\n");
			$message->{'topic'} = "raft/1";
			$message->set_tag_str("data", "{'data':$randoms[$stage]}");
			$message->send();
		}
	}
	elsif ($stage == 1) {
		unless (defined $randoms[$stage]) {
			$randoms[$stage] = int(rand(10));
			$dbg->msg(1, "- Send get to node 1\n");
			$message->{'topic'} = "raft/1";
			$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_GET);
			$message->send();
		}

	}
	elsif ($stage == 3) {
		unless (defined $randoms[$stage]) {
			$randoms[$stage] = int(rand(10));
			$dbg->msg(1, "- Send patch to node 1\n");
			$message->{'topic'} = "raft/1";
			$message->set_tag_str("patch", "{'patch':$randoms[$stage]}");
			$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);
			$message->send();
		}
	}
	elsif ($stage == 4) {
		unless (defined $randoms[$stage]) {
			$randoms[$stage] = int(rand(10));
			$dbg->msg(1, "- Send get to node 1\n");
			$message->{'topic'} = "raft/1";
			$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_GET);
			$message->send();
		}

	}
	elsif ($stage == 6) {
		$message->{'topic'} = "raft-ok";
		$message->send();
	}

	return 1;
}

sub process {
	my $message = shift;

	push_response($message);

	# Test is faster if checking the result immediately
	# in the source function thus results are checked
	# there and stage incremented.
	$message->{'topic'} = "";
	$message->clear_array();

	if ($stage == 0 or $stage == 3) {
		my $method = $stage == 0
			? "PUT"
			: "PAT"
		;

		# The ACK message has no topic itself. The topic
		# of the message it refers to is in an array field.
		$dbg->msg(1, "- Checking result of $method command\n");

		$res = check_response(\%result_values, "", {
			"raft_command" => $method,
			"raft_status" => 1,
			"raft_reason" => "OK",
			"raft_topic" => "raft/1"
		});

		if ($res) {
			if ($res == 1) {
				# No response yet, wait
			}
			elsif (defined $result_values{"raft_reason"} and
			       $result_values{"raft_reason"} eq "NOT LEADER"
			) {
				# Node is not yet leader
				$dbg->msg(1, "- Node is not yet leader, try again\n");
				$randoms[$stage] = undef;
			}
			else {
				return 0;
			}
		}
		else {
			$stage++;
		}
	}
	elsif ($stage == 1 or $stage == 4) {
		# Check for ACK message for the GET which arrives first
		$res = check_response(\%result_values, "", {
			"raft_command" => "GET",
			"raft_status" => 1,
			"raft_reason" => "OK",
			"raft_topic" => "raft/1"
		});

		if ($res) {
			if ($res == 1) {
				# No response yet, wait
			}
			else {
				return 0;
			}
		}
		else {
			$stage++;
		}
	}
	elsif ($stage == 2 or $stage == 5) {
		my $data = $stage == 2
			? "{'data':$randoms[$stage - 2]}"
			: "{'data':$randoms[$stage - 5],'patch':$randoms[$stage - 2]}"
		;
 
		# Check for the actual resulting message arriving secondly
		$res = check_response(\%result_values, "raft/1", {
			"data" => $data
		});

		if ($res) {
			if ($res == 1) {
				# No response yet, wait
			}
			else {
				return 0;
			}
		}
		else {
			$stage++;
		}
	}

	return 1;
}
