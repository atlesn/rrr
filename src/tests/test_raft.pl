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

	if (scalar keys %fields == 0) {
		$response{'fields'}->{'data'} = $response{'data'};
	}

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

# Stages in this test. Each stage is started in the source
# function and is then completed in the process function as
# responses arrives. The 's' bullets are for the source
# function and the 'p' bullets are for the process functions.
#
# When the process function has verified the action made by
# the source function, the stage is incremented.
#
# Note that many test stages are the same or nearly the same.
#
# The test expects that messages with topic 'raft/1' and 'raft/3'
# will go to the leader and 'raft/2' will go to a non-leader.
#
# Stage 0-2 - Simple PUT and GET
# 0s.  PUT message 'raft/1' containing array message with field 'data'
#      containing a JSON object with a field 'data'.
# 0p.  Check ACK message for PUT
# 1s.  GET message for 'raft/1'
# 1p.  Check ACK message for GET
# 2p.  Check data message for 'raft/1' and verify data
#
# Stage 3-5 - PAT operation, add an array value
# 3s.  PAT message 'raft/1' containing array message with field 'data'
#      containing JSON with a new field 'patch'
# 3p.  Check ACK message for PAT
# 4s.  GET message for 'raft/1'
# 4p.  Check ACK message for GET
# 5p.  Check data message for 'raft/1' and verify that the new array
#      field exists within the 'data' field JSON object
#
# Stage 6-8 - PAT operation, replace an array value
# 6s.  PAT message 'raft/1' containing array message with field 'data'
#      containing non-JSON data
# 6p.  Check ACK message for PAT
# 7s.  GET message for 'raft/1'
# 7p.  Check ACK message for GET
# 8s.  Check data message for 'raft/1' in which the full contents of
#      the 'data' field should now have been replaced with the non-
#      JSON data.
#
# Stage 9 - GET operation to non-leader with negative response
# 9s.  GET message for 'raft/2'
# 9p.  Check ACK message for GET, negative response
#
# Stage 10 - PAT operation with negative response
# 10s. PAT message for 'raft/3'
# 10p. Check ACK message for PAT, negative response
#
# Stage 11 - PUT operation with JSON in data message
# 11s. PUT message for 'raft/1'
# 11p. Check ACK message for PUT
# 12s. GET message for 'raft/1'
# 12p. Check ACK message for GET
# 13p. Check data message for 'raft.1'
#
# Stage 14 - Completion
# 14s. Test completion signal message is emitted

sub source {
	my $message = shift;

	my $res;
	my %result_values;

	# - Source function should be called every 500 ms

	$dbg->msg(1, "== STAGE $stage" . "s\n");

	if (defined $randoms[$stage]) {
		return 1;
	}

	if ($stage == 0) {
		$randoms[$stage] = int(rand(10));
		$message->{'topic'} = "raft/1";
		$message->set_tag_str("data", "{'data':$randoms[$stage]}");

		$dbg->msg(1, "- Send store to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($stage == 1 or $stage == 4 or $stage == 7 or $stage == 9 || $stage == 12) {
		$randoms[$stage] = int(rand(10));
		$message->{'topic'} = $stage == 9
			? "raft/2"
			: "raft/1";
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_GET);

		$dbg->msg(1, "- Send get for topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($stage == 3 || $stage == 10) {
		$randoms[$stage] = int(rand(10));
		$message->{'topic'} = $stage == 10
			? "raft/3"
			: "raft/1";
		$message->set_tag_str("data", "{'patch':$randoms[$stage]}");
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send JSON patch to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($stage == 6) {
		$randoms[$stage] = int(rand(10));
		$message->{'topic'} = "raft/1";
		$message->set_tag_str("data", "data $randoms[$stage]");
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send non-JSON patch to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($stage == 11) {
		$randoms[$stage] = int(rand(10));
		$message->{'topic'} = "raft/1";
		$message->clear_array();
		$message->{"data"} = "{'data':$randoms[$stage]}";

		$dbg->msg(1, "- Send store non-array to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($stage == 14) {
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

	$dbg->msg(1, "== STAGE $stage" . "p\n");

	if ($stage == 0 or $stage == 3 or $stage == 6 or $stage == 10 or $stage == 11) {
		my $method = ($stage == 0 or $stage == 11)
			? "PUT"
			: "PAT"
		;

		# The ACK message has no topic itself. The topic
		# of the message it refers to is in an array field.
		$dbg->msg(1, "- Checking result of $method command\n");

		$res = check_response(\%result_values, "", {
			"raft_command" => $method,
			"raft_status" => $stage == 10
				? 0
				: 1,
			"raft_reason" => $stage == 10
				? "NOT FOUND"
				: "OK",
			"raft_topic" => $stage == 10
				? "raft/3"
				: "raft/1"
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
	elsif ($stage == 1 or $stage == 4 or $stage == 7 or $stage == 9 || $stage == 12) {
		# Check for ACK message for the GET which arrives first
		$res = check_response(\%result_values, "", {
			"raft_command" => "GET",
			"raft_status" => $stage == 9
				? 0
				: 1,
			"raft_reason" => $stage == 9
				? "NOT FOUND"
				: "OK",
			"raft_topic" => $stage == 9
				? "raft/2"
				: "raft/1"
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
	elsif ($stage == 2 or $stage == 5 or $stage == 13) {
		# Note that when patching, the JSON library will
		# produce double quotes for all keys
		my $data = ($stage == 2 or $stage == 13)
			? "{'data':$randoms[$stage - 2]}"
			: "{\"data\":$randoms[$stage - 5],\"patch\":$randoms[$stage - 2]}"
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
	elsif ($stage == 8 || $stage == 12) {
		# Check for the actual resulting message arriving secondly
		$res = check_response(\%result_values, "raft/1", {
			"data" => "data $randoms[$stage - 2]"
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
