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
# Stage 11-13 - PUT operation with JSON in data message
# 11s. PUT message for 'raft/1'
# 11p. Check ACK message for PUT
# 12s. GET message for 'raft/1'
# 12p. Check ACK message for GET
# 13p. Check data message for 'raft/1'
#
# Stage 14-16 - PAT operation with JSON in data message
# 14s. PAT message for 'raft/1'
# 14p. Check ACK message for PAT
# 15s. GET message for 'raft/1'
# 15p. Check ACK message for GET
# 16p. Check data message for 'raft/1'
#
# Stage 17-19 - PAT operation with non-JSON in data message
# 17s. PAT message for 'raft/1'
# 17p. Check ACK message for PAT
# 18s. GET message for 'raft/1'
# 18p. Check ACK message for GET
# 19p. Check data message for 'raft/1'
#
# Stage 20-21 - DEL operation
# 20s. DEL message for 'raft/1'
# 20p. Check ACK message for DEL
# 21s. GET message for 'raft/1'
# 21p. Check ACK message for GET

# Stage 22-23 - DEL operation with negative response
# 22s. DEL message for 'raft/3'
# 22p. Check ACK message for DEL, negative response
# 23s. GET message for 'raft/3'
# 23p. Check ACK message for GET, negative response

# Stage 22 - Completion
# 24s. Test completion signal message is emitted

# Data with random numbers are generation while sourcing. The
# process handlers will then check data, patched or full data,
# against the random numbers stored.
my %randoms;

# Checks corresponding to command messages are in the
# the process handler hash. Note that not all stages have
# source steps because some steps produce two messages (ACK and
# result message). In those cases, the result message is check in
# a separate step.
my %source_handlers = (
	 0 => "MSG_PUT_ARRAY_JSON",
	 1 => "MSG_GET_OK",

	 3 => "MSG_PAT_ARRAY_JSON_OK",
	 4 => "MSG_GET_OK",

	 6 => "MSG_PAT_ARRAY_DATA",
	 7 => "MSG_GET_OK",

	 9 => "MSG_GET_NF",

	10 => "MSG_PAT_ARRAY_JSON_NF",

	11 => "MSG_PUT_DATA_JSON",
	12 => "MSG_GET_OK",

	14 => "MSG_PAT_DATA_JSON",
	15 => "MSG_GET_OK",

	17 => "MSG_PAT_DATA_DATA",
	18 => "MSG_GET_OK",

	20 => "MSG_DEL_OK",
	21 => "MSG_GET_NF",

	22 => "MSG_DEL_NF",
	23 => "MSG_GET_NF",

	24 => "OK"
);

# Incrementing stage only happen in process handlers when
# expected data arrives.
#
# Operations depend on previous source operations, and the number
# of operations in between matters.
# - MSG_JSON_ONE check depends on PUT two steps prior
# - MSG_JSON_TWO check depends on PAT two steps prior and PUT five steps prior
# - MSG_DATA check depends on PUT or PAT two steps prior
my %process_handlers = (
	 0 => "ACK_PUT_OK",
	 1 => "ACK_GET_OK",
	 2 => "MSG_JSON_ONE",

	 3 => "ACK_PAT_OK",
	 4 => "ACK_GET_OK",
	 5 => "MSG_JSON_TWO",

	 6 => "ACK_PAT_OK",
	 7 => "ACK_GET_OK",
	 8 => "MSG_DATA",

	 9 => "ACK_GET_NF",

	10 => "ACK_PAT_NF",

	11 => "ACK_PUT_OK",
	12 => "ACK_GET_OK",
	13 => "MSG_JSON_ONE",

	14 => "ACK_PAT_OK",
	15 => "ACK_GET_OK",
	16 => "MSG_JSON_TWO",

	17 => "ACK_PAT_OK",
	18 => "ACK_GET_OK",
	19 => "MSG_DATA",

	20 => "ACK_DEL_OK",
	21 => "ACK_GET_NF",

	22 => "ACK_DEL_NF",
	23 => "ACK_GET_NF"

);
my %process_topic;

sub source {
	my $message = shift;

	my $data;
	my %result_values;

	# - Source function should be called every 500 ms

	$dbg->msg(1, "== STAGE $stage" . "s $source_handlers{$stage}\n");

	if (defined $randoms{$stage}) {
		return 1;
	}

	$randoms{$stage} = int(rand(10));

	$message->clear_array();

	if ($source_handlers{$stage} eq "MSG_PUT_ARRAY_JSON") {
		$message->{'topic'} = "raft/1";
		$message->set_tag_str("data", "{'data':$randoms{$stage}}");

		$dbg->msg(1, "- Send store to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} =~ /^MSG_GET_(OK|NF)$/) {
		my $status = $1;

		$message->{'topic'} = $status eq "OK" ? "raft/1" : "raft/2";
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_GET);

		$dbg->msg(1, "- Send get for topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} =~ /^MSG_DEL_(OK|NF)$/) {
		my $status = $1;

		$message->{'topic'} = $status eq "OK" ? "raft/1" : "raft/3";
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_DEL);

		$dbg->msg(1, "- Send del for topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} =~ /^MSG_PAT_ARRAY_JSON_(OK|NF)/) {
		my $status = $1;

		$message->{'topic'} = $status eq "OK" ? "raft/1" : "raft/3";
		$message->set_tag_str("data", "{'patch':$randoms{$stage}}");
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send JSON patch with array to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} eq "MSG_PAT_ARRAY_DATA") {
		$message->{'topic'} = "raft/1";
		$message->set_tag_str("data", "data $randoms{$stage}");
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send non-JSON patch to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} eq "MSG_PUT_DATA_JSON") {
		$message->{'topic'} = "raft/1";
		$message->{"data"} = "{'data':$randoms{$stage}}";

		$dbg->msg(1, "- Send store non-array JSON to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} eq "MSG_PAT_DATA_JSON") {
		$message->{'topic'} = "raft/1";
		$message->{'data'} = "{'patch':$randoms{$stage}}";
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send patch non-array JSON to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} eq "MSG_PAT_DATA_DATA") {
		$message->{'topic'} = "raft/1";
		$message->{"data"} = "data $randoms{$stage}";
		$message->type_set(rrr::rrr_helper::rrr_message::MSG_TYPE_PAT);

		$dbg->msg(1, "- Send store non-array non-JSON to leader topic $message->{'topic'}\n");

		$message->send();
	}
	elsif ($source_handlers{$stage} eq "OK") {
		$message->{'topic'} = "raft-ok";
		$message->send();
	}
	else {
		die ("Unknown source stage $stage\n");
	}

	$process_topic{$stage} = $message->{'topic'};

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

	$dbg->msg(1, "== STAGE $stage" . "p $process_handlers{$stage}\n");

	if ($process_handlers{$stage} =~ /^ACK_(PUT|PAT)_(OK|NF)$/) {
		my $method = $1;
		my $status = $2;

		# The ACK message has no topic itself. The topic
		# of the message it refers to is in an array field.
		$dbg->msg(1, "- Checking result of $method command expecting status $status\n");

		$res = check_response(\%result_values, "", {
			"raft_command" => $method,
			"raft_status" => $status eq "OK" ? 1 : 0,
			"raft_reason" => $status eq "OK" ? "OK" : "NOT FOUND",
			"raft_topic" => $process_topic{$stage}
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
				$randoms{$stage} = undef;
			}
			else {
				return 0;
			}
		}
		else {
			$stage++;
		}
	}
	elsif ($process_handlers{$stage} =~ /^ACK_(GET|DEL)_(OK|NF)$/) {
		my $method = $1;
		my $status = $2;

		$res = check_response(\%result_values, "", {
			"raft_command" => $method,
			"raft_status" => $status eq "OK" ? 1 : 0,
			"raft_reason" => $status eq "OK" ? "OK" : "NOT FOUND",
			"raft_topic" => $process_topic{$stage}
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
	elsif ($process_handlers{$stage} =~ /^MSG_JSON_(ONE|TWO)$/) {
		my $data_type = $1;

		# Note that when patching, the JSON library will
		# produce double quotes for all keys
		my $data = $data_type eq "ONE"
			? "{'data':$randoms{$stage - 2}}"
			: "{\"data\":$randoms{$stage - 5},\"patch\":$randoms{$stage - 2}}"
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
	elsif ($process_handlers{$stage} eq "MSG_DATA") {
		# Check for the actual resulting message arriving secondly
		$res = check_response(\%result_values, "raft/1", {
			"data" => "data $randoms{$stage - 2}"
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
	else {
		die("Unknown process stage $stage\n");
	}

	return 1;
}
