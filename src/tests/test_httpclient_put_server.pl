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

sub source {
	my $message = shift;


	return 1;
}

my $seen_endpoints = {
	"prio" => {},
	"nonprio" => {}
};
my $state = 0;

sub process {
	my $message = shift;

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];

	$dbg->msg(1,  "Server received endpoint $endpoint topic $message->{'topic'}\n");

	unless ($endpoint =~ s/^\/(prio|nonprio)\/(\d+)$//) {
		$dbg->msg(0, "Unrecognized endpoint $endpoint\n");
		return 0;
	}

	my $endpoint_type = $1;
	my $endpoint_id = $2;

	unless (defined $seen_endpoints->{$endpoint_type}->{$endpoint_id}) {
		if ($state > 0) {
			$dbg->msg(0, "Received first time seen endpoint $endpoint when only already seen endpoints were expected\n");
			return 0;
		}

		$seen_endpoints->{$endpoint_type}->{$endpoint_id} = 1;

		$message->clear_array();
		$message->push_tag("http_response_code", 409);
		$message->send();

		return 1;
	}
	elsif ($state == 0) {
		$dbg->msg(1, "Received already seen endpoint, now checking for prio/nonprio order\n");
		$state++;
	}

	if ($seen_endpoints->{$endpoint_type}->{$endpoint_id} > 1) {
		$dbg->msg(0, "Received $endpoint_type endpoint $endpoint_type multiple times\n");
		return 0;
	}

	$seen_endpoints->{$endpoint_type}->{$endpoint_id} = 2;

	if ($endpoint_type eq "prio") {
		if ($state != 1) {
			$dbg->msg(0, "Received prio endpoint $endpoint when not expected\n");
			return 0;
		}

		my $all_prio_received = 1;
		foreach my $key (keys(%{$seen_endpoints->{"prio"}})) {
			my $state = $seen_endpoints->{"prio"}->{$key};
			if ($state != 2) {
				$all_prio_received = 0;
				last;
			}
		}

		if ($all_prio_received) {
			$dbg->msg(1, "All prio endpoitns now received\n");
			$state++;
		}
	}
	else {
		if ($state != 2) {
			$dbg->msg(0, "Received nonprio endpoint $endpoint when not expected, all prios must be received first\n");
			return 0;
		}

		my $all_nonprio_received = 1;
		foreach my $key (keys(%{$seen_endpoints->{"nonprio"}})) {
			my $state = $seen_endpoints->{"nonprio"}->{$key};
			if ($state != 2) {
				$all_nonprio_received = 0;
				last;
			}
		}

		if ($all_nonprio_received) {
			$dbg->msg(1, "All nonprio endpoitns now received\n");
			$state++;
		}
	}

	$message->clear_array();
	$message->push_tag("http_response_code", 200);
	$message->send();

	if ($state == 3) {
		$dbg->msg(1,  "Server - All messages received\n");
		$message->clear_array();
		$message->{'topic'} = "rrr/success";
		$message->send();
	}

	return 1;
}
