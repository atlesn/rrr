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

	foreach my $suffix (@endpoint_suffixes) {
		if (!defined($results{$suffix})) {
			$dbg->msg(1,  "Server - Message for endpoint $suffix missing\n");
			return 1;
		}
		my $id_check =
			($suffix eq "A" ? 2 :
			($suffix eq "B" ? 3 :
			($suffix eq "C" ? 4 : 0)));

		foreach my $id (sort keys %{$results{$suffix}}) {
			if ($id != $id_check) {
				$dbg->msg(1,  "Server - Endpoint $suffix id mismatch $id_check<>$id\n");
				return 1;
			}
			$id_check++;
		}
		if ($id_check < $id_max + 1) {
			$dbg->msg(1,  "Server - Endpoint $suffix not all ids received, now at " . ($id_check) . "\n");
			return 1;
		}
	}

	$dbg->msg(1,  "Server - All messages received\n");

	$message->{'topic'} = "rrr/success";
	$message->send();

	return 1;
}

sub process {
	my $message = shift;

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];

	$endpoint =~ s/^\///;

	$dbg->msg(1,  "Server received endpoint $endpoint topic $message->{'topic'}\n");

	if ($endpoint =~ /^\Q$endpoint_prefix\E\/(\w+)\/(\d+)$/) {
		if (!defined $results{$1}) {
			$results{$1} = {};
		}

		$results{$1}->{$2} = 1;
	}

	$message->clear_array();
	$message->send();

	return 1;
}
