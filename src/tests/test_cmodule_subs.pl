#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $SUB_NAME;

sub sub_config {
	my $settings = shift;

	$SUB_NAME = $settings->get("sub_name");

	return 1;
}

sub sub_process {
	my $message = shift;

	print "Got message in sub $SUB_NAME\n";
	$message->push_tag_str("sub_name", $SUB_NAME);
	$message->send();

	return 1;
}

my @CHECK_NAMES;
my %RECEIVED_NAMES;

sub check_config {
	my $settings = shift;

	@CHECK_NAMES = split /,/, $settings->get("sub_names");

	return 1;
}

sub check_process {
	my $message = shift;

	my $sub_name = ($message->get_tag_all("sub_name"))[0];

	print "Got message in checker from sub $sub_name\n";

	$RECEIVED_NAMES{$sub_name} = 1;

	foreach my $check_sub_name (@CHECK_NAMES) {
		return 1 unless defined $RECEIVED_NAMES{$check_sub_name};
	}

	$message->send();

	return 1;
}
