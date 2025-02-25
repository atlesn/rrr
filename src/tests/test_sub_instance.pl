#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $CONFIG;

sub config {
	my $settings = shift;

	$CONFIG{"param"} = $settings->get("param");
	$CONFIG{"role"} = $settings->get("role");
	$CONFIG{"generate_topic"} = $settings->get("generate_topic");

	if ($CONFIG{"role"} eq "first") {
		die "Param mismatch" unless $CONFIG{"param"} eq "a";
	}
	elsif ($CONFIG{"role"} eq "second") {
		die "Param mismatch" unless $CONFIG{"param"} eq "b";
		$CONFIG{"read_topic"} = $settings->get("read_topic");
	}
	else {
		die "Role error";
	}

	return 1;
}

sub source {
	my $msg = shift;

	if ($CONFIG{"role"} eq "first") {
		print "WE ARE FIRST\n";
		$msg->{"topic"} = $CONFIG{"generate_topic"};
		$msg->send();
	}	

	return 1;
}

sub process {
	my $msg = shift;

	if ($CONFIG{"role"} eq "first") {
		die "first role got the message!";
	}

	die "second role not implemented";

	return 1;
}
