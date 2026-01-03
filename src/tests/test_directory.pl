#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	die "Source not implemented";

	return 1;
}

sub process {
	my $message = shift;

	my @dirs = $message->get_tag_all("file_directory");
	my @names = $message->get_tag_all("file_name");
	my @orig_paths = $message->get_tag_all("file_path_orig");

	die "Directory field count was not 1" unless @dirs == 1;
	die "Name field count was not 1 but " . scalar @names unless @names == 1;
	die "Path orig field count was not 1 but " . scalar @orig_paths unless @orig_paths == 1;

	my $dir = $dirs[0];
	my $name = $names[0];
	my $orig_path = $orig_paths[0];

	die "Unexpected directory $dir, expected /tmp (module must remove trailing / from configuration value)"
		unless $dir eq "/tmp";

	$dbg->msg(1, "Got report for file $name->$orig_path in directory $dir\n");

	die "Unexpected path $orig_path" unless $orig_path eq "/tmp/rrr-test-data.tmp.__test_directory_sh";

	unless (-f "$orig_path") {
		die "Reported filename '$orig_path' did not exist\b";
	}

	unlink $orig_path or die "Could not unlink $orig_path $!\n";

	die "Unexpected filename $name" unless $name eq "rrr-test-data.tmp.__test_directory_sh";

	$message->{'topic'} = "success";
	$message->clear_array();
	$message->send();

	return 1;
}
