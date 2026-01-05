#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use Time::Local qw(timegm_posix);
use Time::HiRes qw(gettimeofday tv_interval);

my $DONE_MAX_AGE_S = 3600 * 24 * 2; # Two days
my $OUT_MAX_AGE_S = 3600 * 24 * 7; # One week
my $ALLOWED_DIRECTORY_FILE = "/var/lib/mass-storage-event.state";

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	die "Source not implemented";

	return 1;
}

sub my_sync {
	my $start_time = [gettimeofday];
	system("sync") and die ("Sync failed: $!\n");
	my $end_time = [gettimeofday];

	$dbg->msg(1, "Synced filesystems (" . (tv_interval($start_time, $end_time) * 1 * 1000 * 1000) . "us)\n")
}

sub process_ffmpeg {
	my $message = shift;

	my $filename = ($message->get_tag_all("ffmpeg_filename"))[0];
	my $directory = ($message->get_tag_all("ffmpeg_directory"))[0];

	chdir($directory) or die "Could not change directory to $directory: %!\n";

	unless (-f "$filename") {
		die "Reported filename '$filename' did not exist\b";
	}

	my $filename_new = $filename;
	$filename_new =~ s/^out-/done-/;

	$dbg->msg(1, "Received report for file $filename in directory $directory topic was '$message->{'topic'}', renaming to '$filename_new'\n");

	rename($filename, $filename_new) or die "Could not rename $filename to $filename_new: $!\n";
	my_sync();

	return 1;
}

sub is_allowed_directory {
	my $directory = shift;

	open(FILE, "< $ALLOWED_DIRECTORY_FILE") || die("Could not open allowed directory file '$ALLOWED_DIRECTORY_FILE': $!\n");
	my $allowed_directory = <FILE>;
	chomp $allowed_directory;
	close(FILE);

	# $dbg->msg(1, "Comparing allowed directory '$allowed_directory'<>'$directory'\n");

	if ($allowed_directory eq "") {
		$dbg->msg(0, "No allowed directory specified in '$ALLOWED_DIRECTORY_FILE'\n");
		return 0;
	}

	$directory =~ s/\/+$//;
	$allowed_directory =~ s/\/+$//;

	if ($directory ne $allowed_directory) {
		$dbg->msg(0, "Directory '$directory' does not match allowed directory specified in '$ALLOWED_DIRECTORY_FILE': '$allowed_directory'\n");
		return 0;
	}

	return 1;
}

sub process_directory {
	my $message = shift;

	my $directory = ($message->get_tag_all("file_directory"))[0];
	my @files = $message->get_tag_all("file_name");
	my @paths = $message->get_tag_all("file_path_resolved");

	if (!is_allowed_directory($directory)) {
		$dbg->msg(0, "Ignoring " . (scalar @files) . " files as directory '$directory' is not an allowed directory\n");
		return 1;
	}

	my $need_sync = 0;
	my $timestamp_limit_done = time() - $DONE_MAX_AGE_S;
	my $timestamp_limit_out = time() - $OUT_MAX_AGE_S;

	for (my $i = 0; $i < @files; $i++) {
		my $file = $files[$i];
		my $path = $paths[$i];

		if ($file !~ /(done|out)-/) {
			$dbg->msg(0, "Could not determin state (done/out) from filename '$file'\n");
			next;
		}

		my $state = $1;

		if ($file !~ /(\d\d\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z/) {
			$dbg->msg(0, "Could not find timestamp in filename '$file'\n");
			next;
		}

		my $year = $1;
		my $month = $2;
		my $day = $3;
		my $hour = $4;
		my $minute = $5;
		my $second = $6;

		my $timestamp = timegm_posix($second, $minute, $hour, $day, $month - 1, $year - 1900);

		if ($state eq "done" && $timestamp < $timestamp_limit_done) {
			$dbg->msg(1, "File '$file'->'$path' is older than $DONE_MAX_AGE_S seconds, deleting\n");
			unless (unlink $path) {
				$dbg->msg(0, "Warning: Could not unlink file '$path': $!\n");
			}
			$need_sync = 1;
		}
		elsif ($state eq "out" && $timestamp < $timestamp_limit_out) {
			$dbg->msg(1, "Stale file '$file'->'$path' is older than $OUT_MAX_AGE_S seconds, deleting\n");
			unless (unlink $path) {
				$dbg->msg(0, "Warning: Could not unlink file '$path': $!\n");
			}
			$need_sync = 1;
		}
	}

	my_sync() if $need_sync;

	return 1;
}
