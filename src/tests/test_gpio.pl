
#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $DEBUGFS;
my $ROUNDS = 10;

sub config {
	my $settings = shift;

	$DEBUGFS = $settings->get("gpio_chip_debugfs");

	if (-d $DEBUGFS && (test_line(12, "0") || test_line(12, "1"))) {
		$dbg->msg(1, "Checking result with debugfs path $DEBUGFS\n");
		return 1;
	}

	$dbg->msg(1, "Not checking result with debugfs, not found on $DEBUGFS\n");
	$DEBUGFS = undef;

	return 1;
}

sub source {
	my $message = shift;

	if (--$ROUNDS == 0) {
		if (defined $DEBUGFS) {
			die "Unexpected line result for 12" unless test_line(12, "1");
			die "Unexpected line result for 13" unless test_line(13, "0");
			die "Unexpected line result for 14" unless test_line(14, "1");
			die "Unexpected line result for 15" unless test_line(15, "0");
		}

		$message->clear_array();
		$message->{'topic'} = "gpio-ok";
		$message->send();

		return 1;
	}
	elsif ($ROUNDS < 0) {
		return 1;
	}

	command($message, 12, "on");
	command($message, 13, "off");
	command($message, 14, "on");
	command($message, 15, "off");

	return 1;
}

sub test_line {
	my $line = shift;
	my $expect = shift;

	my $line_file = "$DEBUGFS/$line";
	open(LINE, "< $line_file") or do {
		$dbg->msg(0, "Could not open line file $line_file from debugfs: $!\n");
		return 0;
	};
	$line = <LINE>;
	chomp $line;
	close(LINE);

	$dbg->msg(1, ">> Result from debugfs for $line_file: $line\n");

	return $line eq $expect;
}

sub command {
	my $message = shift;
	my $line = shift;
	my $set = shift;

	$message->clear_array();
	$message->{'topic'} = "gpio-command";

	$message->push_tag_str ("gpio_line", $line);
	$message->push_tag_str ("gpio_set", $set);

	$dbg->msg(1, ">> GPIO line $line set $set\n");

	$message->send();

	return 1;
}
