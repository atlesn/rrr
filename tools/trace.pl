#!/usr/bin/perl -w

use strict;

my %transactions;
my @results;

my $i = 1;

my %times;
my $time_total;

while (<STDIN>) {
	if (/pid:.*(read|write).*fd:\s*(\d+).*time:\s*(\d+)/) {
		if ($1 eq "read") {
			$transactions{$2} = $3;
		}
		else {
			my $time = ($3 - $transactions{$2});
			if ($time > 1000) {
				print "Write at $i: $time\n";
			}
			$time_total += $time;
			$time -= $time % 100;
			$times{$time} += 1;
		}
	}

	$i++;
}

my $sum = 0;

foreach my $time (sort {$a <=> $b} keys %times) {
	print "$time: $times{$time}\n";

	$sum += $times{$time};
}

print "Total: $sum\n";
print "Average: " . ($time_total / $sum) . "\n";
