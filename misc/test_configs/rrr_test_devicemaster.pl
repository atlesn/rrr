#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use bytes;

my $global_settings = undef;

sub get_from_tag {
	my $message = shift;
	my $tag = shift;

	for (my $i = 0; $i < @{$message->{'array_tags'}}; $i++) {
		if (@{$message->{'array_tags'}}[$i] eq $tag) {
			return @{$message->{'array_values'}}[$i];
		}
	}

	return undef;
}

sub push_tag {
	my $message = shift;
	my $tag = shift;
	my $value = shift;

	push @{$message->{'array_values'}}, "$value";
	push @{$message->{'array_tags'}}, $tag;
	push @{$message->{'array_types'}}, "str";
}

sub process {
	my $message = shift;

	my $code = get_from_tag($message, "code");
	if (!defined($code)) {
		push_tag($message, "code", $message->{'timestamp'});
#		printf "perl5: Could not find tag 'code' in message\n";
#		return 1;
	}

	push_tag($message, "reply", "A\r");

	my $sin = sockaddr_in (7777, inet_aton("127.0.0.1"));
	my $sin_len = bytes::length($sin);

	$message->{'ip_addr'} = $sin;
	$message->{'ip_addr_len'} = $sin_len;
	$message->{'ip_so_type'} = "tcp";

#	foreach my $key (sort keys(%{$message})) {
#		print "Key: $key: " . $message->{$key} . "\n";
#	}

	$message->send();

	return 1;
}
