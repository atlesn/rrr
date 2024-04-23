
#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub config {
	my $settings = shift;

	return 1;
}

my %endpoints = (
	"/" => <<'END',
<!DOCTYPE html>
<html>
<head>
	<title>Test HTTP/3 server</title>
</head>
<body>
	<h1>Test HTTP/3 server</h1>
	<p>This is a test HTTP/3 server.</p>
</body>
</html>
END
);

my $not_found = <<'END';
<!DOCTYPE html>
<html>
<head>
	<title>Not Found</title>
</head>
<body>
	<h1>Not Found</h1>
	<p>The requested URL was not found on this server.</p>
</body>
</html>
END

my $not_allowed = <<'END';
<!DOCTYPE html>
<html>
<head>
	<title>Not Allowed</title>
</head>
<body>
	<h1>Not Allowed</h1>
	<p>The requested method is not allowed on this server.</p>
</body>
</html>
END

sub process {
	my $message = shift;

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];
	my $method = ($message->get_tag_all("http_method"))[0];

	$message->clear_array();

	if ($method ne "GET") {
		$message->push_tag("http_response_code", 405);
		$message->push_tag("http_content_type", "text/html");
		$message->push_tag("http_body", $not_allowed);

		$message->send();

		return 1;
	}

	my $data = $endpoints{$endpoint};

	if (!defined $data) {
		$message->push_tag("http_response_code", 404);
		$message->push_tag("http_content_type", "text/html");
		$message->push_tag("http_body", $not_found);

		$message->send();

		return 1;
	}

	$message->push_tag("http_response_code", 200);
	$message->push_tag("http_content_type", "text/html");
	$message->push_tag("http_body", $data);

	$message->send();

	return 1;
}
