# READ ROUTE RECORD EXAMPLES

An example consists of a configuration file solving a real-world problem,
and sometimes a Perl5 or Python3 script which is part of the solution. All
files of a particular example will have similar file names.

All scripts and examples are in the public domain, they can be copied and
used in any way at your will.

## PERIPHERALS

A peripheral is some external device which produces or receives data in some basic
form, usually without any high-level protocol being involved.

For instance a device which measures temperature may send a UDP packet every second with
a reading. The RRR **ip** module is designed to receive such messages.

RRR array definitions are used to describe what the input data looks like. A typical
measurement include some reading with a terminator byte at the end.

### Peripheral examples

*  

## HTTP

The two modules **httpserver** and **httpclient** provides HTTP functionality
in RRR. HTTP is a complex protocol to parse as there are a lot of different
syntaxes in the header fields, and there are multiple ways to specify how
long (in bytes) a request or response is.

If you use **httpserver** without any configuration, it will respond with
"204 No Content" to *any* request and then ignore the received data. It can
be configured to extract POST and GET fields from the received requests and
put them into RRR messages, or it can operate in raw mode putting whole requests
into RRR messages.

The **httpclient** module always needs to have a remote server configured to
which it sends data. The data can be values from an RRR array put into POST or
GET queries, or raw data from another module.  

### HTTP Example Configurations

* [HTTP forwarder](http/http_forwarder.md)
* [HTTP Perl5 server](http/http_perl_server.md)