# READ ROUTE RECORD EXAMPLES

An example consists of a configuration file solving a real-world problem,
and sometimes a Perl5 or Python3 script which is part of the solution. All
files of a particular example will have similar file names.

All scripts and examples are in the public domain, they can be copied and
used in any way at your will.

## PERIPHERALS

A peripheral is some external device which produces or receives data in some basic
form, usually without any high-level protocol being involved. RRR can receive these
messages using the **ip** module and forward them or save them.

The RRR array framework allows data of different formats to be parsed an validated.
Usually devices send some message and then an end terminator, or they may send multiple
fields in the same message. With RRR arrays, these values can be extracted and tagged
for use by some higher level of the application.

Networking is an area with many pitfalls, and something as simple as having a TCP
connection open with some other host causes all sorts of problems when the remote host
stops replying or packets are lost. RRR is designed to handle this complexity while allowing
developers to focus on the actual application instead of fighting with networking code.

By default, RRR also buffers messages in between modules. This means that if for instance
a messages is received on UDP and converted to MQTT PUBLISH messages, messages will be buffered
if the MQTT broker is unreachable and sent later when the broker becomes alive again.

### Peripherals Example Configurations

* [Barcode Scanner](peripherals/barcode_scanner.md)  

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

* [HTTP Forwarder](http/http_forwarder.md)
* [HTTP Perl5 Server](http/http_perl_server.md)
