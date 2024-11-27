# Messaging patterns

## Message queue

Modules have an output FIFO buffer from which readers read from.
The buffer may be disabled and replaced with a slot which fits a single message.
The sender will block if the slot is filled.

    +-------------+--------+    +-------------+
    | Sender node | Buffer |===>| Reader node |
    +-------------+--------+ |  +-------------+
                             | 
                             |  +-------------+
                             |=>| Reader node |
                             |  +-------------+
                             |
                             |  +-------------+
                             |=>| Reader node |
                                +-------------+

## Pipelining

Modules are chained together.

    +--------+    +--------+    +--------+    
    | Node A |===>| Node B |===>| Node C |
    +--------+    +--------+    +--------+
     1             2             3

## Push-Pull

Multiple modules read from one module without duplication on the output.

    +-------+    +--------+
    | Entry |===>| Worker |
    +-------+ |  +--------+
     1234     |   14
              |  +--------+
              |=>| Worker |
              |  +--------+
              |   3
              |  +--------+
              |=>| Worker |
                 +--------+
                  2

## Fan out

Multiple modules read from one module with duplication on the output.
The entry module will have one buffer for each reader and all output messages are written to all buffers.
If buffering is disabled, there will be one slot in place for each reader.

    +-------+--------+    +--------+
    | Entry | Buffer |===>| Worker |
    +-------+--------+    +--------+
     1234   |        |     1234
            +--------+    +--------+
            | Buffer |===>| Worker |
            +--------+    +--------+
            |        |     1234
            +--------+    +--------+
            | Buffer |===>| Worker |
            +--------+    +--------+
                           1234

Fan in

One module reads from multiple others.

    +-------+    +--------+
    | Entry |===>| Worker |
    +-------+  | +--------+
     13        |  1234
    +-------+  |
    | Entry |=>|
    +-------+  |
     2         |
    +-------+  |
    | Entry |=>|
    +-------+
     4

## Router-Dealer

Route is set on output of module.
Targets may be chosen based on which values are present in a message and/or by topic.

    +-------+             +----------+
    | Entry |= ROUTING ==>| Worker A |
    +-------+          |  +----------+
                       |
                       |  +----------+
                       |=>| Worker B |
                       |  +----------+
                       |
                       |  +----------+
                       |=>| Worker C |
                          +----------+

## Request-Reply

Implemented using HTTP or a custom protocol.

    +--------+   +--------+
    | Client |<=>| Server |
    +--------+   +--------+

## Publish-Subscribe

Implemented using MQTT or by setting internal topic filters on module input.
In any case, MQTT-style topics and filters are used.
If internal filters are used, duplication must be enabled on the sender module.

    Network model using MQTT
    +-----------+   +--------+   +------------+
    | Publisher |==>| Broker |==>| Subscriber |
    +-----------+   +--------+   +------------+
    
    Internal model using filters.
    +-----------+               +------------+
    | Publisher |=== FILTER 1 =>| Subscriber |
    +-----------+ |             +------------+
     1234         |              1
                  |             +------------+
                  |= FILTER 2 =>| Subscriber |
                  |             +------------+
                  |              2
                  |             +------------+
                  |= FILTER # =>| Subscriber |
                                +------------+
                                 1234

