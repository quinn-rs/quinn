# Data Transfer

The [previous chapter](set-up-connection.md) explained how to set up an [Endpoint][Endpoint]
and then get access to a [Connection][Connection].
This chapter continues with the subject of sending data over this connection.

## Multiplexing

Multiplexing is the act of combining data from multiple streams into a single stream.
This can have a significant positive effect on the performance of the application.
With QUIC, the programmer is in full control over the stream allocation.

## Stream Types

QUIC provides support for both stream and message-based communication.
Streams and messages can be initiated both on the client and server.

| Type | Description | Reference |
| :----- | :----- | :----- |
| **Bidirectional Stream** | two way stream communication. | see [open_bi][open_bi] |
| **Unidirectional Stream** | one way stream communication. | see [open_uni][open_uni] |
| **Unreliable Messaging (extension)** | message based unreliable communication. | see [send_datagram][send_datagram] |

## How to Use

New streams can be created with [Connection][Connection]'s [open_bi()][open_bi] and
[open_uni()][open_uni] methods.

## Bidirectional Streams

With bidirectional streams, data can be sent in both directions.
For example, from the connection initiator to the peer and the other way around.

*open bidirectional stream*

```rust
{{#include data-transfer.rs:4:10}}
```

*iterate incoming bidirectional stream(s)*

```rust
{{#include data-transfer.rs:12:20}}
```

## Unidirectional Streams

With unidirectional streams, you can carry data only in one direction: from the initiator of the stream to its peer.
It is possible to get reliability without ordering (so no head-of-line blocking) by opening a new stream for each packet.

*open unidirectional stream*

```rust
{{#include data-transfer.rs:22:27}}
```

*iterating incoming unidirectional stream(s)*

```rust
{{#include data-transfer.rs:29:35}}
```

## Unreliable Messaging

With unreliable messaging, you can transfer data without reliability.
This could be useful if data arrival isn't essential or when high throughput is important.

*send datagram*

```rust
{{#include data-transfer.rs:37:40}}
```

*iterating datagram stream(s)*

```rust
{{#include data-transfer.rs:42:48}}
```

[Endpoint]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html
[Connection]: https://docs.rs/quinn/latest/quinn/struct.Connection.html
[open_bi]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_bi
[open_uni]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_uni
[send_datagram]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.send_datagram
