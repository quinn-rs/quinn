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

| Type                                 | Description                             | Reference                          |
| :----------------------------------- | :-------------------------------------- | :--------------------------------- |
| **Bidirectional Stream**             | two way stream communication.           | see [open_bi][open_bi]             |
| **Unidirectional Stream**            | one way stream communication.           | see [open_uni][open_uni]           |
| **Unreliable Messaging (extension)** | message based unreliable communication. | see [send_datagram][send_datagram] |

## How to Use

New streams can be created with [Connection][Connection]'s [open_bi()][open_bi] and
[open_uni()][open_uni] methods.

## Bidirectional Streams

With bidirectional streams, data can be sent in both directions.
For example, from the connection initiator to the peer and the other way around.

_open bidirectional stream_

```rust
{{#include ../bin/data-transfer.rs:7:13}}
```

_iterate incoming bidirectional stream(s)_

```rust
{{#include ../bin/data-transfer.rs:16:24}}
```

## Unidirectional Streams

With unidirectional streams, you can carry data only in one direction: from the initiator of the stream to its peer.
It is possible to get reliability without ordering (so no head-of-line blocking) by opening a new stream for each packet.

_open unidirectional stream_

```rust
{{#include ../bin/data-transfer.rs:27:32}}
```

_iterating incoming unidirectional stream(s)_

```rust
{{#include ../bin/data-transfer.rs:35:41}}
```

## Unreliable Messaging

With unreliable messaging, you can transfer data without reliability.
This could be useful if data arrival isn't essential or when high throughput is important.

_send datagram_

```rust
{{#include ../bin/data-transfer.rs:44:47}}
```

_iterating datagram stream(s)_

```rust
{{#include ../bin/data-transfer.rs:50:56}}
```

[Endpoint]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html
[Connection]: https://docs.rs/quinn/latest/quinn/struct.Connection.html
[open_bi]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_bi
[open_uni]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_uni
[send_datagram]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.send_datagram
