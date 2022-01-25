# Data Transfer

The [previous chapter](set-up-connection.md) explained how to set up an [Endpoint][Endpoint]
and then get access to a [NewConnection][NewConnection] instance.
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

New streams can be created with [open_bi()][open_bi], [open_uni()][open_uni] from type [Connection][Connection].
An instance of this type, together with existing streams, can be found in the [connection][connection] field of [NewConnection].

## Bidirectional Streams

With bidirectional streams, data can be sent in both directions. 
For example, from the connection initiator to the peer and the other way around.
 
*open bidirectional stream*

```rust
async fn open_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let (mut send, recv) = connection
        .open_bi()
        .await?;

    send.write_all(b"test").await?;
    send.finish().await?;
    
    let received = recv.read_to_end(10).await?;

    Ok(())
}
```

*iterate incoming bidirectional stream(s)*

```rust
async fn receive_bidirectional_stream(mut connection: NewConnection) -> anyhow::Result<()> {
    while let Some(Ok((mut send, recv))) = connection.bi_streams.next().await {
        // Because it is a bidirectional stream, we can both send and receive.
        println!("request: {:?}", recv.read_to_end(50).await?);

        send.write_all(b"response").await?;
        send.finish().await?;
    }

    Ok(())
}
```

## Unidirectional Streams 

With unidirectional streams, you can carry data only in one direction: from the initiator of the stream to its peer.
It is possible to get reliability without ordering (so no head-of-line blocking) by opening a new stream for each packet.

*open unidirectional stream*

```rust
async fn open_unidirectional_stream(connection: Connection)-> anyhow::Result<()> {
    let mut send = connection
        .open_uni()
        .await?;

    send.write_all(b"test").await?;
    send.finish().await?;

    Ok(())
}
```

*iterating incoming unidirectional stream(s)*

```rust
async fn receive_unidirectional_stream(mut connection: NewConnection) -> anyhow::Result<()> {
    while let Some(Ok(recv)) = connection.uni_streams.next().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("{:?}", recv.read_to_end(50).await?);
    }

    Ok(())
}
```

## Unreliable Messaging

With unreliable messaging, you can transfer data without reliability. 
This could be useful if data arrival isn't essential or when high throughput is important.

*send datagram*

```rust
async fn send_unreliable(connection: Connection)-> anyhow::Result<()> {
    connection
        .send_datagram(b"test".into())
        .await?;

    Ok(())
}
```

*iterating datagram stream(s)*

```rust
async fn receive_datagram(mut connection: NewConnection) -> anyhow::Result<()> {
    while let Some(Ok(received_bytes)) = connection.datagrams.next().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("request: {:?}", received);
    }

    Ok(())
}
```

[Endpoint]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html
[NewConnection]: https://docs.rs/quinn/latest/quinn/struct.NewConnection.html
[open_bi]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_bi
[open_uni]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.open_uni
[send_datagram]: https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.send_datagram
[connection]: https://docs.rs/quinn/latest/quinn/struct.NewConnection.html#structfield.connection
