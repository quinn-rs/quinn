# Data Transfer

The [previous chapter](set-up-connection.md) explained how to set up an [Endpoint][Endpoint]
and then get access to a [NewConnection][NewConnection] instance.
Now we will continue with the subject of sending data over this connection.

## Multiplexing

Multiplexing is the act of combining data from multiple streams into a single stream. 
This can have a significant positive effect on the performance of the application. 
With QUIC, the programmer is in full control over the stream allocation.  
  
## Stream Types

QUIC provides support for both stream and message based communication.
Streams and messages can be initiated both on the client and server.

| Type | Description | Reference |
| :----- | :----- | :----- |
| **Bidirectional Stream** | two way stream communication. | see [open_bi][open_bi] |
| **Unidirectional Stream** | one way stream communication. | see [open_uni][open_uni] |
| **Unreliable Messaging (extension)** | message based unreliable communication. | see [send_datagram][send_datagram] |

## How to Use

New streams can be created with the methods [open_bi][open_bi], [open_uni][open_uni] of type [Connection][Connection].
An instance of this type, together with existing streams, can be found in the [connection][connection] field of [NewConnection].

*Receive from various streams*

```rust
async fn iterate_streams(mut connection: NewConnection) -> anyhow::Result<()> {
    // Iterate unidirectional streams with only the receiving side.
    while let Some(Ok(recv)) = connection.uni_streams.next().await { }
    // Iterate bidirectional streams with both sent and receiving side.
    while let Some(Ok((sent, recv))) = connection.bi_streams.next().await { }
    // Iterate arrived datagrams.
    while let Some(Ok(bytes)) = connection.datagrams.next().await { }

    Ok(())
}
```
* *(Note that this example would get stuck in the first while loop)* 

*Open various kinds of streams*

```rust
async fn open_streams(mut connection: Connection) -> anyhow::Result<()> {
    // Open unidirectional stream.
    let mut send = connection.
        open_uni()
        .await?;

    // Open bidirectional stream.
    let (send, recv) = connection.
        open_bi()
        .await?;

    Ok(())
}
```

## Bidirectional Streams

With bidirectional streams data can be sent in both directions, for example, from the connection initiator to the peer and the other way around.
 
*open bidirectional stream*

```rust
async fn open_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let (mut send, recv) = connection.
        open_bi()
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
    while let Some(Ok((sent, recv))) = connection.bi_streams.next().await {
        // Because it is a bidirectional stream, we can both sent and recieve.
        println!("request: {:?}", recv.read_to_end(50).await?);

        send.write_all(b"response").await?;
        send.finish().await?;
    }

    Ok(())
}
```

## Unidirectional Streams 

With unidirectional streams, you can carry data only in one direction: from the initiator of the stream to its peer.
    
*open unidirectional stream*

```rust
async fn open_unidirectional_stream(connection: Connection)-> anyhow::Result<()> {
    let mut send = connection.
        open_uni()
        .await?;

    send.write_all(b"test").await.unwrap();
    send.finish().await?;

    Ok(())
}
```

*iterating incoming unidirectional stream(s)*

```rust
async fn receive_unidirectional_stream(mut connection: NewConnection) -> anyhow::Result<()> {
    while let Some(Ok(recv)) = connection.uni_streams.next().await {
        // Because it is a unidirectional stream, we can only receive not sent back.
        println!("{:?}", recv.read_to_end(50).await?);
    }

    Ok(())
}
```

## Unreliable Messaging

With unreliable messaging you can transfer data without reliability. 
This could be useful if data arrival isn't essential or when needing of high throughput matters and reliab

*send datagram*

```rust
async fn sent_unreliable(connection: Connection)-> anyhow::Result<()> {
    connection.
        send_datagram(b"test".into())
        .await?;

    Ok(())
}
```

*iterating datagram stream(s)*

```rust
async fn receive_datagram(mut connection: NewConnection) -> anyhow::Result<()> {
    while let Some(Ok(received_bytes)) = connection.datagrams.next().await {
        // Because it is a unidirectional stream, we can only receive not sent back.
        println!("request: {:?}", received);
    }

    Ok(())
}
```

[Endpoint]: https://docs.rs/quinn/latest/quinn/generic/struct.Endpoint.html
[NewConnection]: https://docs.rs/quinn/latest/quinn/generic/struct.NewConnection.html
[open_bi]: https://docs.rs/quinn/latest/quinn/generic/struct.Connection.html#method.open_bi
[open_uni]: https://docs.rs/quinn/latest/quinn/generic/struct.Connection.html#method.open_uni
[send_datagram]: https://docs.rs/quinn/latest/quinn/generic/struct.Connection.html#method.send_datagram
[connection]: https://docs.rs/quinn/latest/quinn/generic/struct.NewConnection.html#structfield.connection
