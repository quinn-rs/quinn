# Data Transfer

In the [previous chapter](set-up-connection.md) we characterized how to set up an [Endpoint][Endpoint]
and then get access to a [NewConnection][NewConnection] instance.
Now we will continue with the subject of sending data over this connection.

## Multiplexing

A QUIC stream can be compared to a TCP stream, eventhough if it is based on UDP. 
The big difference is that you are not limited to a single stream. 
You can open multiple streams between two peers, this is also called multiplexing.

Stream multiplexing can have a significant positive effect on application performance if the resources allocated to streams are properly prioritized.
Currently multiplexing it is used in a protocol like HTTP/2, but unlike HTTP multiplexing, QUIC does not automatically multiplex.
This is an advantage because the user gets full control over the multiplexing. 
Another difference compared to a TCP stream is that QUIC is not limited to one kind of stream but can open both bidirectional and unidirectional streams.
 
## Stream Types

Quinn offers three ways to send your data. 
Two stream-based and one message-based.

| Type | Description | Reference |
| :----- | :----- | :----- |
| **Bidirectional Stream** | two way stream communication. | see [open_bi][open_bi] |
| **Unidirectional Stream** | one way stream communication. | see [open_uni][open_uni] |
| **Unreliable Messaging** | message based unreliable communication. | see [send_datagram][send_datagram] |

## How to Use

You can open a new stream or read from an existing stream.
New streams can be created with the methods [open_bi][open_bi], [open_uni][open_uni] from [Connection][Connection] type.
An instance of this type is found in the [connection][connection] field of [NewConnection][NewConnection]. 
This [NewConnection][NewConnection] stores existing streams as well. Lets look at some examples:

*Iterate over various opened streams*

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

*Open different types of streams*

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

With bidirectional streams you can carry data in both directions, for example, from the initiator to the peer and in reverse.
 
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

*iterate bidirectional stream(s)*

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

With unidirectional streams, you can carry data only in one direction, for example, from the initiator of the stream to its peer.
    
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

*iterating unidirectional stream(s)*

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

With unreliable messaging you can transfer data unreliable over bare UDP.

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
    while let Some(Ok(receivedBytes)) = connection.datagrams.next().await {
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