use bytes::Bytes;
use quinn::Connection;

async fn open_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"test").await?;
    send.finish()?;
    let received = recv.read_to_end(10).await?;
    Ok(())
}

async fn receive_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        // Because it is a bidirectional stream, we can both send and receive.
        println!("request: {:?}", recv.read_to_end(50).await?);
        send.write_all(b"response").await?;
        send.finish()?;
    }
    Ok(())
}

async fn open_unidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let mut send = connection.open_uni().await?;
    send.write_all(b"test").await?;
    send.finish()?;
    Ok(())
}

async fn receive_unidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    while let Ok(mut recv) = connection.accept_uni().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("{:?}", recv.read_to_end(50).await?);
    }
    Ok(())
}

async fn send_unreliable(connection: Connection) -> anyhow::Result<()> {
    connection.send_datagram(Bytes::from(&b"test"[..]))?;
    Ok(())
}

async fn receive_datagram(connection: Connection) -> anyhow::Result<()> {
    while let Ok(received_bytes) = connection.read_datagram().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("request: {:?}", received_bytes);
    }
    Ok(())
}
