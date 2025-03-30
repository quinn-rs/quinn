use quinn::Connection;

async fn open_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let (mut send, recv) = connection.open_bi().await?;
    send.write_all(b"test").await?;
    send.finish().await?;
    let received = recv.read_to_end(10).await?;
    Ok(())
}

async fn receive_bidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    while let Ok((mut send, recv)) = connection.accept_bi().await {
        // Because it is a bidirectional stream, we can both send and receive.
        println!("request: {:?}", recv.read_to_end(50).await?);
        send.write_all(b"response").await?;
        send.finish().await?;
    }
    Ok(())
}

async fn open_unidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    let mut send = connection.open_uni().await?;
    send.write_all(b"test").await?;
    send.finish().await?;
    Ok(())
}

async fn receive_unidirectional_stream(connection: Connection) -> anyhow::Result<()> {
    while let Ok(recv) = connection.accept_uni().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("{:?}", recv.read_to_end(50).await?);
    }
    Ok(())
}

async fn send_unreliable(connection: Connection) -> anyhow::Result<()> {
    connection.send_datagram(b"test".into()).await?;
    Ok(())
}

async fn receive_datagram(connection: Connection) -> anyhow::Result<()> {
    while let Ok(received_bytes) = connection.read_datagram().await {
        // Because it is a unidirectional stream, we can only receive not send back.
        println!("request: {:?}", received_bytes);
    }
    Ok(())
}
