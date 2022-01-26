# Connection Setup

In the [previous chapter](certificate.md) we looked at how to configure a certificate.
This aspect is omitted in this chapter to prevent duplication. 
But **remember** that this is required to get your [Endpoint][Endpoint] up and running. 
This chapter explains how to set up a connection and prepare it for data transfer. 

It all starts with the [Endpoint][Endpoint] struct, this is the entry point of the library. 

## Example

Let's start by defining some constants. 

```rust
static SERVER_NAME: &str = "localhost";

fn client_addr() -> SocketAddr {
    "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
}
```

**Server**

First, the server endpoint should be bound to a socket. 
The [server()][server] method, which can be used for this, returns a tuple containing the `Endpoint` and `Incoming` types.
The `Endpoint` type can be used to start outgoing connections, and the `Incoming` type can be used to listen for incoming connections.

```rust
async fn server() -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given server address. 
    let (endpoint, mut incoming) = Endpoint::server(
        server_config,
        server_addr()
    )?;

    // Start iterating over incoming connections.
    while let Some(conn) = incoming.next().await {
        let mut connection: NewConnection = conn.await?;

        // Save connection somewhere, start transferring, receiving data, see DataTransfer tutorial.
    }

    Ok(())
}
```

**Client**

The [client()][client] returns only a `Endpoint` type.
The client needs to connect to the server using the [connect(server_name)][connect] method.  
The `SERVER_NAME` argument is the DNS name, matching the certificate configured in the server.

```rust
async fn client() -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given client address.
    let mut endpoint = Endpoint::client(client_addr());

    // Connect to the server passing in the server name which is supposed to be in the server certificate.
    let new_connection = endpoint.connect(server_addr(), SERVER_NAME)?.await?;
    let NewConnection { connection, .. } = new_connection;

    // Start transferring, receiving data, see data transfer page.

    Ok(())
}
```
<br><hr>

[Next up](data-transfer.md), let's have a look at sending data over this connection.  


[Endpoint]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html
[server]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.server
[client]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client
[connect]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.connect
