# Connection Setup

In the [previous chapter](certificate.md) we looked at how to configure a certificate.
This aspect is omitted in this chapter to prevent duplication. 
But **remember** that is is required to get your [Endpoint][Endpoint] up and running. 
This chapter explains how to set up a connection and prepare it for data transfer. 

It all starts with the [Endpoint][Endpoint] struct, this is the entry of the library. 

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

For both the server and the client we use the [EndpointBuilder][EndpointBuilder]. 
The [EndpointBuilder][EndpointBuilder] has a method [bind(address)][bind] with which you link an address to the endpoint. 
This method initializes a UDP-socket that is used by quinn.
If you need more control over the socket creation, it is also possible to initialize a quinn endpoint with an existing UDP socket with [with_socket][with_socket]. 

**Server**

Just like a TCP Listener, you have to listen to incoming connections.
Before you can listen to connections you need to configure the [EndpointBuilder][EndpointBuilder] as a server. 
Note that the configuration itself does not perform any listening logic, instead use the `Incomming` type returned by [bind()][bind].  

```rust
async fn server() -> anyhow::Result<()> {
    let mut endpoint_builder = Endpoint::builder();
    // Configure this endpoint as a server by passing in `ServerConfig`.
    endpoint_builder.listen(ServerConfig::default());

    // Bind this endpoint to a UDP socket on the given server address. 
    let (endpoint, mut incoming) = endpoint_builder.bind(&server_addr())?;

    // Start iterating over incoming connections.
    while let Some(conn) = incoming.next().await {
        let mut connection: NewConnection = conn.await?;

        // Save connection somewhere, start transferring, receiving data, see DataTransfer tutorial.
    }

    Ok(())
}
```

**Client**

Just like a TCP client, you need to connect to a listening endpoint (the server).
In quinn you can do this with the method [connect()][connect].
The [connect()][connect] method has an argument 'server name' which has to be the name that is in the configured certificate. 

```rust
async fn client() -> anyhow::Result<()> {
    let mut endpoint_builder = Endpoint::builder();

    // Bind this endpoint to a UDP socket on the given client address.
    let (endpoint, _) = endpoint_builder.bind(&client_addr())?;

    // Connect to the server passing in the server name which is supposed to be in the server certificate.
    let connection: NewConnection = endpoint
        .connect(&server_addr(), SERVER_NAME)?
        .await?;

    // Start transferring, receiving data, see data transfer page.

    Ok(())
}
```
<br><hr>

[Nextup](set-up-connection.md), lets have a look at sending data over this connection.  


[Endpoint]: https://docs.rs/quinn/latest/quinn/generic/struct.Endpoint.html
[EndpointBuilder]: https://docs.rs/quinn/latest/quinn/generic/struct.EndpointBuilder.html
[bind]: https://docs.rs/quinn/latest/quinn/generic/struct.EndpointBuilder.html#method.bind
[connect]: https://docs.rs/quinn/latest/quinn/generic/struct.Endpoint.html#method.connect
[with_socket]: https://docs.rs/quinn/latest/quinn/generic/struct.EndpointBuilder.html#method.with_socket