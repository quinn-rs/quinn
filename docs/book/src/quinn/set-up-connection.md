# Connection Setup

In the [previous chapter](certificate.md) we looked at how to configure a certificate.
This aspect is omitted in this chapter to prevent duplication.
But **remember** that this is required to get your [Endpoint][Endpoint] up and running.
This chapter explains how to set up a connection and prepare it for data transfer.

It all starts with the [Endpoint][Endpoint] struct, this is the entry point of the library.

## Example

Let's start by defining some constants.

```rust
{{#include ../bin/set-up-connection.rs:35:38}}
```

**Server**

First, the server endpoint should be bound to a socket.
The [server()][server] method, which can be used for this, returns the `Endpoint` type.
`Endpoint` is used to start outgoing connections and accept incoming connections.

```rust
{{#include ../bin/set-up-connection.rs:8:20}}
```

**Client**

The [client()][client] returns only a `Endpoint` type.
The client needs to connect to the server using the [connect(server_name)][connect] method.
The `SERVER_NAME` argument is the DNS name, matching the certificate configured in the server.

```rust
{{#include ../bin/set-up-connection.rs:23:33}}
```

<br><hr>

[Next up](data-transfer.md), let's have a look at sending data over this connection.

[Endpoint]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html
[server]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.server
[client]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client
[connect]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.connect
