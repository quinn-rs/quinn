## HTTPS File Serving

This `http` example shows how to serve files from an directory. 
It exists out of two parts, namely a server and a client:

1. HTTP Server (`http_server.rs`)

The server, listens for any client requesting a file. 
If the file path is valid and allowed, it returns the contents. 

Open up a terminal and execute:

```text
$ cargo run --example http_server ./
```

2. HTTP Client (`http_client.rs`)

The client requests a file. 
If the file is on the server, it will receive the response. 

In a new terminal execute:

```test
$ cargo run --example http_client https://localhost:4433/README.MD
```

**Result:**

The output will be the contents of the README.

## Insecure Connection

## Single Socket