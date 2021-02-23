# Networking Introduction

In this chapter, you will find a very short introduction to various networking concepts. 
These concepts are important to understanding when to use QUIC.

## 1. TCP/IP and UDP Comparison

Let's compare TCP, UDP, and QUIC.

- **unreliable**: Transport packets are not assured of arrival and ordering. 
- **reliable**: Transport packets are assured of arrival and ordering.

| Feature |  TCP  | UDP | QUIC
| :-------------: | :-------------: | :-------------: | :-------------: |
|  [Connection-Oriented][6]           |       Yes         | No                       | Yes
|  Transport Guarantees               | Reliable          | Unreliable               | Reliable ('a)
|  Packet Transfer                    | [Stream-based][4] | Message based            | Stream based
|  Header Size                        |  ~20 bytes         | 8 bytes                  |  ~16 bytes (depending on connection id)  
|  [Control Flow, Congestion Avoidance/Control][5] | Yes  | No                       |  Yes ('b)                                      
|  Based On | [IP][3]                 | [IP][3]           |  UDP

'a. Unreliable is supported as an extension.    
'b. QUIC control flow/congestion implementations will run in userspace whereas in TCP it's running in kernel space, 
however, there might be a kernel implementation for QUIC in the future.

## 2. Issues with TCP 

TCP has been around for a long time and was not designed with the modern internet in mind. 
It has several difficulties that QUIC tries to resolve. 

### Head-of-line Blocking

One of the biggest issues with TCP is that of Head-of-line blocking. 
It is a convenient feature because it ensures that all packages are sent and arrive in order. 
However, in cases of high throughput (multiplayer game networking) and big load in a short time (web page load), this can severely impact latency.

The issue is demonstrated in the following animation:

![Head of line blocking][animation] 

This animation shows that if a certain packet drops in transmission, all packets have to wait at the transport layer until it is resent by the other end. Once the delayed packet arrives at its destination, all later packets are passed on to the destination application together.

Let's look at two areas where head-of-line blocking causes problems. 

**Web Networking**

As websites increasingly need a larger number of HTTP requests (HTML, CSS, JavaScript, images) to display all content, the impact of head-of-line blocking has also increased. 
To improve on this, HTTP 2 introduced request multiplexing within a TCP data stream, which allows servers to stream multiple responses at the same time. 
However, data loss of a single packet will still block all response streams because they exist within the context of a single TCP stream.

### Connection Setup Duration

In the usual TCP + TLS + HTTP stack, TCP needs 6 handshake messages to set up a session between server and client. TLS performs its own, sending 4 messages for setting up an initial connection over TLS 1.3. By integrating the transport protocol and TLS handshakes, QUIC can make connection setup more efficient.

[animation]: ./images/hol.gif 

[1]: https://en.wikipedia.org/wiki/Packet_loss
[2]: https://observersupport.viavisolutions.com/html_doc/current/index.html#page/gigastor_hw/packet_deduplicating.html
[3]: https://nl.wikipedia.org/wiki/Internetprotocol
[4]: https://en.wikipedia.org/wiki/Stream_(computing)
[5]: https://en.wikipedia.org/wiki/TCP_congestion_control
[6]: https://en.wikipedia.org/wiki/Connection-oriented_communication
[7]: https://en.wikipedia.org/wiki/Internet_protocol_suite
[8]: https://en.wikipedia.org/wiki/IP_fragmentation
