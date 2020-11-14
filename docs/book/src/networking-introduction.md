# Networking Introduction

In this chapter, you will find a very short introduction to various networking concepts. 
Those concepts are key for understanding the motivations for QUIC. 

## 1. TCP/IP and UDP Comparison

**TCP:** stands for 'transmission control protocol' and adds certain guarantees ontop of [IP][3]. 
It forms the backbone for almost everything you do online, from web browsing to IRC to email to file transfer.
The protocol is [reliable ordered][guarantees] in nature.

**UDP** stands for 'user datagram protocol' and adds certain guarantees ontop of [IP][3], but unlike TCP, 
instead of adding lots of features and complexity, UDP is a very thin layer over IP and is also [unreliable][guarantees] in nature.

| Feature |  TCP  | UDP | QUIC
| :-------------: | :-------------: | :-------------: | :-------------: |
|  [Connection-Oriented][6]           |       Yes                      | No                       | Yes
|  [Transport Guarantees][guarantees] | [Reliable Ordered][guarantees] | [Unreliable][guarantees] | [Reliable Ordered][guarantees] and [Unreliable][guarantees] 
|  Packet Transfer                    | [Stream-based][4]              | Message based            | Message based and Stream based
|  Automatic [fragmentation][8]       | Yes                            | Yes, but better to stay below datagram size limit | Yes
|  Header Size                        |  20 bytes                      | 8 bytes                  |  16 bytes  
|  [Control Flow, Congestion Avoidance/Control][5] | Yes               | No                       |  Yes, and user controlled                                          

## 2. The 5 Transport Guarantees

There are 5 main different ways you can transfer data:

| Transport Guarantees         | Packet Drop [(1)][1]  | Packet Duplication [(2)][2] | Packet Order | Packet Delivery |
| :-------------:              | :-------------: | :-------------: | :-------------: | :-------------:
|   **Unreliable Unordered**   |       Any       |      Yes        |     No          |   No
|   **Unreliable Sequenced**   |    Any + old    |      No         |     Sequenced   |   No
|   **Reliable Unordered**     |       No        |      No         |     No          |   Yes
|   **Reliable Ordered**       |       No        |      No         |     Ordered     |   Yes
|   **Reliable Sequenced**     |    Only old     |      No         |     Sequenced   |   Only newest

Unreliability gives great uncertainty with a lot of freedom, while reliability gives great certainty with costs in speed and freedom.
That is why protocols such as QUIC, RUDP, SCTP, QUIC, netcode, laminar are built on UDP instead of TCP. 
UDP gives the end-user more control over the transmission than TCP can do. 

## 3. Issues with TCP 

Now the golden question: "Why choose so much uncertainty with UDP when TCP is so reliable and safe?". 
To answer that question we will have to delve a little deeper into some issues with TCP. 

### Head-of-line Blocking

One of the biggest issues with TCP is that of Head-of-line blocking. 
It is a convenient feature because it ensures that all packages are sent and arrive in [order][guarantees]. 
However, in cases of high throughput (multiplayer game networking) and big load in a short time (web page load), this can be catastrophic to your application performance.

The issue is demonstrated in the following animation:

![Head of line blocking][animation] 

This animation shows that if a certain packet drops in transmission, all packets have to wait at the transport layer until it is resent by the other end.
If the dropped packet is resent and arrived then all packets are freed from the transport layer. 

Let's look at two areas where this head-of-line blocking issue is a huge deal.

**Multiplayer Game Networking**

Multiplayer action games are based on a constant stream of packets sent at a speed ranging from 10 to 30 packets per second.
For the most part, the data in these packages are so time-sensitive that only the most recent data is useful.
You can think of the input and position of the player, the orientation and speed, and the state of the physical objects in the world.
If a single packet drops out we can not afford to queue up 10-30 packets a second until the lost packet is retransmitted. 
This could cause annoying lag behavior and a bad user experience. 

**Web Networking**

Game networking is not the only area where this head-of-line blocking is a big issue.
The World Wide Web is a place where quick web-page load speeds are important (who wants to wait 200ms to the long right?).
As websites get bigger and attention decreases, we need faster loading times for websites.

To tackle this issue, HTTP-2 introduced a technique called multiplexing. 
In short, this means that multiple TCP streams are initialized to communicate with the server. 
Then If one of them blocks the whole website can continue to load seemingly while that single stream is retransmitting.

We will take a deeper dive into this subject when looking at QUIC multiplexing.
    
### Connection Setup Duration

In the standard HTTP+TLS+TCP stack, TCP needs a handshake to establish a session between server and client, 
and TLS needs its handshake to ensure that the session is secured.

![TCP-handshake](./images/tcp-handshake.svg.png)

First, the source sends an 'SYN initial request' packet to the target server to start the dialogue. 
Then the target server sends an 'SYN-ACK packet' to agree to the process.
Lastly, the source sends an 'ACK packet' to the target to confirm the process, after which the message exchange can start. 
 
Now if we want to secure the TCP connection, we have to use a protocol like TLS on top of it. 
In the case of TLS versions older than 1.3, an additional three more handshake messages are required.

You can see how expensive it is to create a secure TCP connection. 
In a scenario of TCP and TLS 1.2 with a 100ms latency, we need to wait for 6 x 100ms = 600ms to set up a connection. 
If the website is big, an additional load time can make the website load over a second. 
This, of course, is disturbing for our short attention spans. 

### Requests in Segment

A TCP segment can only carry a single HTTP/1.1 Request/Response. 
Consequently, a large number of small segments may be sent within
an HTTP/1.1 session which can lead to overhead.

### Client Connection Initiation

HTTP/1.1 transfers are always initiated by the client. 
This decreases the performance of HTTP/1.1 significantly when loading embedded files because a server has to
wait for a request from the client, even if the server knows
that the client needs a specific resource.


[guarantees]: #2-the-5-transport-guarantees
[animation]: ./images/hol.gif 

[1]: https://en.wikipedia.org/wiki/Packet_loss
[2]: https://observersupport.viavisolutions.com/html_doc/current/index.html#page/gigastor_hw/packet_deduplicating.html
[3]: https://nl.wikipedia.org/wiki/Internetprotocol
[4]: https://en.wikipedia.org/wiki/Stream_(computing)
[5]: https://en.wikipedia.org/wiki/TCP_congestion_control
[6]: https://en.wikipedia.org/wiki/Connection-oriented_communication
[7]: https://en.wikipedia.org/wiki/Internet_protocol_suite
[8]: https://en.wikipedia.org/wiki/IP_fragmentation