# Networking Introduction

In this chapter, you will find a very short introduction to various networking concepts. 
These concepts are important to understanding when to use QUIC.

## 1. TCP/IP and UDP Comparison

Let's compare TCP, UDP, and QUIC.

- **unreliable**: Transport packeten zijn er niet van verzekerd dat ze aan komen bij hun eindbestemming en op volgorde zijn. 
- **reliable**: Transport packeten zijn er van verzekerd dat ze op volgorde op hun eindbestemming komen.

Unreliability gives great uncertainty with a lot of freedom, while reliability gives great certainty with costs in speed and freedom.
That is why some protocols such as QUIC, SCTP are built on UDP instead of TCP. 

| Feature |  TCP  | UDP | QUIC
| :-------------: | :-------------: | :-------------: | :-------------: |
|  [Connection-Oriented][6]           |       Yes         | No                       | Yes
|  Transport Guarantees               | Reliable          | Unreliable               | Reliable and/or unreliable with extension 
|  Packet Transfer                    | [Stream-based][4] | Message based            | Message based and/or Stream based
|  Header Size                        |  20 bytes         | 8 bytes                  |  ~16 bytes(depending on connection id)  
|  [Control Flow, Congestion Avoidance/Control][5] | Yes  | No                       |  ** Yes, and possible controlled by userspace                                          
|  Based On | [IP][3]                 | [IP][3]           |  UDP

** QUIC control flow/congestion implementations will run in userspace wereas in TCP its running in kernelspace, 
however there might be a kernel implementations for QUIC in the future.

## 2. Issues with TCP 

TCP has been around for a long time and was not designed with the modern internet in mind. 
It has several difficulties that QUIC tries to resolve. 

### Head-of-line Blocking

One of the biggest issues with TCP is that of Head-of-line blocking. 
It is a convenient feature because it ensures that all packages are sent and arrive in order. 
However, in cases of high throughput (multiplayer game networking) and big load in a short time (web page load), this can severely impact latency.

The issue is demonstrated in the following animation:

![Head of line blocking][animation] 

This animation shows that if a certain packet drops in transmission, all packets have to wait at the transport layer until it is resent by the other end.
If the dropped packet is resent and arrived then all packets are freed from the transport layer. 

Let's look at two areas where head-of-line blocking causes problems. 

**Web Networking**

The last years websites have been growing in size which causes. 
This increases the loading time and makes head-of-line blocking a more concerning topic. 
To tackle this issue HTTP-2 has introduced a technique called multiplexing. 
In short, this means that multiple TCP streams are initialized to communicate with the server. 
It allows a server to transfer multiple sources in parallel over a single stream.

**Multiplayer Game Networking**

The web space is not the only area where this head-of-line blocking is a major concern.
Multiplayer action games work with a constant flow of packets sent at an interval ranging between 10 to 30 packets per second.
For the most part, the data in these packets is so time sensitive that only the most recent data can be used. 
Therefore, it cannot be afforded to queue 10-30 packets per second until the lost packet is resent.
Most multiplayer network solutions build a custom protocol on top of UDP to address head-of-line blocking issues while maintaining reliability.
   
### Connection Setup Duration

In the usual HTTP+TLS+TCP stack, TCP needs 6 handshake messages to set up a session between server and client, 
and TLS needs its own handshake to make sure the session is secure.  
This handshake consists of 6 messages for TLS 1.2 or lower, and 4 messages for setting up the 'initial' connection over TLS 1.3.
Despite the '0-RTT' function of TLS 1.3, which allows you to resume a previous connection in 0-RTT, the 6 TCP handshake messages are still required.
Nevertheless, QUIC has the 0-RTT feature as well and is not restrained by the 6 TCP handshake messages.
This implies that QUIC is able to provide encrypted true 0-RTT connections. 

[animation]: ./images/hol.gif 

[1]: https://en.wikipedia.org/wiki/Packet_loss
[2]: https://observersupport.viavisolutions.com/html_doc/current/index.html#page/gigastor_hw/packet_deduplicating.html
[3]: https://nl.wikipedia.org/wiki/Internetprotocol
[4]: https://en.wikipedia.org/wiki/Stream_(computing)
[5]: https://en.wikipedia.org/wiki/TCP_congestion_control
[6]: https://en.wikipedia.org/wiki/Connection-oriented_communication
[7]: https://en.wikipedia.org/wiki/Internet_protocol_suite
[8]: https://en.wikipedia.org/wiki/IP_fragmentation
