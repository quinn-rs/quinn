# Networking Introduction

The Internet is unreliable, it changes every second, cables can be cut, network congestion can occur, packets can become corrupted, etc. 
As soon as we send a packet, it can take any road to reach its destination. 
To assure the end-user of certain transmission guarantees, such as the arrival of packets, specific protocols are defined.  

Some of those established protocols are TCP and UDP which are supported by all routers, firewalls, servers, and operating systems. 
However, this does not mean that they are perfect or flawless.
One of the reasons to build QUIC is to solve those problems.  

Before jumping directly into the meat of QUIC, it can be useful to understand its underlying motivations. 
For those motivations, we have to inspect the flaws of TCP and the nature of UDP, 
because QUIC tries to improve the flaws of TCP on top of UDP.

1. [Transport Guarantees](network-introduction/transport-guarantees.md) (what guarantees for transmission exists)
2. [Transport Protocols](network-introduction/transport-protocols.md) (analyse of UDP and TCP internals)
3. [TCP Problems](network-introduction/tcp-problems.md) (description of TCP its problems)
 