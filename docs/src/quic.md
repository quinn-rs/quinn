# QUIC Introduction
QUIC is a general-purpose network protocol built on top of UDP.
The protocol is still under development and standardized by the IETF. 
Quinn strives to implement the latest draft but may lag a bit behind.  
Although QUIC is still in a draft phase, the protocol is used for all connections from Chrome web browsers to the Google servers. 
 
The goal of QUIC is to provide the same functionalities as TCP while fixing many problems and adding additional features. 
QUIC's goals include reduced connection and transport latency, and bandwidth estimation in each direction to avoid congestion. 
It also moves congestion control algorithms into the user space at both endpoints, rather than the kernel space.
Additionally, the protocol can be extended with forward error correction (FEC) to further improve performance when errors are expected.

While QUIC's intentions are originally web-oriented, it offers interesting opportunities in other areas like game networking.
One thing is for sure, QUIC has many great potentials and will serve us in the future with HTTP/3.

[draft]: https://datatracker.ietf.org/doc/draft-ietf-quic-transport/