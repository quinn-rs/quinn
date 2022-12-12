# The QUIC protocol
[QUIC] is a general-purpose network protocol built on top of UDP,
and [standardized][rfc] by the [IETF]. Although QUIC is still relatively new, 
the protocol is used for all connections from Chrome web browsers to the Google servers. 
 
QUIC solves a number of transport-layer and application-layer problems experienced by modern web applications. 
It is very similar to TCP+TLS+HTTP2, but implemented on top of UDP. 
Having QUIC as a self-contained protocol allows innovations which aren’t 
possible with existing protocols as they are hampered by legacy clients and middleboxes.

Key advantages of QUIC over TCP+TLS+HTTP2 include:
* Improved connection establishment speed (0-rtt).
* Improved congestion control by moving congestion control algorithms into the user space at both endpoints.
* Improved bandwidth estimation in each direction to avoid congestion. 
* Improved multiplexing without head-of-line blocking.
* Contains forward error correction (FEC). 
 
While QUIC's intentions are originally web-oriented, it offers interesting opportunities in other areas like game networking.
One thing is for sure, QUIC has many great potentials and will serve us in the future with HTTP/3. 

In the upcoming chapter we will be discussing various aspects of QUIC also in relation to Quinn. 

[rfc]: https://www.rfc-editor.org/rfc/rfc9000.html
[IETF]: https://www.ietf.org/
[QUIC]: https://en.wikipedia.org/wiki/QUIC
