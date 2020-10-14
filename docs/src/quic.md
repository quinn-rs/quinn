# QUIC Introduction

QUIC is a general-purpose, transport layer, network protocol, built on top of UDP.
It is still an internet [draft][draft] undergoing standardization by the IETF.
This indicates that it is not yet stabilized. 
Quinn focuses on satisfying the latest draft but may lag some drafts behind. 
The fact that it is a draft does not detract from the fact that QUIC is already used by more than half of 
all connections from Chrome web browsers to Google's servers with increasing adoption in the overall market. 

QUIC aims to be nearly equivalent to a TCP connection. With the goals to improve the performance of connection-oriented web applications, 
reduce connection and transport latency, and estimate bandwidth for better congestion control. 
While the intentions of QUIC were original web-oriented, it suits other areas like the game-networking industry very well.   

[draft]: https://datatracker.ietf.org/doc/draft-ietf-quic-transport/