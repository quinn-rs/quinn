# Transport Guarantees

Let's start by defining terminology that is often used when it comes to protocols. 
There are 'transport guarantees' such as the order at which packets arrive, 
and regulation of packet corruption, duplication, and dropping. 

## Ordering VS Sequencing

Packet arrival is possible in two ways. 
They can arrive in sequence and in order. 

Let's define two concepts here:
- "Sequencing: this is the process of only caring about the newest items."_ [1](https://dictionary.cambridge.org/dictionary/english/sequencing)
- "Ordering: this is the process of putting something in a particular order."_ [2](https://dictionary.cambridge.org/dictionary/english/ordering)

**Example**

- Sequencing: Only the newest items will be passed trough e.g. `1,3,2,5,4` which results in `1,3,5`.
- Ordering: All items are returned in order `1,3,2,5,4` which results in `1,2,3,4,5`.

## The 5 Transport Guarantees

There are 5 main different ways you can transfer data:

| Transport Guarantees         | Packet Drop [(1)][1]  | Packet Duplication [(2)][2] | Packet Order [(3)](#ordering-vs-sequencing) | Packet Delivery |
| :-------------:              | :-------------: | :-------------:    | :-------------:  |  :-------------:
|   **Unreliable Unordered**   |       Any       |      Yes           |     No           |    No
|   **Unreliable Sequenced**   |    Any + old    |      No            |     Sequenced    |    No
|   **Reliable Unordered**     |       No        |      No            |     No           |    Yes
|   **Reliable Ordered**       |       No        |      No            |     Ordered      |    Yes
|   **Reliable Sequenced**     |    Only old     |      No            |     Sequenced    |    Only newest

Unreliability gives great uncertainty with a lot of freedom, while reliability gives great certainty with costs in speed and freedom.
That is why protocols such as QUIC, RUDP, SCTP, QUIC, netcode, laminar are build on UDP instead of TCP. 
UDP gives the end user more control over the transmission then TCP is able to do. More on this [later](transport-protocols.md).

Sometimes you hear fierce discussions about why one protocol is better than the other, 
but I think we should start looking at what protocol has what purposes.
The key is that a combination of these guarantees are needed for different use cases. 
It is therefore important that you check for your scenario which one you need. 

<br><hr>

[Nextup](transport-protocols.md), we will apply this concept of transport guarantees to TCP and UDP.

[1]: https://en.wikipedia.org/wiki/Packet_loss
[2]: https://observersupport.viavisolutions.com/html_doc/current/index.html#page/gigastor_hw/packet_deduplicating.html
