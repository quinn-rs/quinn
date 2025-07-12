we need to implement RFC 7250 Raw Public Keys support in a fork.. This will allow P2P connections without the overhead of full X.509 certificates, similar to what the Iroh project did in their v0.34 release.
Background:

Quinn currently uses rustls for TLS, which requires X.509 certificates
We want to support Raw Public Keys (RPK) as defined in RFC 7250
Each peer has an Ed25519 keypair, where the public key serves as their identity
No certificate authorities or trust chains needed - just direct public key authentication

Requirements:

TLS Extension Support:

Add support for client_certificate_type and server_certificate_type TLS extensions
Certificate type value for RawPublicKey is 2 (from IANA registry)
Extensions negotiate whether to use X.509 or Raw Public Keys


Certificate Structure Changes:

Instead of X.509 certificates, use SubjectPublicKeyInfo structure directly
SubjectPublicKeyInfo contains just the algorithm OID and public key bytes
For Ed25519: OID is 1.3.101.112


rustls Integration:

Need custom ServerCertVerifier and ClientCertVerifier implementations
Override certificate validation to extract and verify raw public keys
May need to use rustls' dangerous_configuration feature


API Changes:

Add methods to EndpointBuilder like .use_raw_public_keys() or .tls_raw_public_key()
Accept PublicKey/PrivateKey directly instead of certificates
Maintain backward compatibility with existing certificate-based code


Peer Authentication:

Extract peer's public key from TLS handshake
Application can verify this matches expected peer ID
No certificate chain validation needed



Implementation Steps:

Create custom rustls configuration that:

Sends Raw Public Key in Certificate message instead of X.509
Accepts Raw Public Keys from peers
Uses custom verifiers that extract public keys


Modify ant-quic endpoint configuration to:

Option to enable RPK mode
Store keypair instead of certificate chain
Pass through to custom rustls config


Handle the TLS handshake:

Negotiate RPK support via TLS extensions
Send SubjectPublicKeyInfo in Certificate payload
Extract peer's public key for application verification



Example API Usage:
rust// Instead of loading certificates:
let endpoint = Endpoint::builder()
    .use_raw_public_keys()  // Enable RPK mode
    .identity(private_key, public_key)  // Provide keypair directly
    .bind()?;

// When accepting connections:
let connection = endpoint.accept().await?;
let peer_public_key = connection.peer_public_key()?;  // Get peer's raw public key
// Application verifies peer_public_key matches expected identity
Technical Considerations:

RPK is part of TLS 1.3 spec, should work with QUIC

Please implement this Raw Public Key support for Quinn, focusing on:

Clean API that doesn't break existing code
Proper TLS extension negotiation
Efficient public key extraction and verification
Clear documentation and examples

The implementation should allow P2P applications to use public keys as peer identities without certificate overhead, while maintaining security through the existing QUIC/TLS encryption.
