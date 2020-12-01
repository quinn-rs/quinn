# Certificates

In this chapter, we discuss the configuration of the certificates that is **required** for a working Quinn connection. 

QUIC uses TLS 1.3 for authentication of connections, the server will have to provide the client with a certificate confirming its identity, 
and the customer must be configured to trust the certificates he receives from our server. 

## Insecure Connection

For our example use case, the easiest way to allow the client to trust our server is to disable certificate verification (don't do this in production!). 
When the `dangerous_configuration` feature flag of [rustls][3] is enabled, a client can be configured to trust any server.

Start with adding a [rustls][3] dependency with the `dangerous_configuration` feature flag to your `Cargo.toml` file.

```toml
quinn = "*"
rustls = { version = "*", features = ["dangerous_configuration", "quic"] }
``` 

Then, you can skip the certificate validation on the client by implementing [ServerCertVerifier][ServerCertVerifier] and let it assert true for any server. 

```rust
// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipCertificationVerification;

impl rustls::ServerCertVerifier for SkipCertificationVerification {
    fn verify_server_cert(
        &self, _: &rustls::RootCertStore, _: &[rustls::Certificate], _: webpki::DNSNameRef, _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}
```

After that, we can configure our [ClientConfig][ClientConfig] to use this new [ServerCertVerifier][ServerCertVerifier]. 

```rust
pub fn insecure() -> ClientConfig {
    let mut cfg = quinn::ClientConfigBuilder::default().build();

    // Get a mutable reference to the 'crypto' config in the 'client config'..
    let tls_cfg: &mut rustls::ClientConfig =
        std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();

    // Change the certification verifier.
    // This is only available when compiled with 'dangerous_configuration' feature.
    tls_cfg
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipCertificationVerification));
    cfg
}
```
 
Finally, if you plug this [ClientConfig][ClientConfig] into the [EndpointBuilder::default_client_config()][default_client_config] your client endpoint should verify all connections as trustworthy.

## Using Certificates

In this section we look at certifying an endpoint with a real certificate. 
This can be done with either a real certificate or a self-identified certificate.

### Self Signed

A [self-signed][5] certificate entails that you sign a certificate with your own CA. 
These certificates are easy to create and cost no money. 
However, they do not offer all the security features that certificates from a trusted CA do have. 
Some ways to create a self-signed certificate is by using [rcgen][4] or openssl. 
In this example [rcgen][4] is used.   

Let's look at an example:

```rust
pub fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> anyhow::Result<(quinn::Certificate, quinn::PrivateKey)> {
    // Generate dummy certificate.
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let serialized_key = certificate.serialize_private_key_der();
    let serialized_certificate = certificate.serialize_der().unwrap();

    // Write to files.
    fs::write(&cert_path, &serialized_certificate).context("failed to write certificate")?;
    fs::write(&key_path, &serialized_key).context("failed to write private key")?;

    let cert = quinn::Certificate::from_der(&cert)?;
    let key = quinn::PrivateKey::from_der(&serialized_key)?;
    Ok((cert, key))
}
```

*Note that [generate_simple_self_signed][generate_simple_self_signed] returns a [Certificate][2] that can be serialized to both `.der` and `.pem` formats.*

### Official Certificates

[Let's Encrypt][6] is a well-known Certificate Authority ([CA][1]) (certificate issuer) and distributes certificates for free.
For this section lets-encrypt is used however any CA could be used interchangeably. 

**Generate Certificate**

Let's encode [Certbot][7] to generate certificates. 
The certbot websites give clear instructions on how to use the tool.  
Normally a certificate is generated to secure a web server and certbot will use it to secure the server. 
However, since we generate a certificate for a protocol, the configuration process will be slightly different than normal.
If you do want to use an existing web server to generate certificates, please follow the instructions on certbot's website.

For this example it is expected that no web server is installed.
 Select on the certbot website that you do not have a web server and follow the given installation instructions. 

Note that servers must be accessible on a public DNS name in order to get a Let's Encrypt certificate.
Certbot must answer a cryptographic challenge of the Let's Encrypt API to prove that we control our domain. 
It uses ports 80 (HTTP) or 443 (HTTPS) to achieve this. Open the appropriate port in your firewall and router.

If certbot is installed, run `certbot certonly --standalone`, this command will start a web server in the background.
Certbot asks for the required data and writes the certificate to `cert.pem` and the private key to `privkey.pem`.  
These files can then be referenced in code.  
 
```rust
pub fn read_cert_from_file() -> anyhow::Result<(quinn::Certificate, quinn::PrivateKey)> {
    // Read from certificate and key from directory.
    let (cert, key) = fs::read(&"./cert.pem").and_then(|x| Ok((x, fs::read(&"./privkey.pem")?)))?;

    // Parse to certificate chain whereafter taking the first certifcater in this chain.
    let cert = quinn::CertificateChain::from_pem(&cert)?.iter().next().unwrap().clone();
    let key = quinn::PrivateKey::from_pem(&key)?;

    Ok((quinn::Certificate::from(cert), key))
}
```

### Configuring Certificates

Now you generated, or maybe you already had, the certificate, they need to be configured into the client and server. 
After configuring plug the configuration into the `Endpoint`.

**Configure Server**

```rust
let mut builder = ServerConfigBuilder::default();
builder.certificate(CertificateChain::from_certs(vec![certificate]), key)?;
```

This is the only thing you need to do for your sever to be secured. 

**Configure Client**

```rust
let mut builder = ClientConfigBuilder::default();
builder.add_certificate_authority(certificate)?;    
```

This is the only thing you need to do for your client trust a server certificate. 

<br><hr>

[Nextup](set-up-connection.md), lets have a look at how to setup a connection. 

[1]: https://en.wikipedia.org/wiki/Certificate_authority
[2]: https://en.wikipedia.org/wiki/Public_key_certificate
[3]: https://github.com/ctz/rustls
[4]: https://github.com/est31/rcgen
[5]: https://en.wikipedia.org/wiki/Self-signed_certificate#:~:text=In%20cryptography%20and%20computer%20security,a%20CA%20aim%20to%20provide.
[6]: https://letsencrypt.org/getting-started/
[7]: https://certbot.eff.org/instructions

[ClientConfig]: https://docs.rs/quinn/latest/quinn/generic/struct.ClientConfig.html
[ServerCertVerifier]: https://docs.rs/rustls/latest/rustls/trait.ServerCertVerifier.html
[default_client_config]: https://docs.rs/quinn/latest/quinn/generic/struct.EndpointBuilder.html#method.default_client_config
[generate_simple_self_signed]: https://docs.rs/rcgen/latest/rcgen/fn.generate_simple_self_signed.html
[Certificate]: https://docs.rs/rcgen/latest/rcgen/struct.Certificate.html