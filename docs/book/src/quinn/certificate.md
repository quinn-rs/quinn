# Certificates

In this chapter, we discuss the configuration of the certificates that are **required** for a working Quinn connection.

As QUIC uses TLS 1.3 for authentication of connections, the server needs to provide the client with a certificate confirming its identity, and the client must be configured to trust the certificates it receives from the server.

## Insecure Connection

For our example use case, the easiest way to allow the client to trust our server is to disable certificate verification (don't do this in production!).
When the [rustls][3] `dangerous_configuration` feature flag is enabled, a client can be configured to trust any server.

Start by adding a [rustls][3] dependency with the `dangerous_configuration` feature flag to your `Cargo.toml` file.

```toml
quinn = "*"
rustls = { version = "*", features = ["dangerous_configuration", "quic"] }
```

Then, allow the client to skip the certificate validation by implementing [ServerCertVerifier][ServerCertVerifier] and letting it assert verification for any server.

```rust
// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
```

After that, modify the [ClientConfig][ClientConfig] to use this [ServerCertVerifier][ServerCertVerifier] implementation.

```rust
fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}
```

Finally, if you plug this [ClientConfig][ClientConfig] into the [Endpoint::set_default_client_config()][set_default_client_config] your client endpoint should verify all connections as trustworthy.

## Using Certificates

In this section, we look at certifying an endpoint with a certificate.
The certificate can be signed with its key, or with a certificate authority's key.

### Self Signed Certificates

Relying on [self-signed][5] certificates means that clients allow servers to sign their certificates.
This is simpler because no third party is involved in signing the server's certificate.
However, self-signed certificates do not protect users from person-in-the-middle attacks, because an interceptor can trivially replace the certificate with one that it has signed. Self-signed certificates, among other options, can be created using the [rcgen][4] crate or the openssl binary.
This example uses [rcgen][4] to generate a certificate.

Let's look at an example:

```rust
fn generate_self_signed_cert() -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn Error>>
{
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    Ok((rustls::Certificate(cert.serialize_der()?), key))
}
```

*Note that [generate_simple_self_signed][generate_simple_self_signed] returns a [Certificate][2] that can be serialized to both `.der` and `.pem` formats.*

### Non-self-signed Certificates

For this example, we use [Let's Encrypt][6], a well-known Certificate Authority ([CA][1]) (certificate issuer) which distributes certificates for free.

**Generate Certificate**

[certbot][7] can be used with Let's Encrypt to generate certificates; its website comes with clear instructions.
Because we're generating a certificate for an internal test server, the process used will be slightly different compared to what you would do when generating certificates for an existing (public) website.

On the certbot website, select that you do not have a public web server and follow the given installation instructions.
certbot must answer a cryptographic challenge of the Let's Encrypt API to prove that you control the domain.
It needs to listen on port 80 (HTTP) or 443 (HTTPS) to achieve this. Open the appropriate port in your firewall and router.

If certbot is installed, run `certbot certonly --standalone`, this command will start a web server in the background and start the challenge.
certbot asks for the required data and writes the certificates to `fullchain.pem` and the private key to `privkey.pem`.
These files can then be referenced in code.

```rust
use std::{error::Error, fs::File, io::BufReader};

pub fn read_certs_from_file(
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Box<dyn Error>> {
    let mut cert_chain_reader = BufReader::new(File::open("./fullchain.pem")?);
    let certs = rustls_pemfile::certs(&mut cert_chain_reader)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let mut key_reader = BufReader::new(File::open("./privkey.pem")?);
    // if the file starts with "BEGIN RSA PRIVATE KEY"
    // let mut keys = rustls_pemfile::rsa_private_keys(&mut key_reader)?;
    // if the file starts with "BEGIN PRIVATE KEY"
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;

    assert_eq!(keys.len(), 1);
    let key = rustls::PrivateKey(keys.remove(0));

    Ok((certs, key))
}
```

### Configuring Certificates

Now that you have a valid certificate, the client and server need to be configured to use it.
After configuring plug the configuration into the `Endpoint`.

**Configure Server**

```rust
let server_config = ServerConfig::with_single_cert(certs, key)?;
```

This is the only thing you need to do for your server to be secured.

**Configure Client**

```rust
let client_config = ClientConfig::with_native_roots();
```

This is the only thing you need to do for your client to trust a server certificate signed by a conventional certificate authority.

<br><hr>

[Next](set-up-connection.md), let's have a look at how to set up a connection.

[1]: https://en.wikipedia.org/wiki/Certificate_authority
[2]: https://en.wikipedia.org/wiki/Public_key_certificate
[3]: https://github.com/ctz/rustls
[4]: https://github.com/est31/rcgen
[5]: https://en.wikipedia.org/wiki/Self-signed_certificate#:~:text=In%20cryptography%20and%20computer%20security,a%20CA%20aim%20to%20provide.
[6]: https://letsencrypt.org/getting-started/
[7]: https://certbot.eff.org/instructions

[ClientConfig]: https://docs.rs/quinn/latest/quinn/struct.ClientConfig.html
[ServerCertVerifier]: https://docs.rs/rustls/latest/rustls/client/trait.ServerCertVerifier.html
[set_default_client_config]: https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.set_default_client_config
[generate_simple_self_signed]: https://docs.rs/rcgen/latest/rcgen/fn.generate_simple_self_signed.html
[Certificate]: https://docs.rs/rcgen/latest/rcgen/struct.Certificate.html
