//! This example demonstrates how to make a QUIC connection where the server
//! authenticates the client, as well as the other way around.
//!
//! Checkout the `README.md` for guidance.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use quinn::Connection;
use quinn::Endpoint;
use quinn::RecvStream;
use quinn::SendStream;
use quinn::TransportConfig;
use quinn::VarInt;
use rand::Rng;
use rcgen::BasicConstraints;
use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyUsagePurpose;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use tokio::task::AbortHandle;
use tokio::task::JoinSet;
use tokio::time::sleep_until;
use tokio::time::Duration;
use tokio::time::Instant;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenerateRootCertificate { output: PathBuf },
    GenerateNodeCertificate { output: PathBuf, name: String },
    StartNode { node: u32 },
}

#[tokio::main]
async fn main() -> Result<(), NodeError> {
    let cli = Cli::parse();
    match &cli.command {
        Command::GenerateRootCertificate { output } => {
            generate_root_certificate(output.clone())?;
        }
        Command::GenerateNodeCertificate { output, name } => {
            generate_node_certificate(output.clone(), name.clone())?;
        }
        Command::StartNode { node } => start_node(*node).await.unwrap(),
    }
    Ok(())
}

fn generate_root_certificate(output: PathBuf) -> std::io::Result<()> {
    let cert = new_ca();
    let mut cert_path = output.clone();
    cert_path.push("root");
    std::fs::write(cert_path, cert.serialize_private_key_pem())?;
    let mut cert_path = output.clone();
    cert_path.push("root.pub");
    std::fs::write(cert_path, cert.serialize_pem().unwrap())?;

    Ok(())
}

fn generate_node_certificate(output: PathBuf, name: String) -> std::io::Result<()> {
    let ca = load_root(output.clone())?;
    let cert = new_end_entity(&name);
    let mut cert_path = output.clone();
    cert_path.push(name.clone());
    std::fs::write(cert_path, cert.serialize_private_key_pem())?;
    let mut cert_path = output.clone();
    cert_path.push(format!("{}.pub", name));
    std::fs::write(cert_path, cert.serialize_pem_with_signer(&ca).unwrap())?;

    Ok(())
}

fn new_ca() -> Certificate {
    let mut params = CertificateParams::new(vec!["root.local".into()]);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    Certificate::from_params(params).unwrap()
}

fn new_end_entity(name: &str) -> Certificate {
    let name = format!("{}.local", name);
    let mut params = CertificateParams::new(vec![name.clone()]);
    params.distinguished_name.push(DnType::CommonName, name);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    Certificate::from_params(params).unwrap()
}

fn load_root(output: PathBuf) -> std::io::Result<Certificate> {
    let mut cert_path = output.clone();
    cert_path.push("root");

    let key_pair_pem = std::fs::read_to_string(cert_path)?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pair_pem).unwrap();

    let mut cert_path = output.clone();
    cert_path.push("root.pub");

    let pub_pem = std::fs::read_to_string(cert_path)?;

    let params = rcgen::CertificateParams::from_ca_cert_pem(&pub_pem, key_pair).unwrap();

    Ok(Certificate::from_params(params).unwrap())
}

#[derive(Error, Debug)]
enum NodeError {
    #[error("IO Error")]
    IO(#[from] std::io::Error),
    #[error("Write Error")]
    Write(#[from] quinn::WriteError),
    #[error("Read Error")]
    Read(#[from] quinn::ReadError),
    #[error("Read To End Error")]
    ReadToEnd(#[from] quinn::ReadToEndError),
    #[error("Connection Error")]
    Connection(#[from] quinn::ConnectionError),
    #[error("Connect Error")]
    Connect(#[from] quinn::ConnectError),
    #[error("Send Error")]
    Send(#[from] SendError<(String, SendStream, RecvStream)>),
    #[error("rustls::Error")]
    Tls(#[from] rustls::Error),
}

enum ControlMessage {
    AcceptConnection {
        connection: Connection,
    },
    Connection {
        remote_name: String,
        send: SendStream,
        recv: RecvStream,
    },
}

async fn start_node(node: u32) -> Result<(), NodeError> {
    let mut config: HashMap<String, SocketAddr> = Default::default();
    for i in 0..5 {
        if i == node {
            continue;
        }

        let remote_name = format!("node{}.local", i);
        let address = format!("127.0.0.1:{}", 10000 + i).parse().unwrap();
        config.insert(remote_name, address);
    }

    let endpoint = build_endpoint(node)?;
    let mut connection_handles: HashMap<String, AbortHandle> = HashMap::default();

    let (stop_tx, _) = broadcast::channel(16);
    let (tx, mut rx) = mpsc::channel::<ControlMessage>(5);
    let mut join_set = JoinSet::default();

    check_connections(
        &mut join_set,
        &config,
        &mut connection_handles,
        &endpoint,
        stop_tx.subscribe(),
    )
    .await;

    join_set.spawn(server_task(
        endpoint.clone(),
        tx.clone(),
        stop_tx.subscribe(),
    ));

    let mut rng = rand::thread_rng();
    let duration = Duration::from_millis(rng.gen_range(3000..=5000));
    let mut deadline = Instant::now() + duration;

    loop {
        tokio::select! {
            r = rx.recv() => {
                match r {
                    None => break,
                    Some(ControlMessage::Connection { remote_name, mut send, recv }) => {
                        {
                            let entry = connection_handles.entry(remote_name.clone());
                            if let Entry::Occupied(entry) = entry {
                                let abort_handle = entry.get();
                                if abort_handle.is_finished() {
                                    entry.remove();
                                } else {
                                    let _ = send.finish().await;
                                    continue;
                                }
                            }
                        }
                        connection_handles.insert(
                            remote_name.clone(),
                            join_set.spawn(connection("S", remote_name.clone(), send, recv, stop_tx.subscribe())),
                        );
                    },
                    Some(ControlMessage::AcceptConnection {connection }) => {
                        join_set.spawn(server_connection(connection, tx.clone()));
                    }
                }
            },
            _ = sleep_until(deadline) => {
                check_connections(&mut join_set, &config, &mut connection_handles, &endpoint, stop_tx.subscribe()).await;

                let duration = Duration::from_millis(rng.gen_range(3000..=5000));
                deadline = Instant::now() + duration;
            },
            _ = tokio::signal::ctrl_c() => {
                println!("Cleaning up nicely");
                stop_tx.send(()).unwrap();
                break;
            }
        }
    }

    while join_set.join_next().await.is_some() {
        // Do Nothing
    }

    Ok(())
}

async fn check_connections(
    join_set: &mut JoinSet<Result<(), NodeError>>,
    config: &HashMap<String, SocketAddr>,
    connection_handles: &mut HashMap<String, AbortHandle>,
    endpoint: &Endpoint,
    stop_rx: broadcast::Receiver<()>,
) {
    println!("Checking connections");
    for (remote_name, address) in config.iter() {
        let entry = connection_handles.entry(remote_name.clone());
        match entry {
            Entry::Occupied(o) => {
                if o.get().is_finished() {
                    println!("Connection aborted {}", remote_name);
                    o.remove();
                } else {
                    continue;
                }
            }
            Entry::Vacant(v) => {
                v.insert(join_set.spawn(client_task(
                    remote_name.clone(),
                    *address,
                    endpoint.clone(),
                    stop_rx.resubscribe(),
                )));
            }
        }
    }
}

fn build_endpoint(node: u32) -> Result<Endpoint, NodeError> {
    let cert_dir = PathBuf::from("./certificates");
    let mut private_key = cert_dir.clone();
    private_key.push(format!("node{}", node));
    let mut public_key = cert_dir.clone();
    public_key.push(format!("node{}.pub", node));
    let (server_config, client_config) =
        load_mutual_certificates(private_key.clone(), public_key.clone())?;

    let mut endpoint = Endpoint::server(
        server_config,
        format!("127.0.0.1:{}", 10000 + node).parse().unwrap(),
    )?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

fn load_mutual_certificates(
    private_key: PathBuf,
    public_key: PathBuf,
) -> Result<(quinn::ServerConfig, quinn::ClientConfig), NodeError> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(2000).into()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_millis(500)));

    let mut certificate = PathBuf::from("./certificates");
    certificate.push("root.pub");

    let mut root = rustls::RootCertStore::empty();

    let root_cert_chain: Vec<_> = rustls_pemfile::certs(&mut &*std::fs::read(certificate)?)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    root.add(&root_cert_chain[0])?;

    let key_pair_pem = std::fs::read(private_key)?;
    let public_key_pem = std::fs::read(public_key)?;

    let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key_pair_pem).unwrap();
    let private_key = rustls::PrivateKey(pkcs8.into_iter().next().unwrap());
    let cert_chain: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*public_key_pem)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
            root.clone(),
        )))
        .with_single_cert(cert_chain.clone(), private_key.clone())
        .unwrap();

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root)
        .with_client_auth_cert(cert_chain, private_key)?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(transport_config));

    Ok((
        quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
        client_config,
    ))
}

async fn server_task(
    endpoint: Endpoint,
    tx: mpsc::Sender<ControlMessage>,
    mut stop_rx: broadcast::Receiver<()>,
) -> Result<(), NodeError> {
    loop {
        tokio::select! {
            _ = stop_rx.recv() => {
                return Ok(())
            },
            conn = endpoint.accept() => {
                match conn {
                    None => return Ok(()),
                    Some(conn) => {
                        let connection: Result<quinn::Connection, _> = conn.await;
                        match connection {
                            Err(e) => println!("Connection failed: {:?}", e),
                            Ok(connection) => {
                                tx.send(ControlMessage::AcceptConnection { connection }).await.unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn server_connection(
    connection: Connection,
    tx: mpsc::Sender<ControlMessage>,
) -> Result<(), NodeError> {
    println!("Remote IP: {}", connection.remote_address());

    while let Ok((send, recv)) = connection.accept_bi().await {
        let remote_name = match peer_name(&connection) {
            Err(_) => continue,
            Ok(s) => s,
        };
        tx.send(ControlMessage::Connection {
            remote_name,
            send,
            recv,
        })
        .await
        .unwrap();
    }
    Ok(())
}

fn peer_name(conn: &quinn::Connection) -> Result<String, ()> {
    let peer_identity = conn.peer_identity().unwrap();
    let peer_identity: Box<Vec<rustls::Certificate>> = match peer_identity.downcast() {
        Err(_e) => {
            conn.close(VarInt::from_u32(1), b"Failed handshake");
            return Err(());
        }
        Ok(hd) => hd,
    };

    let certificate =
        x509_certificate::certificate::X509Certificate::from_der(&peer_identity.deref()[0])
            .unwrap();

    let subject_name = certificate.subject_name();

    let common_name = subject_name
        .iter_common_name()
        .next()
        .unwrap()
        .value
        .to_string()
        .unwrap();
    Ok(common_name)
}

async fn client_task(
    remote_name: String,
    address: SocketAddr,
    endpoint: Endpoint,
    stop_rx: broadcast::Receiver<()>,
) -> Result<(), NodeError> {
    tokio::time::sleep(Duration::from_secs(3)).await;
    // let remote = format!("node{}.local", i);
    println!("Connecting to {} {}", address, remote_name);
    let conn = endpoint.connect(address, &remote_name)?.await;

    let conn = match conn {
        Err(_) => {
            println!("Failed to connect to {}", remote_name);
            return Ok(());
        }
        Ok(conn) => conn,
    };

    let (mut send, recv) = conn.open_bi().await?;

    println!("Connected to {}", remote_name);
    send.write_all(b"test").await?;
    send.flush().await?;

    connection("C", remote_name, send, recv, stop_rx).await?;

    Ok(())
}

async fn connection(
    origin: &'static str,
    remote_name: String,
    mut send: SendStream,
    mut recv: RecvStream,
    mut stop_rx: broadcast::Receiver<()>,
) -> Result<(), NodeError> {
    let mut buf: [u8; 4096] = [0; 4096];
    loop {
        println!("{}: Reading from {}...", origin, remote_name);
        tokio::select! {
            _ = stop_rx.recv() => {
                return Ok(());
            },
            len = recv.read(&mut buf) => {
                let len = match len {
                    Ok(None) | Err(_) => {
                        println!("{}: Connection lost from {}", origin, remote_name);
                        return Ok(());
                    }
                    Ok(Some(i)) => i,
                };

                println!(
                    "{}: Received {:?}",
                    origin,
                    std::str::from_utf8(&buf[..len]).unwrap()
                );

                tokio::time::sleep(Duration::from_secs(2)).await;

                println!("{}: Writing to {}...", origin, remote_name);
                if let Err(e) = send.write_all(&buf[..len]).await {
                    println!("{}: Connection lost from {} ({:?})", origin, remote_name, e);
                    return Ok(());
                }
                send.flush().await?;
            }
        };
    }
}
