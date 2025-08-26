#[cfg(feature = "qlog")]
use std::{fs::File, io::BufWriter, path::PathBuf};
use std::{io, net::SocketAddr, num::ParseIntError, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
#[cfg(feature = "qlog")]
use quinn::QlogConfig;
use quinn::{
    AckFrequencyConfig, TransportConfig, VarInt,
    congestion::{self, ControllerFactory},
    udp::UdpSocketState,
};
use rustls::crypto::ring::cipher_suite;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::warn;

#[cfg_attr(not(feature = "json-output"), allow(dead_code))]
pub mod stats;

pub mod noprotection;

pub mod client;
pub mod server;

// Common options between client and server binary
#[derive(Parser)]
pub struct CommonOpt {
    /// Send buffer size in bytes
    ///
    /// This can use SI suffixes for sizes. For example, 1M will request
    /// 1MiB, 10G will request 10GiB.
    #[clap(long, default_value = "2M", value_parser = parse_byte_size)]
    pub send_buffer_size: u64,
    /// Receive buffer size in bytes
    ///
    /// This can use SI suffixes for sizes. For example, 1M will request
    /// 1MiB, 10G will request 10GiB.
    #[clap(long, default_value = "2M", value_parser = parse_byte_size)]
    pub recv_buffer_size: u64,
    /// Whether to print connection statistics
    #[clap(long)]
    pub conn_stats: bool,
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    pub keylog: bool,
    /// UDP payload size that the network must be capable of carrying
    #[clap(long, default_value = "1200")]
    pub initial_mtu: u16,
    /// Disable packet encryption/decryption (for debugging purpose)
    #[clap(long = "no-protection")]
    pub no_protection: bool,
    /// The initial round-trip-time (in msecs)
    #[clap(long, group = "common")]
    pub initial_rtt: Option<u64>,
    /// Ack Frequency mode
    #[clap(long = "ack-frequency")]
    pub ack_frequency: bool,
    /// Congestion algorithm to use
    #[clap(long = "congestion")]
    pub cong_alg: Option<CongestionAlgorithm>,
    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This can use SI suffixes for sizes. For example, 1M will limit to
    /// 1MiB, 10G will limit to 10GiB.
    #[clap(long, value_parser = parse_byte_size)]
    pub stream_receive_window: Option<u64>,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This can use SI suffixes for sizes. For example, 1M will limit to
    /// 1MiB, 10G will limit to 10GiB.
    #[clap(long, value_parser = parse_byte_size)]
    pub receive_window: Option<u64>,
    /// Maximum number of bytes to transmit to a peer without acknowledgment
    ///
    /// This can use SI suffixes for sizes. For example, 1M will limit to
    /// 1MiB, 10G will limit to 10GiB.
    #[clap(long, value_parser = parse_byte_size)]
    pub send_window: Option<u64>,
    /// Max UDP payload size in bytes
    #[clap(long, default_value = "1472")]
    pub max_udp_payload_size: u16,
    /// qlog output file
    #[cfg(feature = "qlog")]
    #[clap(long = "qlog")]
    pub qlog_file: Option<PathBuf>,
}

impl CommonOpt {
    pub fn build_transport_config(
        &self,
        #[cfg(feature = "qlog")] name: &str,
    ) -> io::Result<TransportConfig> {
        let mut transport = TransportConfig::default();
        transport.initial_mtu(self.initial_mtu);

        if let Some(initial_rtt) = self.initial_rtt {
            transport.initial_rtt(Duration::from_millis(initial_rtt));
        }

        if self.ack_frequency {
            transport.ack_frequency_config(Some(AckFrequencyConfig::default()));
        }

        if let Some(cong_alg) = self.cong_alg {
            transport.congestion_controller_factory(cong_alg.build());
        }

        if let Some(stream_receive_window) = self.stream_receive_window {
            transport.stream_receive_window(
                VarInt::from_u64(stream_receive_window).unwrap_or(VarInt::MAX),
            );
        }

        if let Some(receive_window) = self.receive_window {
            transport.receive_window(VarInt::from_u64(receive_window).unwrap_or(VarInt::MAX));
        }

        if let Some(send_window) = self.send_window {
            transport.send_window(send_window);
        }

        #[cfg(feature = "qlog")]
        if let Some(qlog_file) = &self.qlog_file {
            let mut qlog = QlogConfig::default();
            let file = File::create(qlog_file)?;
            let writer = BufWriter::new(file);
            qlog.writer(Box::new(writer)).title(Some(name.into()));
            transport.qlog_stream(qlog.into_stream());
        }

        Ok(transport)
    }

    pub fn bind_socket(&self, addr: SocketAddr) -> Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
            .context("create socket")?;

        if addr.is_ipv6() {
            socket.set_only_v6(false).context("set_only_v6")?;
        }

        socket
            .bind(&socket2::SockAddr::from(addr))
            .context("binding endpoint")?;

        let socket_state = UdpSocketState::new((&socket).into())?;
        socket_state
            .set_send_buffer_size((&socket).into(), self.send_buffer_size as usize)
            .context("send buffer size")?;
        socket_state
            .set_recv_buffer_size((&socket).into(), self.recv_buffer_size as usize)
            .context("recv buffer size")?;

        let buf_size = socket_state
            .send_buffer_size((&socket).into())
            .context("send buffer size")?;
        if buf_size < self.send_buffer_size as usize {
            warn!(
                "Unable to set desired send buffer size. Desired: {}, Actual: {}",
                self.send_buffer_size, buf_size
            );
        }

        let buf_size = socket_state
            .recv_buffer_size((&socket).into())
            .context("recv buffer size")?;
        if buf_size < self.recv_buffer_size as usize {
            warn!(
                "Unable to set desired recv buffer size. Desired: {}, Actual: {}",
                self.recv_buffer_size, buf_size
            );
        }

        Ok(socket.into())
    }
}

pub fn parse_byte_size(s: &str) -> Result<u64, ParseIntError> {
    let s = s.trim();

    let multiplier = match s.chars().last() {
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('M') => 1024 * 1024,
        Some('k') => 1024,
        _ => 1,
    };

    let s = match multiplier {
        1 => s,
        _ => &s[..s.len() - 1],
    };

    Ok(u64::from_str(s)? * multiplier)
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CongestionAlgorithm {
    Cubic,
    Bbr,
    NewReno,
}

impl CongestionAlgorithm {
    pub fn build(self) -> Arc<dyn ControllerFactory + Send + Sync + 'static> {
        match self {
            CongestionAlgorithm::Cubic => Arc::new(congestion::CubicConfig::default()),
            CongestionAlgorithm::Bbr => Arc::new(congestion::BbrConfig::default()),
            CongestionAlgorithm::NewReno => Arc::new(congestion::NewRenoConfig::default()),
        }
    }
}

pub static PERF_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];
