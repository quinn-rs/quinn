//! Terminal UI formatting and display helpers for ant-quic
//!
//! Provides colored output, formatting, and visual elements for better UX

use std::net::{IpAddr, SocketAddr};
use unicode_width::UnicodeWidthStr;
use tracing::Level;
use tracing_subscriber::fmt::{format::Writer, FormatFields};
use four_word_networking::FourWordAdaptiveEncoder;

/// ANSI color codes for terminal output
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    
    // Regular colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    
    // Bright colors
    pub const BRIGHT_BLACK: &str = "\x1b[90m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";
}

/// Unicode symbols for visual indicators
pub mod symbols {
    pub const CHECK: &str = "✓";
    pub const CROSS: &str = "✗";
    pub const INFO: &str = "ℹ";
    pub const WARNING: &str = "⚠";
    pub const ARROW_RIGHT: &str = "→";
    pub const DOT: &str = "•";
    pub const KEY: &str = "🔑";
    pub const NETWORK: &str = "📡";
    pub const GLOBE: &str = "🌐";
    pub const ROCKET: &str = "🚀";
    pub const HOURGLASS: &str = "⏳";
    pub const CIRCULAR_ARROWS: &str = "⟳";
}

/// Box drawing characters for borders
pub mod box_chars {
    pub const TOP_LEFT: &str = "╭";
    pub const TOP_RIGHT: &str = "╮";
    pub const BOTTOM_LEFT: &str = "╰";
    pub const BOTTOM_RIGHT: &str = "╯";
    pub const HORIZONTAL: &str = "─";
    pub const VERTICAL: &str = "│";
    pub const T_LEFT: &str = "├";
    pub const T_RIGHT: &str = "┤";
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_ipv6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 0xfe) && ((octets[1] & 0xc0) == 0x80)
}

/// Check if an IPv6 address is unique local (fc00::/7)
fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    (octets[0] & 0xfe) == 0xfc
}

/// Check if an IPv6 address is multicast (ff00::/8)
fn is_ipv6_multicast(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xff
}

/// Format a peer ID with color (shows first 8 chars)
pub fn format_peer_id(peer_id: &[u8; 32]) -> String {
    let hex = hex::encode(&peer_id[..4]);
    format!("{}{}{}{}", colors::CYAN, hex, "...", colors::RESET)
}

/// Format an address with appropriate coloring
pub fn format_address(addr: &SocketAddr) -> String {
    let color = match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                colors::DIM
            } else if ip.is_private() {
                colors::YELLOW
            } else {
                colors::GREEN
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                colors::DIM
            } else if ip.is_unspecified() {
                colors::DIM
            } else if is_ipv6_link_local(&ip) {
                colors::YELLOW
            } else if is_ipv6_unique_local(&ip) {
                colors::CYAN
            } else {
                colors::BRIGHT_CYAN
            }
        }
    };
    
    format!("{}{}{}", color, addr, colors::RESET)
}

/// Format an address as four words with original address in brackets
pub fn format_address_with_words(addr: &SocketAddr) -> String {
    // Try to encode the address as four words
    match FourWordAdaptiveEncoder::new() {
        Ok(encoder) => {
            match encoder.encode(&addr.to_string()) {
                Ok(words) => {
                    let color = match addr.ip() {
                        IpAddr::V4(ip) => {
                            if ip.is_loopback() {
                                colors::DIM
                            } else if ip.is_private() {
                                colors::YELLOW
                            } else {
                                colors::GREEN
                            }
                        }
                        IpAddr::V6(ip) => {
                            if ip.is_loopback() {
                                colors::DIM
                            } else if ip.is_unspecified() {
                                colors::DIM
                            } else if is_ipv6_link_local(&ip) {
                                colors::YELLOW
                            } else if is_ipv6_unique_local(&ip) {
                                colors::CYAN
                            } else {
                                colors::BRIGHT_CYAN
                            }
                        }
                    };
                    
                    format!("{}{}{} {}{}{} {}", 
                        colors::BOLD, color, words, colors::RESET,
                        colors::DIM, format!("[{}]", addr), colors::RESET
                    )
                }
                Err(_) => {
                    // Fallback to regular address formatting if encoding fails
                    format_address(addr)
                }
            }
        }
        Err(_) => {
            // Fallback if encoder creation fails
            format_address(addr)
        }
    }
}

/// Categorize and describe an IP address
pub fn describe_address(addr: &SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                "loopback"
            } else if ip.is_private() {
                "private network"
            } else if ip.is_link_local() {
                "link-local"
            } else {
                "public"
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                "IPv6 loopback"
            } else if ip.is_unspecified() {
                "IPv6 unspecified"
            } else if is_ipv6_link_local(&ip) {
                "IPv6 link-local"
            } else if is_ipv6_unique_local(&ip) {
                "IPv6 unique local"
            } else if is_ipv6_multicast(&ip) {
                "IPv6 multicast"
            } else {
                "IPv6 global"
            }
        }
    }
}

/// Draw a box with title and content
pub fn draw_box(title: &str, width: usize) -> (String, String, String) {
    let padding = width.saturating_sub(title.width() + 4);
    let left_pad = padding / 2;
    let right_pad = padding - left_pad;
    
    let top = format!(
        "{}{} {} {}{}{}",
        box_chars::TOP_LEFT,
        box_chars::HORIZONTAL.repeat(left_pad),
        title,
        box_chars::HORIZONTAL.repeat(right_pad),
        box_chars::HORIZONTAL,
        box_chars::TOP_RIGHT
    );
    
    let middle = format!(
        "{} {{}} {}",
        box_chars::VERTICAL,
        box_chars::VERTICAL
    );
    
    let bottom = format!(
        "{}{}{}",
        box_chars::BOTTOM_LEFT,
        box_chars::HORIZONTAL.repeat(width - 2),
        box_chars::BOTTOM_RIGHT
    );
    
    (top, middle, bottom)
}

/// Print the startup banner
pub fn print_banner(version: &str) {
    let title = format!("ant-quic v{}", version);
    let (top, middle, bottom) = draw_box(&title, 60);
    
    println!("{}", top);
    println!("{}", middle.replace("{}", "Starting QUIC P2P with NAT Traversal                 "));
    println!("{}", bottom);
    println!();
}

/// Print a section header
pub fn print_section(icon: &str, title: &str) {
    println!("{} {}{}{}", icon, colors::BOLD, title, colors::RESET);
}

/// Print an item with bullet point
pub fn print_item(text: &str, indent: usize) {
    let indent_str = " ".repeat(indent);
    println!("{}{} {}", indent_str, symbols::DOT, text);
}

/// Print a status line with icon
pub fn print_status(icon: &str, text: &str, color: &str) {
    println!("  {} {}{}{}", icon, color, text, colors::RESET);
}

/// Format bytes into human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format duration into human-readable time
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Format timestamp into HH:MM:SS format
pub fn format_timestamp(_timestamp: std::time::Instant) -> String {
    use std::time::SystemTime;
    
    // This is a simplified timestamp - in a real app you'd want proper time handling
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::ZERO);
    
    let total_seconds = duration_since_epoch.as_secs();
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Custom log formatter that adds colors and symbols
pub struct ColoredLogFormatter;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for ColoredLogFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        let level = metadata.level();
        
        // Choose color and symbol based on level
        let (color, symbol) = match *level {
            Level::ERROR => (colors::RED, symbols::CROSS),
            Level::WARN => (colors::YELLOW, symbols::WARNING),
            Level::INFO => (colors::GREEN, symbols::CHECK),
            Level::DEBUG => (colors::BLUE, symbols::INFO),
            Level::TRACE => (colors::DIM, symbols::DOT),
        };
        
        // Write colored output
        write!(&mut writer, "{}{} ", color, symbol)?;
        
        // Write the message
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        
        write!(&mut writer, "{}", colors::RESET)?;
        
        writeln!(writer)
    }
}

/// Progress indicator for operations
pub struct ProgressIndicator {
    message: String,
    frames: Vec<&'static str>,
    current_frame: usize,
}

impl ProgressIndicator {
    pub fn new(message: String) -> Self {
        Self {
            message,
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current_frame: 0,
        }
    }
    
    pub fn tick(&mut self) {
        print!("\r{} {} {} ", 
            self.frames[self.current_frame], 
            colors::BLUE, 
            self.message
        );
        self.current_frame = (self.current_frame + 1) % self.frames.len();
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }
    
    pub fn finish_success(&self, message: &str) {
        println!("\r{} {}{}{} {}", 
            symbols::CHECK, 
            colors::GREEN,
            self.message,
            colors::RESET,
            message
        );
    }
    
    pub fn finish_error(&self, message: &str) {
        println!("\r{} {}{}{} {}", 
            symbols::CROSS, 
            colors::RED,
            self.message,
            colors::RESET,
            message
        );
    }
}