# Unit Tests

Unit tests verify individual components in isolation.

## Organization

Unit tests are embedded in source files:

```rust
// src/peer_id.rs
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        // ...
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex_valid() {
        let hex = "a".repeat(64);
        assert!(PeerId::from_hex(&hex).is_ok());
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let hex = "abc";
        assert!(PeerId::from_hex(hex).is_err());
    }
}
```

## Running Unit Tests

```bash
# All unit tests
cargo test --lib

# Specific module
cargo test peer_id

# Specific test
cargo test test_from_hex_valid

# With output
cargo test --lib -- --nocapture
```

## Key Test Modules

### PeerId Tests

```rust
#[cfg(test)]
mod peer_id_tests {
    use super::*;

    #[test]
    fn roundtrip_hex() {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id(&public_key);

        let hex = peer_id.to_hex();
        let recovered = PeerId::from_hex(&hex).unwrap();

        assert_eq!(peer_id, recovered);
    }
}
```

### Configuration Tests

```rust
#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let config = P2pConfig::builder().build().unwrap();

        assert!(config.known_peers.is_empty());
        assert_eq!(config.max_connections, 100);
    }

    #[test]
    fn builder_with_known_peer() {
        let addr = "192.168.1.1:9000".parse().unwrap();
        let config = P2pConfig::builder()
            .known_peer(addr)
            .build()
            .unwrap();

        assert_eq!(config.known_peers.len(), 1);
    }
}
```

### Frame Tests

```rust
#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn encode_decode_add_address() {
        let frame = AddAddressFrame {
            sequence: 1,
            addr: "192.168.1.1:9000".parse().unwrap(),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf);

        let decoded = AddAddressFrame::decode(&buf).unwrap();
        assert_eq!(frame.sequence, decoded.sequence);
    }
}
```

### Candidate Tests

```rust
#[cfg(test)]
mod candidate_tests {
    use super::*;

    #[test]
    fn priority_calculation() {
        let local = CandidateAddress {
            addr: "192.168.1.1:9000".parse().unwrap(),
            source: CandidateSource::Local,
            priority: 0,
        };

        let observed = CandidateAddress {
            addr: "203.0.113.1:9000".parse().unwrap(),
            source: CandidateSource::Observed,
            priority: 0,
        };

        // Observed addresses should have higher priority
        assert!(observed.calculate_priority() > local.calculate_priority());
    }
}
```

## Async Unit Tests

```rust
#[cfg(test)]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_creation() {
        let config = P2pConfig::builder().build().unwrap();
        let endpoint = P2pEndpoint::new(config).await;

        assert!(endpoint.is_ok());
    }

    #[tokio::test]
    async fn event_subscription() {
        let config = P2pConfig::builder().build().unwrap();
        let endpoint = P2pEndpoint::new(config).await.unwrap();

        let events = endpoint.subscribe();
        // Verify subscription works
        drop(events);
    }
}
```

## Test Utilities

### Test Helpers

```rust
#[cfg(test)]
mod test_helpers {
    pub fn test_config() -> P2pConfig {
        P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap()
    }

    pub fn random_peer_id() -> PeerId {
        let (_, pk) = generate_ed25519_keypair();
        derive_peer_id(&pk)
    }
}
```

### Mock Implementations

```rust
#[cfg(test)]
struct MockConnection {
    closed: bool,
}

#[cfg(test)]
impl MockConnection {
    fn new() -> Self {
        Self { closed: false }
    }

    fn close(&mut self) {
        self.closed = true;
    }
}
```

## Best Practices

1. **Test one thing per test**
2. **Use descriptive test names**
3. **Test edge cases and error paths**
4. **Keep tests fast (< 100ms each)**
5. **Avoid network I/O in unit tests**

## See Also

- [Testing Overview](./testing.md)
- [Integration Tests](./testing-integration.md)
- [Property Tests](./testing-property.md)

