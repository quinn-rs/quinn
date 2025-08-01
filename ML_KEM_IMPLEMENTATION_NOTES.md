# ML-KEM Implementation Notes

## Problem

The aws-lc-rs library's `DecapsulationKey` type for ML-KEM doesn't expose methods for raw private key serialization/deserialization. The API only provides:

- `DecapsulationKey::generate()` - Generate new keypair
- `DecapsulationKey::encapsulation_key()` - Get public key
- `EncapsulationKey::key_bytes()` - Serialize public key
- `EncapsulationKey::new()` - Deserialize public key from bytes

However, there's no corresponding `DecapsulationKey::private_key_bytes()` or `DecapsulationKey::from_private_key_bytes()`.

## Solution

The implementation uses an in-memory cache approach:

1. **Key Generation**: When generating a keypair, we store the entire `DecapsulationKey` object in a HashMap, using the public key bytes as the identifier.

2. **Key Storage**: The secret key bytes we return contain the public key bytes at the beginning, which serves as an identifier to retrieve the actual `DecapsulationKey` from the cache.

3. **Decapsulation**: When decapsulating, we extract the public key identifier from the secret key bytes and use it to retrieve the stored `DecapsulationKey` from the cache.

## Implementation Details

```rust
pub struct MlKem768Impl {
    algorithm: &'static Algorithm,
    // Maps public key bytes -> DecapsulationKey
    key_cache: Arc<Mutex<HashMap<Vec<u8>, Arc<DecapsulationKey>>>>,
}
```

The cache is thread-safe using `Arc<Mutex<>>` and shares `DecapsulationKey` instances using `Arc`.

## Limitations

1. **Memory Usage**: Keys remain in memory for the lifetime of the `MlKem768Impl` instance.
2. **Persistence**: Keys are not persisted across application restarts.
3. **Security**: Private keys are stored in application memory (though this is common for in-memory crypto operations).

## Production Considerations

For production use, consider:

1. **PKCS#8 Encoding**: Check if aws-lc-rs supports PKCS#8 encoding for ML-KEM keys in future versions.
2. **Key Management Service**: Use a proper KMS for key storage and retrieval.
3. **Custom Serialization**: Implement a secure serialization format that includes both public and private key material.
4. **Cache Eviction**: Implement TTL or LRU eviction for the key cache to manage memory usage.

## Alternative Approaches

1. **External Storage**: Store the serialized `DecapsulationKey` in a secure external storage system.
2. **Different Library**: Use a PQC library that supports full key serialization (e.g., liboqs).
3. **Hybrid Approach**: Use aws-lc-rs for operations but store keys using a different serialization library.

## Testing

The implementation includes comprehensive tests:
- Key generation with correct sizes
- Encapsulation/decapsulation roundtrip
- Multiple keypairs can coexist in the cache

See `src/crypto/pqc/ml_kem_impl.rs` for the full implementation.