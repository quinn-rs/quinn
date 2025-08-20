// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Chat protocol implementation for QUIC streams
//!
//! This module provides a structured chat protocol for P2P communication
//! over QUIC streams, including message types, serialization, and handling.

use crate::nat_traversal_api::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

/// Chat protocol version
pub const CHAT_PROTOCOL_VERSION: u16 = 1;

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Chat protocol errors
#[derive(Error, Debug)]
pub enum ChatError {
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),

    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(u16),

    #[error("Invalid message format")]
    InvalidFormat,
}

/// Chat message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatMessage {
    /// User joined the chat
    Join {
        nickname: String,
        peer_id: [u8; 32],
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
    },

    /// User left the chat
    Leave {
        nickname: String,
        peer_id: [u8; 32],
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
    },

    /// Text message from user
    Text {
        nickname: String,
        peer_id: [u8; 32],
        text: String,
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
    },

    /// Status update from user
    Status {
        nickname: String,
        peer_id: [u8; 32],
        status: String,
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
    },

    /// Direct message to specific peer
    Direct {
        from_nickname: String,
        from_peer_id: [u8; 32],
        to_peer_id: [u8; 32],
        text: String,
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
    },

    /// Typing indicator
    Typing {
        nickname: String,
        peer_id: [u8; 32],
        is_typing: bool,
    },

    /// Request peer list
    PeerListRequest { peer_id: [u8; 32] },

    /// Response with peer list
    PeerListResponse { peers: Vec<PeerInfo> },
}

/// Information about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub nickname: String,
    pub status: String,
    #[serde(with = "timestamp_serde")]
    pub joined_at: SystemTime,
}

/// Timestamp serialization module
mod timestamp_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(super) fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        // Serialize as a tuple of (seconds, nanoseconds) to preserve full precision
        let secs = duration.as_secs();
        let nanos = duration.subsec_nanos();
        (secs, nanos).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (secs, nanos): (u64, u32) = Deserialize::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + Duration::new(secs, nanos))
    }
}

/// Wire format for chat messages
#[derive(Debug, Serialize, Deserialize)]
struct ChatWireFormat {
    /// Protocol version
    version: u16,
    /// Message payload
    message: ChatMessage,
}

impl ChatMessage {
    /// Create a new join message
    pub fn join(nickname: String, peer_id: PeerId) -> Self {
        Self::Join {
            nickname,
            peer_id: peer_id.0,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new leave message
    pub fn leave(nickname: String, peer_id: PeerId) -> Self {
        Self::Leave {
            nickname,
            peer_id: peer_id.0,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new text message
    pub fn text(nickname: String, peer_id: PeerId, text: String) -> Self {
        Self::Text {
            nickname,
            peer_id: peer_id.0,
            text,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new status message
    pub fn status(nickname: String, peer_id: PeerId, status: String) -> Self {
        Self::Status {
            nickname,
            peer_id: peer_id.0,
            status,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new direct message
    pub fn direct(
        from_nickname: String,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        text: String,
    ) -> Self {
        Self::Direct {
            from_nickname,
            from_peer_id: from_peer_id.0,
            to_peer_id: to_peer_id.0,
            text,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a typing indicator
    pub fn typing(nickname: String, peer_id: PeerId, is_typing: bool) -> Self {
        Self::Typing {
            nickname,
            peer_id: peer_id.0,
            is_typing,
        }
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ChatError> {
        let wire_format = ChatWireFormat {
            version: CHAT_PROTOCOL_VERSION,
            message: self.clone(),
        };

        let data = serde_json::to_vec(&wire_format)
            .map_err(|e| ChatError::Serialization(e.to_string()))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ChatError::MessageTooLarge(data.len(), MAX_MESSAGE_SIZE));
        }

        Ok(data)
    }

    /// Deserialize message from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, ChatError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ChatError::MessageTooLarge(data.len(), MAX_MESSAGE_SIZE));
        }

        let wire_format: ChatWireFormat =
            serde_json::from_slice(data).map_err(|e| ChatError::Deserialization(e.to_string()))?;

        if wire_format.version != CHAT_PROTOCOL_VERSION {
            return Err(ChatError::InvalidProtocolVersion(wire_format.version));
        }

        Ok(wire_format.message)
    }

    /// Get the peer ID from the message
    pub fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Join { peer_id, .. }
            | Self::Leave { peer_id, .. }
            | Self::Text { peer_id, .. }
            | Self::Status { peer_id, .. }
            | Self::Typing { peer_id, .. }
            | Self::PeerListRequest { peer_id, .. } => Some(PeerId(*peer_id)),
            Self::Direct { from_peer_id, .. } => Some(PeerId(*from_peer_id)),
            Self::PeerListResponse { .. } => None,
        }
    }

    /// Get the nickname from the message
    pub fn nickname(&self) -> Option<&str> {
        match self {
            Self::Join { nickname, .. }
            | Self::Leave { nickname, .. }
            | Self::Text { nickname, .. }
            | Self::Status { nickname, .. }
            | Self::Typing { nickname, .. } => Some(nickname),
            Self::Direct { from_nickname, .. } => Some(from_nickname),
            Self::PeerListRequest { .. } | Self::PeerListResponse { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let peer_id = PeerId([1u8; 32]);
        let message = ChatMessage::text(
            "test-user".to_string(),
            peer_id,
            "Hello, world!".to_string(),
        );

        // Serialize
        let data = message.serialize().unwrap();
        assert!(data.len() < MAX_MESSAGE_SIZE);

        // Deserialize
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn test_all_message_types() {
        let peer_id = PeerId([2u8; 32]);
        let messages = vec![
            ChatMessage::join("alice".to_string(), peer_id),
            ChatMessage::leave("alice".to_string(), peer_id),
            ChatMessage::text("alice".to_string(), peer_id, "Hello".to_string()),
            ChatMessage::status("alice".to_string(), peer_id, "Away".to_string()),
            ChatMessage::direct(
                "alice".to_string(),
                peer_id,
                PeerId([3u8; 32]),
                "Private message".to_string(),
            ),
            ChatMessage::typing("alice".to_string(), peer_id, true),
            ChatMessage::PeerListRequest { peer_id: peer_id.0 },
            ChatMessage::PeerListResponse {
                peers: vec![PeerInfo {
                    peer_id: peer_id.0,
                    nickname: "alice".to_string(),
                    status: "Online".to_string(),
                    joined_at: SystemTime::now(),
                }],
            },
        ];

        for msg in messages {
            let data = msg.serialize().unwrap();
            let deserialized = ChatMessage::deserialize(&data).unwrap();
            match (&msg, &deserialized) {
                (
                    ChatMessage::Join {
                        nickname: n1,
                        peer_id: p1,
                        ..
                    },
                    ChatMessage::Join {
                        nickname: n2,
                        peer_id: p2,
                        ..
                    },
                ) => {
                    assert_eq!(n1, n2);
                    assert_eq!(p1, p2);
                }
                _ => assert_eq!(msg, deserialized),
            }
        }
    }

    #[test]
    fn test_message_too_large() {
        let peer_id = PeerId([4u8; 32]);
        let large_text = "a".repeat(MAX_MESSAGE_SIZE);
        let message = ChatMessage::text("user".to_string(), peer_id, large_text);

        match message.serialize() {
            Err(ChatError::MessageTooLarge(_, _)) => {}
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    #[test]
    fn test_invalid_version() {
        let peer_id = PeerId([5u8; 32]);
        let message = ChatMessage::text("user".to_string(), peer_id, "test".to_string());

        // Create wire format with wrong version
        let wire_format = ChatWireFormat {
            version: 999,
            message,
        };

        let data = serde_json::to_vec(&wire_format).unwrap();

        match ChatMessage::deserialize(&data) {
            Err(ChatError::InvalidProtocolVersion(999)) => {}
            _ => panic!("Expected InvalidProtocolVersion error"),
        }
    }
}
