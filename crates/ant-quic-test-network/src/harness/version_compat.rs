//! Version Compatibility Handshake (ctl↔agent)
//!
//! This module provides version negotiation between the test controller (ctl)
//! and test agents. It ensures:
//! - Compatible protocol versions are used
//! - Schema versions match for data exchange
//! - Graceful degradation when versions differ
//! - Clear error messages for incompatible versions
//!
//! The handshake occurs at connection establishment and validates
//! that both sides can communicate effectively.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;
use uuid::Uuid;

/// Semantic version (major.minor.patch)
///
/// Version is immutable after construction. Use the getter methods
/// `major()`, `minor()`, and `patch()` to access components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Major version - incompatible API changes
    major: u32,
    /// Minor version - backwards-compatible functionality
    minor: u32,
    /// Patch version - backwards-compatible bug fixes
    patch: u32,
}

impl Version {
    /// Create a new version
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Get the major version component
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// Get the minor version component
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// Get the patch version component
    pub const fn patch(&self) -> u32 {
        self.patch
    }

    /// Check if this version is compatible with another (same major, >= minor)
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }

    /// Check if this version is an exact match
    pub fn is_exact_match(&self, other: &Self) -> bool {
        self == other
    }

    /// Check if this is a pre-release version (0.x.x)
    pub fn is_prerelease(&self) -> bool {
        self.major == 0
    }

    /// Get the next major version
    pub fn next_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    /// Get the next minor version
    pub fn next_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    /// Get the next patch version
    pub fn next_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::new(0, 1, 0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = VersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(VersionParseError::InvalidFormat(s.to_string()));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber(parts[0].to_string()))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber(parts[1].to_string()))?;
        let patch = parts[2]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber(parts[2].to_string()))?;

        Ok(Self::new(major, minor, patch))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Error parsing a version string
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// Invalid format (expected x.y.z)
    InvalidFormat(String),
    /// Invalid number in version
    InvalidNumber(String),
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "invalid version format: {s} (expected x.y.z)"),
            Self::InvalidNumber(s) => write!(f, "invalid version number: {s}"),
        }
    }
}

impl std::error::Error for VersionParseError {}

/// Component being versioned
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionedComponent {
    /// Wire protocol version
    Protocol,
    /// Schema version for data structures
    Schema,
    /// API version
    Api,
    /// Harness infrastructure version
    Harness,
    /// Agent software version
    Agent,
}

impl fmt::Display for VersionedComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => write!(f, "protocol"),
            Self::Schema => write!(f, "schema"),
            Self::Api => write!(f, "api"),
            Self::Harness => write!(f, "harness"),
            Self::Agent => write!(f, "agent"),
        }
    }
}

/// How strict version checking should be
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityPolicy {
    /// Require exact version match
    Strict,
    /// Allow compatible versions (same major, higher minor OK)
    #[default]
    Compatible,
    /// Allow any version (warn only)
    Lenient,
}

impl CompatibilityPolicy {
    /// Check if versions are acceptable under this policy
    pub fn check(&self, local: &Version, remote: &Version) -> CompatibilityResult {
        match self {
            Self::Strict => {
                if local.is_exact_match(remote) {
                    CompatibilityResult::Compatible
                } else {
                    CompatibilityResult::Incompatible {
                        reason: format!(
                            "strict policy requires exact match: local={local}, remote={remote}"
                        ),
                    }
                }
            }
            Self::Compatible => {
                if local.is_compatible_with(remote) || remote.is_compatible_with(local) {
                    CompatibilityResult::Compatible
                } else {
                    CompatibilityResult::Incompatible {
                        reason: format!(
                            "versions incompatible: local={local}, remote={remote} (major version mismatch)"
                        ),
                    }
                }
            }
            Self::Lenient => {
                if local.is_compatible_with(remote) || remote.is_compatible_with(local) {
                    CompatibilityResult::Compatible
                } else {
                    CompatibilityResult::CompatibleWithWarning {
                        warning: format!(
                            "version mismatch (lenient mode): local={local}, remote={remote}"
                        ),
                    }
                }
            }
        }
    }
}

/// Result of compatibility check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityResult {
    /// Versions are compatible
    Compatible,
    /// Versions are compatible but with a warning
    CompatibleWithWarning { warning: String },
    /// Versions are incompatible
    Incompatible { reason: String },
}

impl CompatibilityResult {
    /// Check if result allows proceeding
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Compatible | Self::CompatibleWithWarning { .. })
    }

    /// Check if result is a hard failure
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Incompatible { .. })
    }

    /// Get warning message if any
    pub fn warning(&self) -> Option<&str> {
        match self {
            Self::CompatibleWithWarning { warning } => Some(warning),
            _ => None,
        }
    }

    /// Get error message if any
    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Incompatible { reason } => Some(reason),
            _ => None,
        }
    }
}

/// Version information for a component
///
/// ComponentVersion is immutable after construction via builder methods.
/// Use getter methods to access fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentVersion {
    /// The component
    component: VersionedComponent,
    /// Current version
    version: Version,
    /// Minimum supported version
    min_supported: Version,
    /// Features enabled at this version
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    features: Vec<String>,
}

impl ComponentVersion {
    /// Create a new component version
    pub fn new(component: VersionedComponent, version: Version) -> Self {
        Self {
            component,
            version,
            min_supported: version,
            features: Vec::new(),
        }
    }

    /// Get the component type
    pub fn component(&self) -> VersionedComponent {
        self.component
    }

    /// Get the current version
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get the minimum supported version
    pub fn min_supported(&self) -> Version {
        self.min_supported
    }

    /// Get the enabled features
    pub fn features(&self) -> &[String] {
        &self.features
    }

    /// Set minimum supported version
    pub fn with_min_supported(mut self, min: Version) -> Self {
        self.min_supported = min;
        self
    }

    /// Add a feature
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    /// Check if a remote version is supported
    pub fn supports(&self, remote: &Version) -> bool {
        *remote >= self.min_supported && remote.major() == self.version.major()
    }
}

/// Handshake request from one party to another
///
/// Fields set at construction are immutable. Use getter methods to access them.
/// Use builder methods (`with_*`) to configure optional values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionHandshakeRequest {
    /// Request ID (use `request_id()` to access)
    request_id: Uuid,
    /// Sender identity (use `sender_id()` to access)
    sender_id: String,
    /// Sender role (use `sender_role()` to access)
    sender_role: String,
    /// Component versions offered (use `versions()` to access)
    versions: HashMap<VersionedComponent, ComponentVersion>,
    /// Compatibility policy requested (use `policy()` to access)
    policy: CompatibilityPolicy,
    /// Timestamp (use `timestamp()` to access)
    timestamp: SystemTime,
    /// Additional capabilities (use `capabilities()` to access)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
}

impl VersionHandshakeRequest {
    /// Create a new handshake request
    pub fn new(sender_id: impl Into<String>, sender_role: impl Into<String>) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            sender_id: sender_id.into(),
            sender_role: sender_role.into(),
            versions: HashMap::new(),
            policy: CompatibilityPolicy::default(),
            timestamp: SystemTime::now(),
            capabilities: Vec::new(),
        }
    }

    /// Get the request ID
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Get the sender ID
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }

    /// Get the sender role
    pub fn sender_role(&self) -> &str {
        &self.sender_role
    }

    /// Get the versions map
    pub fn versions(&self) -> &HashMap<VersionedComponent, ComponentVersion> {
        &self.versions
    }

    /// Get the compatibility policy
    pub fn policy(&self) -> CompatibilityPolicy {
        self.policy
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Get the capabilities
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Add a component version
    pub fn with_version(mut self, cv: ComponentVersion) -> Self {
        self.versions.insert(cv.component(), cv);
        self
    }

    /// Set compatibility policy
    pub fn with_policy(mut self, policy: CompatibilityPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add a capability
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Set a fixed request ID (for testing/reproducibility)
    pub fn with_fixed_id(mut self, id: Uuid) -> Self {
        self.request_id = id;
        self
    }

    /// Set a fixed timestamp (for testing/reproducibility)
    pub fn with_fixed_timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Get version for a component
    pub fn get_version(&self, component: VersionedComponent) -> Option<Version> {
        self.versions.get(&component).map(|cv| cv.version())
    }
}

/// Handshake response
///
/// Use `is_accepted()` and `rejection_reason()` to check the outcome.
/// The `accepted` and `error` fields are kept private to ensure consistency -
/// an accepted response never has an error, and a rejected response always has one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionHandshakeResponse {
    /// Response to request ID
    pub request_id: Uuid,
    /// Response ID
    pub response_id: Uuid,
    /// Responder identity
    pub responder_id: String,
    /// Whether handshake succeeded (use `is_accepted()` to access)
    accepted: bool,
    /// Negotiated versions (if accepted)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub negotiated_versions: HashMap<VersionedComponent, Version>,
    /// Compatibility results per component
    pub compatibility_results: HashMap<VersionedComponent, CompatibilityResult>,
    /// Error message if rejected (use `rejection_reason()` to access)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Warnings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Timestamp
    pub timestamp: SystemTime,
}

impl VersionHandshakeResponse {
    /// Create an accepted response
    pub fn accept(request_id: Uuid, responder_id: impl Into<String>) -> Self {
        Self {
            request_id,
            response_id: Uuid::new_v4(),
            responder_id: responder_id.into(),
            accepted: true,
            negotiated_versions: HashMap::new(),
            compatibility_results: HashMap::new(),
            error: None,
            warnings: Vec::new(),
            timestamp: SystemTime::now(),
        }
    }

    /// Create a rejected response
    pub fn reject(
        request_id: Uuid,
        responder_id: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            response_id: Uuid::new_v4(),
            responder_id: responder_id.into(),
            accepted: false,
            negotiated_versions: HashMap::new(),
            compatibility_results: HashMap::new(),
            error: Some(error.into()),
            warnings: Vec::new(),
            timestamp: SystemTime::now(),
        }
    }

    /// Add a negotiated version
    pub fn with_negotiated_version(
        mut self,
        component: VersionedComponent,
        version: Version,
    ) -> Self {
        self.negotiated_versions.insert(component, version);
        self
    }

    /// Add a compatibility result
    pub fn with_result(
        mut self,
        component: VersionedComponent,
        result: CompatibilityResult,
    ) -> Self {
        // Collect warnings
        if let Some(warning) = result.warning() {
            self.warnings.push(warning.to_string());
        }
        self.compatibility_results.insert(component, result);
        self
    }

    /// Add a warning
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Check if the handshake was accepted
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Get the rejection reason if the handshake was rejected
    pub fn rejection_reason(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Mark the response as rejected with an error (internal use)
    pub(crate) fn mark_rejected(&mut self, error: impl Into<String>) {
        self.accepted = false;
        self.error = Some(error.into());
    }

    /// Set a fixed response ID (for deterministic testing)
    pub fn with_fixed_id(mut self, id: Uuid) -> Self {
        self.response_id = id;
        self
    }

    /// Set a fixed timestamp (for deterministic testing)
    pub fn with_fixed_timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Version negotiator for handshake
#[derive(Debug, Clone)]
pub struct VersionNegotiator {
    /// Local component versions
    local_versions: HashMap<VersionedComponent, ComponentVersion>,
    /// Default policy
    default_policy: CompatibilityPolicy,
    /// Required components
    required_components: Vec<VersionedComponent>,
}

impl VersionNegotiator {
    /// Create a new negotiator
    pub fn new() -> Self {
        Self {
            local_versions: HashMap::new(),
            default_policy: CompatibilityPolicy::default(),
            required_components: Vec::new(),
        }
    }

    /// Add a local version
    pub fn with_version(mut self, cv: ComponentVersion) -> Self {
        self.local_versions.insert(cv.component(), cv);
        self
    }

    /// Set default policy
    pub fn with_default_policy(mut self, policy: CompatibilityPolicy) -> Self {
        self.default_policy = policy;
        self
    }

    /// Mark a component as required
    pub fn require(mut self, component: VersionedComponent) -> Self {
        if !self.required_components.contains(&component) {
            self.required_components.push(component);
        }
        self
    }

    /// Create a handshake request
    pub fn create_request(
        &self,
        sender_id: impl Into<String>,
        sender_role: impl Into<String>,
    ) -> VersionHandshakeRequest {
        let mut request =
            VersionHandshakeRequest::new(sender_id, sender_role).with_policy(self.default_policy);

        for cv in self.local_versions.values() {
            request = request.with_version(cv.clone());
        }

        request
    }

    /// Process an incoming request and generate response
    pub fn process_request(
        &self,
        request: &VersionHandshakeRequest,
        responder_id: impl Into<String>,
    ) -> VersionHandshakeResponse {
        let responder_id = responder_id.into();
        let policy = request.policy();
        let mut response = VersionHandshakeResponse::accept(request.request_id(), &responder_id);
        let mut all_compatible = true;

        // Check required components
        for required in &self.required_components {
            if !request.versions().contains_key(required) {
                return VersionHandshakeResponse::reject(
                    request.request_id(),
                    responder_id,
                    format!("missing required component: {required}"),
                );
            }
        }

        // Check each component version
        for (component, remote_cv) in request.versions() {
            let result = if let Some(local_cv) = self.local_versions.get(component) {
                policy.check(&local_cv.version(), &remote_cv.version())
            } else {
                // Component not known locally - policy determines behavior
                match policy {
                    CompatibilityPolicy::Strict => {
                        // Strict mode rejects unknown components
                        CompatibilityResult::Incompatible {
                            reason: format!(
                                "unknown component not allowed in strict mode: {component}"
                            ),
                        }
                    }
                    CompatibilityPolicy::Compatible | CompatibilityPolicy::Lenient => {
                        // Non-strict modes warn but allow
                        CompatibilityResult::CompatibleWithWarning {
                            warning: format!("unknown component: {component}"),
                        }
                    }
                }
            };

            if result.is_error() {
                all_compatible = false;
            }

            // Negotiate to the lower version
            if let Some(local_cv) = self.local_versions.get(component) {
                let negotiated = std::cmp::min(local_cv.version(), remote_cv.version());
                response = response.with_negotiated_version(*component, negotiated);
            }

            response = response.with_result(*component, result);
        }

        if !all_compatible {
            response.mark_rejected("version incompatibility detected");
        }

        response
    }

    /// Get local version for a component
    pub fn get_version(&self, component: VersionedComponent) -> Option<Version> {
        self.local_versions.get(&component).map(|cv| cv.version())
    }
}

impl Default for VersionNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

/// Current harness version constants
pub mod current {
    use super::*;

    /// Current protocol version
    pub const PROTOCOL_VERSION: Version = Version::new(1, 0, 0);
    /// Current schema version
    pub const SCHEMA_VERSION: Version = Version::new(1, 0, 0);
    /// Current API version
    pub const API_VERSION: Version = Version::new(1, 0, 0);
    /// Current harness version
    pub const HARNESS_VERSION: Version = Version::new(0, 14, 0);

    /// Create a fully-configured negotiator with current versions
    pub fn negotiator() -> VersionNegotiator {
        VersionNegotiator::new()
            .with_version(
                ComponentVersion::new(VersionedComponent::Protocol, PROTOCOL_VERSION)
                    .with_min_supported(Version::new(1, 0, 0)),
            )
            .with_version(
                ComponentVersion::new(VersionedComponent::Schema, SCHEMA_VERSION)
                    .with_min_supported(Version::new(1, 0, 0)),
            )
            .with_version(
                ComponentVersion::new(VersionedComponent::Api, API_VERSION)
                    .with_min_supported(Version::new(1, 0, 0)),
            )
            .with_version(
                ComponentVersion::new(VersionedComponent::Harness, HARNESS_VERSION)
                    .with_min_supported(Version::new(0, 14, 0)),
            )
            .require(VersionedComponent::Protocol)
            .require(VersionedComponent::Schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Version Tests ====================

    #[test]
    fn test_version_new() {
        let v = Version::new(1, 2, 3);
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
    }

    #[test]
    fn test_version_default() {
        let v = Version::default();
        assert_eq!(v, Version::new(0, 1, 0));
    }

    #[test]
    fn test_version_display() {
        let v = Version::new(1, 2, 3);
        assert_eq!(format!("{v}"), "1.2.3");
    }

    #[test]
    fn test_version_from_str() {
        let v: Version = "1.2.3".parse().unwrap();
        assert_eq!(v, Version::new(1, 2, 3));
    }

    #[test]
    fn test_version_from_str_invalid() {
        assert!("1.2".parse::<Version>().is_err());
        assert!("1.2.3.4".parse::<Version>().is_err());
        assert!("a.b.c".parse::<Version>().is_err());
    }

    #[test]
    fn test_version_ordering() {
        assert!(Version::new(1, 0, 0) < Version::new(2, 0, 0));
        assert!(Version::new(1, 0, 0) < Version::new(1, 1, 0));
        assert!(Version::new(1, 0, 0) < Version::new(1, 0, 1));
        assert!(Version::new(1, 2, 3) == Version::new(1, 2, 3));
    }

    #[test]
    fn test_version_is_compatible_with() {
        let v1 = Version::new(1, 2, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v2)); // Same major, higher minor
        assert!(!v2.is_compatible_with(&v1)); // Same major, lower minor
        assert!(!v1.is_compatible_with(&v3)); // Different major
    }

    #[test]
    fn test_version_is_exact_match() {
        let v1 = Version::new(1, 2, 3);
        let v2 = Version::new(1, 2, 3);
        let v3 = Version::new(1, 2, 4);

        assert!(v1.is_exact_match(&v2));
        assert!(!v1.is_exact_match(&v3));
    }

    #[test]
    fn test_version_is_prerelease() {
        assert!(Version::new(0, 1, 0).is_prerelease());
        assert!(!Version::new(1, 0, 0).is_prerelease());
    }

    #[test]
    fn test_version_next_methods() {
        let v = Version::new(1, 2, 3);
        assert_eq!(v.next_major(), Version::new(2, 0, 0));
        assert_eq!(v.next_minor(), Version::new(1, 3, 0));
        assert_eq!(v.next_patch(), Version::new(1, 2, 4));
    }

    // ==================== CompatibilityPolicy Tests ====================

    #[test]
    fn test_policy_default() {
        assert_eq!(
            CompatibilityPolicy::default(),
            CompatibilityPolicy::Compatible
        );
    }

    #[test]
    fn test_policy_strict() {
        let policy = CompatibilityPolicy::Strict;
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 0);
        let v3 = Version::new(1, 0, 1);

        assert!(policy.check(&v1, &v2).is_ok());
        assert!(policy.check(&v1, &v3).is_error());
    }

    #[test]
    fn test_policy_compatible() {
        let policy = CompatibilityPolicy::Compatible;
        let v1 = Version::new(1, 2, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        assert!(policy.check(&v1, &v2).is_ok());
        assert!(policy.check(&v1, &v3).is_error());
    }

    #[test]
    fn test_policy_lenient() {
        let policy = CompatibilityPolicy::Lenient;
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(2, 0, 0);

        let result = policy.check(&v1, &v2);
        assert!(result.is_ok());
        assert!(result.warning().is_some());
    }

    // ==================== CompatibilityResult Tests ====================

    #[test]
    fn test_compatibility_result_is_ok() {
        assert!(CompatibilityResult::Compatible.is_ok());
        assert!(
            CompatibilityResult::CompatibleWithWarning {
                warning: "test".to_string()
            }
            .is_ok()
        );
        assert!(
            !CompatibilityResult::Incompatible {
                reason: "test".to_string()
            }
            .is_ok()
        );
    }

    #[test]
    fn test_compatibility_result_is_error() {
        assert!(!CompatibilityResult::Compatible.is_error());
        assert!(
            CompatibilityResult::Incompatible {
                reason: "test".to_string()
            }
            .is_error()
        );
    }

    #[test]
    fn test_compatibility_result_warning() {
        let result = CompatibilityResult::CompatibleWithWarning {
            warning: "some warning".to_string(),
        };
        assert_eq!(result.warning(), Some("some warning"));

        assert!(CompatibilityResult::Compatible.warning().is_none());
    }

    #[test]
    fn test_compatibility_result_error() {
        let result = CompatibilityResult::Incompatible {
            reason: "some error".to_string(),
        };
        assert_eq!(result.error(), Some("some error"));

        assert!(CompatibilityResult::Compatible.error().is_none());
    }

    // ==================== ComponentVersion Tests ====================

    #[test]
    fn test_component_version_new() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));

        assert_eq!(cv.component(), VersionedComponent::Protocol);
        assert_eq!(cv.version(), Version::new(1, 0, 0));
        assert_eq!(cv.min_supported(), Version::new(1, 0, 0));
    }

    #[test]
    fn test_component_version_with_min_supported() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 2, 0))
            .with_min_supported(Version::new(1, 0, 0));

        assert_eq!(cv.min_supported(), Version::new(1, 0, 0));
    }

    #[test]
    fn test_component_version_with_feature() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0))
            .with_feature("compression")
            .with_feature("encryption");

        assert_eq!(cv.features().len(), 2);
        assert!(cv.features().contains(&"compression".to_string()));
    }

    #[test]
    fn test_component_version_supports() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 2, 0))
            .with_min_supported(Version::new(1, 0, 0));

        assert!(cv.supports(&Version::new(1, 0, 0)));
        assert!(cv.supports(&Version::new(1, 1, 0)));
        assert!(cv.supports(&Version::new(1, 2, 0)));
        assert!(!cv.supports(&Version::new(0, 9, 0))); // Below min
        assert!(!cv.supports(&Version::new(2, 0, 0))); // Different major
    }

    // ==================== VersionHandshakeRequest Tests ====================

    #[test]
    fn test_handshake_request_new() {
        let request = VersionHandshakeRequest::new("ctl-1", "controller");

        assert_eq!(request.sender_id(), "ctl-1");
        assert_eq!(request.sender_role(), "controller");
        assert!(request.versions().is_empty());
    }

    #[test]
    fn test_handshake_request_with_version() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(cv);

        assert!(
            request
                .versions()
                .contains_key(&VersionedComponent::Protocol)
        );
    }

    #[test]
    fn test_handshake_request_with_policy() {
        let request = VersionHandshakeRequest::new("ctl-1", "controller")
            .with_policy(CompatibilityPolicy::Strict);

        assert_eq!(request.policy(), CompatibilityPolicy::Strict);
    }

    #[test]
    fn test_handshake_request_with_capability() {
        let request =
            VersionHandshakeRequest::new("ctl-1", "controller").with_capability("compression");

        assert!(request.capabilities().contains(&"compression".to_string()));
    }

    #[test]
    fn test_handshake_request_get_version() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 2, 3));
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(cv);

        assert_eq!(
            request.get_version(VersionedComponent::Protocol),
            Some(Version::new(1, 2, 3))
        );
        assert!(request.get_version(VersionedComponent::Schema).is_none());
    }

    // ==================== VersionHandshakeResponse Tests ====================

    #[test]
    fn test_handshake_response_accept() {
        let request_id = Uuid::new_v4();
        let response = VersionHandshakeResponse::accept(request_id, "agent-1");

        assert!(response.is_accepted());
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.responder_id, "agent-1");
        assert!(response.error.is_none());
    }

    #[test]
    fn test_handshake_response_reject() {
        let request_id = Uuid::new_v4();
        let response =
            VersionHandshakeResponse::reject(request_id, "agent-1", "incompatible versions");

        assert!(!response.is_accepted());
        assert_eq!(response.error, Some("incompatible versions".to_string()));
    }

    #[test]
    fn test_handshake_response_with_negotiated_version() {
        let request_id = Uuid::new_v4();
        let response = VersionHandshakeResponse::accept(request_id, "agent-1")
            .with_negotiated_version(VersionedComponent::Protocol, Version::new(1, 0, 0));

        assert_eq!(
            response
                .negotiated_versions
                .get(&VersionedComponent::Protocol),
            Some(&Version::new(1, 0, 0))
        );
    }

    #[test]
    fn test_handshake_response_with_result() {
        let request_id = Uuid::new_v4();
        let response = VersionHandshakeResponse::accept(request_id, "agent-1").with_result(
            VersionedComponent::Protocol,
            CompatibilityResult::Compatible,
        );

        assert!(
            response
                .compatibility_results
                .contains_key(&VersionedComponent::Protocol)
        );
    }

    #[test]
    fn test_handshake_response_collects_warnings() {
        let request_id = Uuid::new_v4();
        let response = VersionHandshakeResponse::accept(request_id, "agent-1").with_result(
            VersionedComponent::Protocol,
            CompatibilityResult::CompatibleWithWarning {
                warning: "version mismatch".to_string(),
            },
        );

        assert!(response.warnings.contains(&"version mismatch".to_string()));
    }

    // ==================== VersionNegotiator Tests ====================

    #[test]
    fn test_negotiator_new() {
        let negotiator = VersionNegotiator::new();
        assert!(negotiator.local_versions.is_empty());
    }

    #[test]
    fn test_negotiator_with_version() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let negotiator = VersionNegotiator::new().with_version(cv);

        assert!(
            negotiator
                .local_versions
                .contains_key(&VersionedComponent::Protocol)
        );
    }

    #[test]
    fn test_negotiator_create_request() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let negotiator = VersionNegotiator::new().with_version(cv);

        let request = negotiator.create_request("ctl-1", "controller");

        assert_eq!(request.sender_id(), "ctl-1");
        assert!(
            request
                .versions()
                .contains_key(&VersionedComponent::Protocol)
        );
    }

    #[test]
    fn test_negotiator_process_request_compatible() {
        let local_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let remote_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));

        let negotiator = VersionNegotiator::new().with_version(local_cv);
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(remote_cv);

        let response = negotiator.process_request(&request, "agent-1");

        assert!(response.is_accepted());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_negotiator_process_request_incompatible() {
        let local_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let remote_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(2, 0, 0));

        let negotiator = VersionNegotiator::new().with_version(local_cv);
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(remote_cv);

        let response = negotiator.process_request(&request, "agent-1");

        assert!(!response.is_accepted());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_negotiator_process_request_missing_required() {
        let local_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));

        let negotiator = VersionNegotiator::new()
            .with_version(local_cv)
            .require(VersionedComponent::Schema);

        // Request without schema version
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(
            ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0)),
        );

        let response = negotiator.process_request(&request, "agent-1");

        assert!(!response.is_accepted());
        assert!(
            response
                .error
                .as_ref()
                .unwrap()
                .contains("missing required")
        );
    }

    #[test]
    fn test_negotiator_negotiates_lower_version() {
        let local_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 2, 0));
        let remote_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 1, 0));

        let negotiator = VersionNegotiator::new().with_version(local_cv);
        let request = VersionHandshakeRequest::new("ctl-1", "controller").with_version(remote_cv);

        let response = negotiator.process_request(&request, "agent-1");

        assert!(response.is_accepted());
        assert_eq!(
            response
                .negotiated_versions
                .get(&VersionedComponent::Protocol),
            Some(&Version::new(1, 1, 0)) // Lower of the two
        );
    }

    // ==================== Current Module Tests ====================

    #[test]
    fn test_current_versions() {
        assert_eq!(current::PROTOCOL_VERSION, Version::new(1, 0, 0));
        assert_eq!(current::SCHEMA_VERSION, Version::new(1, 0, 0));
    }

    #[test]
    fn test_current_negotiator() {
        let negotiator = current::negotiator();

        assert!(
            negotiator
                .get_version(VersionedComponent::Protocol)
                .is_some()
        );
        assert!(negotiator.get_version(VersionedComponent::Schema).is_some());
        assert!(negotiator.get_version(VersionedComponent::Api).is_some());
        assert!(
            negotiator
                .get_version(VersionedComponent::Harness)
                .is_some()
        );
    }

    // ==================== Integration Tests ====================

    #[test]
    fn test_full_handshake_flow() {
        // Controller setup
        let ctl_negotiator = current::negotiator();
        let request = ctl_negotiator.create_request("ctl-main", "controller");

        // Agent setup
        let agent_negotiator = current::negotiator();
        let response = agent_negotiator.process_request(&request, "agent-1");

        // Verify handshake succeeded
        assert!(response.is_accepted());
        assert!(response.error.is_none());
        assert!(!response.negotiated_versions.is_empty());
    }

    #[test]
    fn test_full_handshake_version_mismatch() {
        // Controller with newer protocol
        let ctl_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(2, 0, 0));
        let ctl_negotiator = VersionNegotiator::new().with_version(ctl_cv);
        let request = ctl_negotiator.create_request("ctl-main", "controller");

        // Agent with older protocol
        let agent_cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let agent_negotiator = VersionNegotiator::new().with_version(agent_cv);
        let response = agent_negotiator.process_request(&request, "agent-1");

        // Verify handshake failed
        assert!(!response.is_accepted());
        assert!(response.error.is_some());
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_version_serialization() {
        let v = Version::new(1, 2, 3);
        let json = serde_json::to_string(&v).unwrap();
        let restored: Version = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn test_handshake_request_roundtrip() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let request = VersionHandshakeRequest::new("ctl-1", "controller")
            .with_version(cv)
            .with_capability("compression");

        let json = serde_json::to_string(&request).unwrap();
        let restored: VersionHandshakeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.sender_id(), request.sender_id());
        assert_eq!(restored.capabilities(), request.capabilities());
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let request_id = Uuid::new_v4();
        let response = VersionHandshakeResponse::accept(request_id, "agent-1")
            .with_negotiated_version(VersionedComponent::Protocol, Version::new(1, 0, 0))
            .with_result(
                VersionedComponent::Protocol,
                CompatibilityResult::Compatible,
            );

        let json = serde_json::to_string(&response).unwrap();
        let restored: VersionHandshakeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.is_accepted(), response.is_accepted());
        assert_eq!(restored.negotiated_versions, response.negotiated_versions);
    }
}
