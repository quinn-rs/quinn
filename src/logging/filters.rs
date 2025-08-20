// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// Log filtering capabilities
///
/// Provides flexible filtering of log messages by component, level, and other criteria
use std::collections::HashMap;
use tracing::Level;

/// Log filter configuration
#[derive(Debug, Clone)]
pub struct LogFilter {
    /// Component-specific log levels
    component_levels: HashMap<String, Level>,
    /// Default log level
    default_level: Level,
    /// Regex patterns to exclude
    exclude_patterns: Vec<regex::Regex>,
    /// Regex patterns to include (overrides excludes)
    include_patterns: Vec<regex::Regex>,
}

impl LogFilter {
    /// Create a new log filter with default settings
    pub fn new() -> Self {
        Self {
            component_levels: HashMap::new(),
            default_level: Level::INFO,
            exclude_patterns: Vec::new(),
            include_patterns: Vec::new(),
        }
    }

    /// Set the default log level
    pub fn with_default_level(mut self, level: Level) -> Self {
        self.default_level = level;
        self
    }

    /// Set log level for a specific module/component
    pub fn with_module(mut self, module: &str, level: Level) -> Self {
        self.component_levels.insert(module.to_string(), level);
        self
    }

    /// Add an exclude pattern
    pub fn exclude_pattern(mut self, pattern: &str) -> Result<Self, regex::Error> {
        let regex = regex::Regex::new(pattern)?;
        self.exclude_patterns.push(regex);
        Ok(self)
    }

    /// Add an include pattern (overrides excludes)
    pub fn include_pattern(mut self, pattern: &str) -> Result<Self, regex::Error> {
        let regex = regex::Regex::new(pattern)?;
        self.include_patterns.push(regex);
        Ok(self)
    }

    /// Check if a log message should be included
    pub fn should_log(&self, target: &str, level: Level, message: &str) -> bool {
        // Check include patterns first (they override excludes)
        for pattern in &self.include_patterns {
            if pattern.is_match(message) || pattern.is_match(target) {
                return true;
            }
        }

        // Check exclude patterns
        for pattern in &self.exclude_patterns {
            if pattern.is_match(message) || pattern.is_match(target) {
                return false;
            }
        }

        // Check level
        // In tracing, levels are ordered: ERROR > WARN > INFO > DEBUG > TRACE
        // So to check if a message should be logged, we need level <= required_level
        let required_level = self.level_for(target).unwrap_or(self.default_level);
        level <= required_level
    }

    /// Get the log level for a specific target
    pub fn level_for(&self, target: &str) -> Option<Level> {
        // Check exact match first
        if let Some(&level) = self.component_levels.get(target) {
            return Some(level);
        }

        // Check prefix matches (e.g., "ant_quic::connection" matches "ant_quic::connection::mod")
        for (module, &level) in &self.component_levels {
            if target.starts_with(module) {
                return Some(level);
            }
        }

        None
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating log filters
pub struct LogFilterBuilder {
    filter: LogFilter,
}

impl Default for LogFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LogFilterBuilder {
    /// Create a new filter builder
    pub fn new() -> Self {
        Self {
            filter: LogFilter::new(),
        }
    }

    /// Set default level
    pub fn default_level(mut self, level: Level) -> Self {
        self.filter.default_level = level;
        self
    }

    /// Configure common QUIC components
    pub fn quic_defaults(mut self) -> Self {
        self.filter
            .component_levels
            .insert("ant_quic::connection".to_string(), Level::DEBUG);
        self.filter
            .component_levels
            .insert("ant_quic::endpoint".to_string(), Level::INFO);
        self.filter
            .component_levels
            .insert("ant_quic::frame".to_string(), Level::TRACE);
        self.filter
            .component_levels
            .insert("ant_quic::packet".to_string(), Level::TRACE);
        self.filter
            .component_levels
            .insert("ant_quic::crypto".to_string(), Level::DEBUG);
        self.filter
            .component_levels
            .insert("ant_quic::transport_params".to_string(), Level::DEBUG);
        self
    }

    /// Configure for debugging NAT traversal
    pub fn nat_traversal_debug(mut self) -> Self {
        self.filter
            .component_levels
            .insert("ant_quic::nat_traversal".to_string(), Level::TRACE);
        self.filter
            .component_levels
            .insert("ant_quic::candidate_discovery".to_string(), Level::DEBUG);
        self.filter.component_levels.insert(
            "ant_quic::connection::nat_traversal".to_string(),
            Level::TRACE,
        );
        self
    }

    /// Configure for performance analysis
    pub fn performance_analysis(mut self) -> Self {
        self.filter
            .component_levels
            .insert("ant_quic::metrics".to_string(), Level::INFO);
        self.filter
            .component_levels
            .insert("ant_quic::congestion".to_string(), Level::DEBUG);
        self.filter
            .component_levels
            .insert("ant_quic::pacing".to_string(), Level::DEBUG);
        self
    }

    /// Configure for production use
    pub fn production(mut self) -> Self {
        self.filter.default_level = Level::WARN;
        self.filter
            .component_levels
            .insert("ant_quic::connection::lifecycle".to_string(), Level::INFO);
        self.filter
            .component_levels
            .insert("ant_quic::endpoint".to_string(), Level::INFO);
        self.filter
            .component_levels
            .insert("ant_quic::metrics".to_string(), Level::INFO);
        self
    }

    /// Exclude noisy components
    pub fn quiet(mut self) -> Self {
        // Add patterns to exclude
        if let Ok(pattern) = regex::Regex::new(r"packet\.sent") {
            self.filter.exclude_patterns.push(pattern);
        }
        if let Ok(pattern) = regex::Regex::new(r"packet\.received") {
            self.filter.exclude_patterns.push(pattern);
        }
        if let Ok(pattern) = regex::Regex::new(r"frame\.sent") {
            self.filter.exclude_patterns.push(pattern);
        }
        if let Ok(pattern) = regex::Regex::new(r"frame\.received") {
            self.filter.exclude_patterns.push(pattern);
        }
        self
    }

    /// Build the filter
    pub fn build(self) -> LogFilter {
        self.filter
    }
}

/// Dynamic filter that can be updated at runtime
pub struct DynamicLogFilter {
    inner: std::sync::RwLock<LogFilter>,
}

impl DynamicLogFilter {
    /// Create a new dynamic filter
    pub fn new(filter: LogFilter) -> Self {
        Self {
            inner: std::sync::RwLock::new(filter),
        }
    }

    /// Update the filter
    pub fn update<F>(&self, updater: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut LogFilter) -> Result<(), Box<dyn std::error::Error>>,
    {
        let mut filter = self.inner.write().unwrap();
        updater(&mut filter)?;
        Ok(())
    }

    /// Check if should log
    pub fn should_log(&self, target: &str, level: Level, message: &str) -> bool {
        self.inner
            .read()
            .unwrap()
            .should_log(target, level, message)
    }

    /// Get level for target
    pub fn level_for(&self, target: &str) -> Option<Level> {
        self.inner.read().unwrap().level_for(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_filtering() {
        let filter = LogFilterBuilder::new()
            .default_level(Level::WARN)
            .quic_defaults()
            .build();

        // ant_quic::connection is set to DEBUG, so it accepts ERROR, WARN, INFO, DEBUG but not TRACE
        assert!(filter.should_log("ant_quic::connection::mod", Level::DEBUG, "test"));
        assert!(!filter.should_log("ant_quic::connection::mod", Level::TRACE, "test"));

        // ant_quic::endpoint is set to INFO, so it accepts ERROR, WARN, INFO but not DEBUG or TRACE
        assert!(filter.should_log("ant_quic::endpoint", Level::INFO, "test"));
        assert!(!filter.should_log("ant_quic::endpoint", Level::DEBUG, "test"));

        // other::module uses default WARN, so it accepts ERROR, WARN but not INFO, DEBUG, or TRACE
        assert!(filter.should_log("other::module", Level::WARN, "test"));
        assert!(!filter.should_log("other::module", Level::INFO, "test"));
    }

    #[test]
    fn test_pattern_filtering() {
        let filter = LogFilter::new()
            .exclude_pattern(r"noisy")
            .unwrap()
            .include_pattern(r"important.*noisy")
            .unwrap();

        assert!(!filter.should_log("test", Level::INFO, "this is noisy"));
        assert!(filter.should_log("test", Level::INFO, "this is important but noisy"));
        assert!(filter.should_log("test", Level::INFO, "this is normal"));
    }
}
