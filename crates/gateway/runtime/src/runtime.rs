//! Standalone runtime composition.
//!
//! This module groups the components that turn a local YAML document into the
//! live gateway state. Protocol implementations must consume the resulting
//! stores; they must not parse or watch configuration directly.

pub use crate::config;
pub use crate::resource_manager;
pub use crate::state_manager;
